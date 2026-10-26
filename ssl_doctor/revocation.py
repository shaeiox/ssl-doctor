"""OCSP / CRL revocation status, with the source and its validity stated.

Default: judge the response the server staples (no extra destination).
`online`: also ask the CA - the AIA OCSP responder, then the CRL - for the
leaf and each intermediate.  `off`: nothing is checked.

Python's ssl module cannot request or return a stapled response, so a
dedicated `openssl s_client -status` handshake to the verified address and
server name fetches it; the DER is taken from the TLS CertificateStatus
structure and validated with `openssl ocsp -respin` (signature, certificate
ID, then the response's time window, checked here).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

from .certs import CertInfo, _parse_time

MODES = ("staple", "online", "off")
GOOD, REVOKED, UNAVAILABLE, NOT_CHECKED, INCONCLUSIVE = (
    "good", "revoked", "unavailable", "not-checked", "inconclusive")
_CRL_LIMIT = 10 * 1024 * 1024
_SKEW = timedelta(minutes=5)

_mode = "staple"


def set_mode(value: str) -> str:
    global _mode
    if value not in MODES:
        raise ValueError(f"revocation mode must be one of {', '.join(MODES)}, got {value!r}")
    _mode = value
    return _mode


def mode() -> str:
    return _mode


@dataclass
class Result:
    state: str
    source: str = ""                  # stapled | ocsp | crl | ""
    evidence: List[str] = field(default_factory=list)
    stapled_defect: bool = False      # a stapled response that is invalid: server issue


# ---------------------------------------------------------------- stapled fetch

_MSG_HEADER = re.compile(r"^<<< .*Handshake \[length [0-9a-f]+\], (Certificate|CertificateStatus)\s*$")
_HEX_LINE = re.compile(r"^\s+((?:[0-9a-f]{2}\s?)+)\s*$")


def _handshake_bytes(msg_output: str) -> bytes:
    """Bytes of the received Certificate / CertificateStatus messages (`-msg`)."""
    out, take = bytearray(), False
    for line in msg_output.splitlines():
        if line.startswith(("<<<", ">>>")):
            take = bool(_MSG_HEADER.match(line))
            continue
        m = _HEX_LINE.match(line) if take else None
        if m:
            out += bytes.fromhex(m.group(1).replace(" ", ""))
        elif take and line.strip():
            take = False
    return bytes(out)


def _der_length(data: bytes, i: int) -> Optional[int]:
    """Total length of the DER element starting at data[i], or None."""
    if i + 2 > len(data):
        return None
    first = data[i + 1]
    if first < 0x80:
        return 2 + first
    n = first & 0x7F
    if n == 0 or n > 3 or i + 2 + n > len(data):
        return None
    return 2 + n + int.from_bytes(data[i + 2:i + 2 + n], "big")


def extract_ocsp(data: bytes) -> Optional[bytes]:
    """The OCSPResponse inside a CertificateStatus: 0x01 (ocsp), uint24 length,
    then a DER SEQUENCE of exactly that length (TLS 1.2 message and TLS 1.3
    status_request extension share this shape)."""
    for i in range(len(data) - 5):
        if data[i] != 0x01 or data[i + 4] != 0x30:
            continue
        length = int.from_bytes(data[i + 1:i + 4], "big")
        if _der_length(data, i + 4) == length and i + 4 + length <= len(data):
            return data[i + 4:i + 4 + length]
    return None


def fetch_stapled(host: str, port: int, sni: Optional[str], timeout: float,
                  connect_ip: Optional[str] = None) -> Tuple[Optional[bytes], str]:
    """(DER OCSP response | None, detail)."""
    if not shutil.which("openssl"):
        return None, "openssl not available"
    addr = connect_ip or host
    target = f"[{addr}]:{port}" if ":" in addr else f"{addr}:{port}"
    argv = ["openssl", "s_client", "-connect", target, "-status", "-msg"]
    if sni:
        argv += ["-servername", sni]
    try:
        proc = subprocess.run(argv, input=b"", capture_output=True, timeout=timeout + 5)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"stapling probe failed: {exc}"
    text = proc.stdout.decode("utf-8", "replace")
    der = extract_ocsp(_handshake_bytes(text))
    if der:
        return der, f"stapled response received from {addr}"
    if "OCSP response: no response sent" in text:
        return None, "the server staples no OCSP response"
    return None, "no stapled OCSP response found in the handshake"


# ---------------------------------------------------------------- validation

def _write(d: str, name: str, data: bytes) -> str:
    path = os.path.join(d, name)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def evaluate(der: bytes, leaf: CertInfo, issuer: CertInfo, source: str,
             now: Optional[datetime] = None) -> Result:
    """Validate an OCSP response for `leaf` and read its status."""
    now = now or datetime.now(timezone.utc)
    stapled = source == "stapled"
    with tempfile.TemporaryDirectory(prefix="ssldoctor-ocsp-") as d:
        resp = _write(d, "resp.der", der)
        leaf_p, issuer_p = _write(d, "leaf.pem", leaf.pem), _write(d, "issuer.pem", issuer.pem)
        try:
            proc = subprocess.run(
                ["openssl", "ocsp", "-respin", resp, "-issuer", issuer_p, "-cert", leaf_p,
                 "-CAfile", issuer_p, "-partial_chain", "-no_nonce"],
                capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return Result(INCONCLUSIVE, source, [f"openssl ocsp could not run: {exc}"])
    text = proc.stdout + proc.stderr
    if "Response Verify Failure" in text or "Response verify OK" not in text:
        return Result(INCONCLUSIVE, source,
                      [f"{source} OCSP response: signature does not verify against the issuer"],
                      stapled_defect=stapled)
    status = re.search(r"leaf\.pem: (good|revoked|unknown|ERROR[^\n]*)", text)
    if not status or status.group(1).startswith("ERROR"):
        return Result(INCONCLUSIVE, source,
                      [f"{source} OCSP response does not name this certificate's issuer and "
                       "serial"], stapled_defect=stapled)
    this_u = re.search(r"This Update: ([^\n]+)", text)
    next_u = re.search(r"Next Update: ([^\n]+)", text)
    this_t = _parse_time(this_u.group(1).strip()) if this_u else None
    next_t = _parse_time(next_u.group(1).strip()) if next_u else None
    window = (f"thisUpdate {this_t:%Y-%m-%d %H:%M} UTC" if this_t else "") + \
             (f", nextUpdate {next_t:%Y-%m-%d %H:%M} UTC" if next_t else "")
    if next_t and next_t < now - _SKEW:
        return Result(INCONCLUSIVE, source,
                      [f"{source} response expired" if stapled else
                       f"{source} response expired", window], stapled_defect=stapled)
    if this_t and this_t > now + _SKEW:
        return Result(INCONCLUSIVE, source, [f"{source} response is not yet valid", window],
                      stapled_defect=stapled)
    if status.group(1) == "good":
        return Result(GOOD, source, [f"{source} OCSP response: good (signature verified)",
                                     window])
    if status.group(1) == "revoked":
        reason = re.search(r"Reason: ([^\n]+)", text)
        when = re.search(r"Revocation Time: ([^\n]+)", text)
        return Result(REVOKED, source,
                      [f"{source} OCSP response: revoked"
                       + (f" at {when.group(1).strip()}" if when else "")
                       + (f" ({reason.group(1).strip()})" if reason else ""), window])
    return Result(INCONCLUSIVE, source, [f"{source} OCSP response: status unknown", window])


# ---------------------------------------------------------------- online

def query_ocsp(leaf: CertInfo, issuer: CertInfo, url: str, timeout: float) -> Result:
    """Ask the CA's responder (opt-in: sends the certificate's serial to it)."""
    with tempfile.TemporaryDirectory(prefix="ssldoctor-ocsp-") as d:
        out = os.path.join(d, "resp.der")
        try:
            proc = subprocess.run(
                ["openssl", "ocsp", "-issuer", _write(d, "issuer.pem", issuer.pem),
                 "-cert", _write(d, "leaf.pem", leaf.pem), "-url", url, "-no_nonce",
                 "-timeout", str(int(timeout)), "-respout", out, "-noverify"],
                capture_output=True, text=True, timeout=timeout + 5)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return Result(INCONCLUSIVE, "ocsp", [f"OCSP responder {url} did not answer: {exc}"])
        if proc.returncode != 0 or not os.path.exists(out):
            first = (proc.stderr.strip().splitlines() or ["no response"])[0][:200]
            return Result(INCONCLUSIVE, "ocsp", [f"OCSP responder {url} did not answer: {first}"])
        with open(out, "rb") as fh:
            der = fh.read()
    result = evaluate(der, leaf, issuer, "ocsp")
    result.evidence.insert(0, f"responder: {url}")
    return result


def _download(url: str, timeout: float) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as resp:      # noqa: S310 - http CRL
        data = resp.read(_CRL_LIMIT + 1)
    if len(data) > _CRL_LIMIT:
        raise ValueError("CRL larger than 10 MiB")
    return data


def query_crl(leaf: CertInfo, issuer: CertInfo, url: str, timeout: float,
              now: Optional[datetime] = None) -> Result:
    now = now or datetime.now(timezone.utc)
    try:
        data = _download(url, timeout)
    except (OSError, ValueError) as exc:
        return Result(INCONCLUSIVE, "crl", [f"CRL {url} could not be fetched: {exc}"])
    with tempfile.TemporaryDirectory(prefix="ssldoctor-crl-") as d:
        crl = _write(d, "crl.der", data)
        issuer_p = _write(d, "issuer.pem", issuer.pem)
        form = ["-inform", "PEM"] if data.lstrip().startswith(b"-----") else ["-inform", "DER"]
        verify = subprocess.run(["openssl", "crl", *form, "-in", crl, "-CAfile", issuer_p,
                                 "-noout"], capture_output=True, text=True, timeout=15)
        dump = subprocess.run(["openssl", "crl", *form, "-in", crl, "-noout", "-text"],
                              capture_output=True, text=True, timeout=15)
    if "verify OK" not in verify.stdout + verify.stderr:
        return Result(INCONCLUSIVE, "crl", [f"CRL {url}: signature does not verify against "
                                            "the issuer"])
    m = re.search(r"Next Update: ([^\n]+)", dump.stdout)
    next_t = _parse_time(m.group(1).strip()) if m else None
    if next_t and next_t < now - _SKEW:
        return Result(INCONCLUSIVE, "crl", [f"CRL {url} expired on {next_t:%Y-%m-%d}"])
    serial = (leaf.serial or "").upper().lstrip("0")
    listed = {s.upper().lstrip("0") for s in
              re.findall(r"Serial Number: ([0-9A-Fa-f]+)", dump.stdout)}
    if serial and serial in listed:
        return Result(REVOKED, "crl", [f"CRL {url}: serial {leaf.serial} is revoked"])
    return Result(GOOD, "crl", [f"CRL {url}: serial not listed (signature verified)"])


# ---------------------------------------------------------------- orchestration

def check_chain(chain: List[CertInfo], host: str, port: int, sni: Optional[str],
                timeout: float, connect_ip: Optional[str] = None,
                now: Optional[datetime] = None) -> Result:
    """Revocation state of the presented chain under the current mode."""
    if _mode == "off":
        return Result(NOT_CHECKED, "", ["revocation checking is off (--revocation=off)"])
    leaf = chain[0]
    issuer = chain[1] if len(chain) > 1 else None
    has_urls = bool(leaf.ocsp_urls or leaf.crl_urls)
    der, detail = fetch_stapled(host, port, sni, timeout, connect_ip)
    stapled = None
    if der and issuer is not None:
        stapled = evaluate(der, leaf, issuer, "stapled", now)
    elif der:
        stapled = Result(INCONCLUSIVE, "stapled", ["a response is stapled, but the issuer "
                                                   "certificate was not sent to check it"])
    if _mode != "online":
        if stapled is not None:
            return stapled
        if not has_urls:
            return Result(UNAVAILABLE, "", [detail, "the certificate names no OCSP responder "
                                                    "or CRL"])
        return Result(NOT_CHECKED, "", [detail, "online revocation checking is off; "
                                                "enable it with --revocation=online"])
    results = []
    for i, cert in enumerate(chain[:-1] if len(chain) > 1 else chain):
        parent = chain[i + 1] if i + 1 < len(chain) else None
        if i == 0 and stapled is not None and stapled.state in (GOOD, REVOKED):
            results.append(stapled)
            continue
        if parent is None:
            results.append(Result(INCONCLUSIVE, "", [f"'{cert.common_name}': issuer "
                                                     "certificate not available"]))
            continue
        if cert.ocsp_urls:
            r = query_ocsp(cert, parent, cert.ocsp_urls[0], timeout)
            if r.state not in (GOOD, REVOKED) and cert.crl_urls:
                crl = query_crl(cert, parent, cert.crl_urls[0], timeout, now)
                crl.evidence = r.evidence + crl.evidence       # keep why OCSP failed
                r = crl
        elif cert.crl_urls:
            r = query_crl(cert, parent, cert.crl_urls[0], timeout, now)
        else:
            r = Result(UNAVAILABLE, "", [f"'{cert.common_name}': no OCSP responder or CRL"])
        r.evidence = [f"'{cert.common_name or cert.subject}': {e}" for e in r.evidence]
        results.append(r)
    order = [REVOKED, INCONCLUSIVE, UNAVAILABLE, GOOD]
    worst = min(results, key=lambda r: order.index(r.state) if r.state in order else 9)
    worst.evidence = [e for r in results for e in r.evidence]
    if stapled is not None and stapled.stapled_defect:
        worst.stapled_defect = True
        worst.evidence = stapled.evidence + worst.evidence
    return worst
