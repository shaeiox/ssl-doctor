"""Certificate file inspection.

Works entirely offline.  Primary parser is the standard library
(``ssl._ssl._test_decode_cert``); the system ``openssl`` binary is used only
to enrich results (signature algorithm, key type/size) and to compare a
certificate against its private key.  Private-key material is never printed,
logged, or returned - only SHA-256 digests of the DER public key.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import ssl
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, List, Optional, Tuple

from . import findings as F

PEM_BLOCK_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL
)

_NAME_ATTRS = {
    "commonName": "CN",
    "organizationName": "O",
    "organizationalUnitName": "OU",
    "localityName": "L",
    "stateOrProvinceName": "ST",
    "countryName": "C",
    "emailAddress": "email",
    "serialNumber": "serialNumber",
}


def _fmt_name(rdns) -> str:
    """Convert _test_decode_cert RDN sequence to a readable one-line name."""
    parts = []
    for rdn in rdns or ():
        for key, value in rdn:
            parts.append(f"{_NAME_ATTRS.get(key, key)}={value}")
    return ", ".join(parts)


def _parse_time(value: str) -> Optional[datetime]:
    """Parse ASN.1 times as returned by _test_decode_cert ('GMT')."""
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    return None


def extract_pem_blocks(data: bytes) -> List[bytes]:
    return PEM_BLOCK_RE.findall(data)


def der_to_pem(der: bytes) -> bytes:
    return ssl.DER_cert_to_PEM_cert(der).encode("ascii")


def pem_to_der(pem: bytes) -> bytes:
    return ssl.PEM_cert_to_DER_cert(pem.decode("ascii", "replace"))


@dataclass
class CertInfo:
    """One decoded certificate."""

    subject: str = ""
    issuer: str = ""
    common_name: str = ""
    issuer_common_name: str = ""
    san_dns: List[str] = field(default_factory=list)
    san_ip: List[str] = field(default_factory=list)
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    serial: str = ""
    sha256: str = ""
    sha1: str = ""
    signature_algorithm: str = ""   # via openssl, when available
    public_key: str = ""            # e.g. "RSA 2048 bit" via openssl
    is_ca: Optional[bool] = None    # best effort from filename/context
    ski: str = ""                   # subject key identifier (hex, via openssl)
    aki: str = ""                   # authority key identifier (hex, via openssl)
    pem: bytes = b""

    def is_self_signed(self) -> bool:
        return bool(self.subject) and self.subject == self.issuer

    def days_to_expiry(self) -> Optional[int]:
        if not self.not_after:
            return None
        return (self.not_after - datetime.now(timezone.utc)).days

    def is_expired(self) -> bool:
        d = self.days_to_expiry()
        return d is not None and d < 0

    def not_yet_valid(self) -> bool:
        if not self.not_before:
            return False
        return datetime.now(timezone.utc) < self.not_before

    def matches_hostname(self, hostname: str) -> Tuple[bool, List[str]]:
        """Return (match, names_checked).  Simple wildcard-aware matching.

        Only subjectAltName entries count: modern clients ignore the CN.
        """
        names = list(self.san_dns)
        host = hostname.lower().rstrip(".")
        for pattern in names:
            p = pattern.lower()
            if p == host:
                return True, names
            if p.startswith("*."):
                suffix = p[1:]  # ".example.com"
                if host.endswith(suffix) and host.count(".") == pattern.count("."):
                    return True, names
        try:
            import ipaddress

            ip = ipaddress.ip_address(host)
            for name in self.san_ip:
                if ipaddress.ip_address(name) == ip:
                    return True, self.san_ip or names
        except ValueError:
            pass
        return False, names

    def one_liner(self) -> str:
        exp = self.not_after.strftime("%Y-%m-%d") if self.not_after else "?"
        return f"{self.subject or '(no subject)'} | expires {exp} | sha256:{self.sha256[:16]}..."


def _decode_with_stdlib(pem: bytes) -> CertInfo:
    with tempfile.NamedTemporaryFile("wb", suffix=".pem", delete=False) as tmp:
        tmp.write(pem)
        tmp_path = tmp.name
    try:
        raw = ssl._ssl._test_decode_cert(tmp_path)  # type: ignore[attr-defined]
    finally:
        os.unlink(tmp_path)

    info = CertInfo(pem=pem)
    info.subject = _fmt_name(raw.get("subject"))
    info.issuer = _fmt_name(raw.get("issuer"))
    cn = [v for rdn in (raw.get("subject") or ()) for k, v in rdn if k == "commonName"]
    info.common_name = cn[-1] if cn else ""
    icn = [v for rdn in (raw.get("issuer") or ()) for k, v in rdn if k == "commonName"]
    info.issuer_common_name = icn[-1] if icn else ""
    info.serial = str(raw.get("serialNumber", ""))
    info.not_before = _parse_time(raw.get("notBefore", "") or "")
    info.not_after = _parse_time(raw.get("notAfter", "") or "")
    for kind, val in raw.get("subjectAltName", ()) or ():
        if kind == "DNS":
            info.san_dns.append(val)
        elif kind == "IP Address":
            info.san_ip.append(val)
    der = pem_to_der(pem)
    info.sha256 = hashlib.sha256(der).hexdigest()
    info.sha1 = hashlib.sha1(der).hexdigest()
    return info


def _openssl(*args: str, input_data: bytes = b"", timeout: int = 10) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            ["openssl", *args],
            input=input_data,
            capture_output=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode(
            "utf-8", "replace"
        )
    except FileNotFoundError:
        return 127, "", "openssl binary not found"
    except subprocess.TimeoutExpired:
        return 124, "", "openssl timed out"


def _enrich_with_openssl(info: CertInfo) -> None:
    """Fill signature algorithm / public key fields via the openssl CLI."""
    if not shutil.which("openssl"):
        return
    rc, out, _ = _openssl("x509", "-noout", "-text", input_data=info.pem)
    if rc != 0:
        return
    m = re.search(r"Signature Algorithm:\s*([^\n]+)", out)
    if m:
        info.signature_algorithm = m.group(1).strip()
    m = re.search(r"Public-Key:\s*\(([^)]+)\)", out)
    algo = ""
    m2 = re.search(r"Public Key Algorithm:\s*([^\n]+)", out)
    if m2:
        algo = m2.group(1).strip().replace("Public-Key", "").strip()
    if m:
        bits = m.group(1).strip()
        short = {"rsaEncryption": "RSA", "id-ecPublicKey": "ECDSA", "ED25519": "Ed25519"}.get(algo, algo)
        info.public_key = f"{short} {bits}".strip()
    if info.is_ca is None:
        info.is_ca = "CA:TRUE" in out
    m = re.search(r"Subject Key Identifier:\s*\n\s*([0-9A-Fa-f:]+)", out)
    if m:
        info.ski = m.group(1).replace(":", "").lower()
    m = re.search(r"Authority Key Identifier:\s*\n\s*(?:keyid:)?([0-9A-Fa-f:]+)", out)
    if m:
        info.aki = m.group(1).replace(":", "").lower()


def decode_pem(pem: bytes, enrich: bool = True) -> CertInfo:
    info = _decode_with_stdlib(pem)
    if enrich:
        _enrich_with_openssl(info)
    return info


def decode_der(der: bytes, enrich: bool = True) -> CertInfo:
    return decode_pem(der_to_pem(der), enrich=enrich)


def load_cert_file(path: str) -> Tuple[List[CertInfo], Optional[str]]:
    """Load one or more PEM certificates (or a single DER cert) from a file.

    Returns (certs, error).  Unparseable/unsupported formats return an error
    string instead of raising.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return [], f"cannot read file: {exc}"

    if not data.strip():
        return [], "file is empty"

    blocks = extract_pem_blocks(data)
    certs: List[CertInfo] = []
    if blocks:
        for b in blocks:
            try:
                certs.append(decode_pem(b))
            except Exception as exc:  # corrupted block mid-file
                return certs, f"failed to parse one PEM block: {exc}"
        return certs, None

    # No PEM blocks: maybe a single DER file.
    try:
        certs.append(decode_der(data))
        return certs, None
    except Exception:
        pass

    ext = os.path.splitext(path)[1].lower()
    if ext in (".pfx", ".p12", ".pkcs12"):
        return [], (
            "PKCS#12 bundles are not inspected directly (they may contain a "
            "private key). Export the certificate only, e.g.: "
            "openssl pkcs12 -in bundle.pfx -clcerts -nokeys -out cert.pem"
        )
    if b"PRIVATE KEY" in data:
        return [], (
            "file looks like a private key, not a certificate. Key material is "
            "never displayed; use '/cert match <cert> <key>' to verify pairing."
        )
    return [], "unrecognized format (expected PEM or DER certificate)"


def issued_by(child: CertInfo, parent: CertInfo) -> Tuple[bool, str]:
    """Did `parent` issue `child`?  Returns (verdict, method used)."""
    if child.issuer != parent.subject:
        return False, "issuer/subject name"
    if child.aki and parent.ski:
        return child.aki == parent.ski, "issuer/subject name + key identifier"
    return True, "issuer/subject name only (no key identifiers available)"


def load_root_anchors() -> List[CertInfo]:
    """Self-signed certificates from the system trust store (roots only).

    Intermediates that a store may also hold (e.g. the Windows "CA" cache,
    or a bundle with intermediates appended) are excluded on purpose, so
    verdicts never depend on what this machine happens to have cached.
    Cached per trust-store location (decoding a full store takes a moment).
    """
    paths = ssl.get_default_verify_paths()
    key = (paths.cafile, paths.capath)
    if key not in _ROOTS_CACHE:
        _ROOTS_CACHE[key] = _load_root_anchors(paths.capath)
    return list(_ROOTS_CACHE[key])


_ROOTS_CACHE: dict = {}


def _load_root_anchors(capath: Optional[str]) -> List[CertInfo]:
    ctx = ssl.create_default_context()
    ders = list(ctx.get_ca_certs(binary_form=True))
    if not ders:
        if capath and os.path.isdir(capath):
            for name in sorted(os.listdir(capath)):
                try:
                    with open(os.path.join(capath, name), "rb") as fh:
                        ders.extend(pem_to_der(b) for b in extract_pem_blocks(fh.read()))
                except OSError:
                    continue
    roots: List[CertInfo] = []
    seen = set()
    for der in ders:
        try:
            info = decode_der(der, enrich=False)
        except Exception:
            continue
        if info.is_self_signed() and info.sha256 not in seen:
            seen.add(info.sha256)
            roots.append(info)
    return roots


@dataclass
class ChainAssessment:
    status: str                     # complete | incomplete | broken
    anchor: str = ""                # DN of the root the client must trust
    broken_at: int = 0              # 1-based position whose issuer is wrong
    evidence: List[str] = field(default_factory=list)


def assess_chain(chain: List[CertInfo],
                 roots: Optional[List[CertInfo]] = None) -> ChainAssessment:
    """Judge a presented/configured chain without using intermediate caches.

    `roots` are trusted root anchors (self-signed).  When None, completeness
    of a chain topped by a CA certificate is assumed and stated as such.
    """
    label = lambda c: c.common_name or c.subject  # noqa: E731
    for i in range(len(chain) - 1):
        ok, method = issued_by(chain[i], chain[i + 1])
        if not ok:
            return ChainAssessment(
                "broken", broken_at=i + 1,
                evidence=[f"position {i + 1}: '{label(chain[i])}' is not issued by "
                          f"position {i + 2} ('{label(chain[i + 1])}') [{method}]"])
    top = chain[-1]
    names = " -> ".join(label(c) for c in chain)
    if top.is_self_signed():
        return ChainAssessment("complete", top.subject,
                               evidence=[f"{len(chain)} certificate(s), linked, ends at a "
                                         f"self-signed root ({names})"])
    if roots is not None:
        issuer = next((r for r in roots if issued_by(top, r)[0]), None)
        if issuer:
            return ChainAssessment("complete", issuer.subject,
                                   evidence=[f"{len(chain)} certificate(s), linked "
                                             f"({names}); anchored by trusted root "
                                             f"'{label(issuer)}'"])
    if len(chain) > 1:
        # Linked chain: the top issued the cert below it, so it is a CA and
        # its issuer is the expected root.  Not finding that root
        # locally is a trust question (validation reports it), not proof that
        # the server omitted certificates.
        note = ("root anchor list unavailable on this machine" if roots is None else
                f"its issuer '{top.issuer}' is not among this machine's trusted roots")
        return ChainAssessment("complete", top.issuer,
                               evidence=[f"{len(chain)} certificate(s), linked ({names})",
                                         f"top certificate is a CA; {note}"])
    return ChainAssessment("incomplete",
                           evidence=[f"{len(chain)} certificate(s) ({names})",
                                     "intermediate certificate(s) not sent: the chain ends "
                                     f"at a non-CA certificate issued by '{top.issuer}'"])


def inspect_cert_file(path: str, hostname: str = "",
                     emit: Optional[Callable[[Finding], None]] = None) -> List[Finding]:
    """Produce findings for a certificate (or chain) file."""
    out: List[Finding] = []
    target = path

    def _add(f: Finding) -> Finding:
        list.append(out, f)
        if emit is not None:
            emit(f)
        return f

    certs, err = load_cert_file(path)
    if err and not certs:
        _add(
            F.Finding("cert.parse", f"Parse certificate file {os.path.basename(path)}",
                    F.FAIL, F.SCOPE_LOCAL, [err], target=target)
        )
        return out

    first = certs[0]
    desc = (
        f"subject={first.subject}; issuer={first.issuer}; "
        f"valid {first.not_before:%Y-%m-%d}..{first.not_after:%Y-%m-%d} UTC"
        if first.not_before and first.not_after else
        f"subject={first.subject}; issuer={first.issuer}"
    )
    _add(
        F.Finding("cert.parse", f"Parsed certificate file {os.path.basename(path)}",
                F.PASS, F.SCOPE_LOCAL,
                [
                    desc,
                    f"certificates in file: {len(certs)}",
                    f"SHA-256 fingerprint: {first.sha256}",
                    f"SHA-1 fingerprint:   {first.sha1}",
                    f"serial: {first.serial}",
                    *( [f"signature algorithm: {first.signature_algorithm}"] if first.signature_algorithm else [] ),
                    *( [f"public key: {first.public_key}"] if first.public_key else [] ),
                    f"subjectAltName DNS: {', '.join(first.san_dns) or '(none)'}",
                    *( [f"subjectAltName IP: {', '.join(first.san_ip)}"] if first.san_ip else [] ),
                ],
                target=target)
    )

    # Validity window.
    if first.is_expired():
        _add(F.Finding(
            "cert.validity", "Certificate validity dates", F.FAIL, F.SCOPE_LOCAL,
            [f"certificate expired {-first.days_to_expiry()} days ago "
             f"(notAfter={first.not_after:%Y-%m-%d %H:%M UTC})"],
            recommendation="Renew the certificate and deploy the new file to the server.",
            target=target))
    elif first.not_yet_valid():
        _add(F.Finding(
            "cert.validity", "Certificate validity dates", F.FAIL, F.SCOPE_LOCAL,
            [f"certificate is not valid until {first.not_before:%Y-%m-%d %H:%M UTC}"],
            recommendation="Check the client system clock and the certificate issuance date.",
            target=target))
    else:
        days = first.days_to_expiry()
        if days is not None and days <= 30:
            _add(F.Finding(
                "cert.validity", "Certificate validity dates", F.WARNING, F.SCOPE_LOCAL,
                [f"certificate expires in {days} days ({first.not_after:%Y-%m-%d})"],
                recommendation="Renew the certificate soon.",
                target=target))
        else:
            _add(F.Finding(
                "cert.validity", "Certificate validity dates", F.PASS, F.SCOPE_LOCAL,
                [f"certificate is currently valid; {days} days remaining"],
                target=target))

    # Self-signed?
    if first.is_self_signed():
        _add(F.Finding(
            "cert.selfsigned", "Issued by a trusted CA?", F.WARNING, F.SCOPE_LOCAL,
            ["subject and issuer are identical: this is a self-signed certificate"],
            recommendation="Clients will not trust this unless it is imported into their "
                           "trust store. Use a CA-issued certificate for production.",
            target=target))

    # Hostname coverage.
    if hostname:
        ok, names = first.matches_hostname(hostname)
        _add(F.Finding(
            "cert.hostname", f"Hostname match for '{hostname}'",
            F.PASS if ok else F.FAIL, F.SCOPE_LOCAL,
            [f"checked against subjectAltName: {', '.join(names) or '(none)'}",
             "match" if ok else f"certificate does not cover '{hostname}'"] +
            ([f"no subjectAltName: CN '{first.common_name}' is ignored by modern clients"]
             if not first.san_dns and first.common_name else []),
            recommendation="" if ok else
            "Install a certificate whose SAN (or CN) includes this hostname, or connect "
            "using a name the certificate covers.",
            target=target))

    # Chain structure inside the file.
    if len(certs) > 1:
        problems = []
        ordered_ok = True
        for i in range(len(certs) - 1):
            if certs[i].issuer != certs[i + 1].subject:
                ordered_ok = False
                problems.append(
                    f"position {i + 1}: issuer '{certs[i].issuer}' does not match "
                    f"subject of next certificate '{certs[i + 1].subject}'")
        leaf = certs[0]
        if leaf.subject == leaf.issuer:
            problems.append("first certificate in file is self-signed (first entry should be the server/leaf certificate)")
        if not ordered_ok:
            problems.append("certificates are out of order (server certificate first, then intermediates)")
        if problems:
            _add(F.Finding(
                "cert.chainfile", "Certificate chain file structure", F.WARNING, F.SCOPE_LOCAL,
                [f"{len(certs)} certificates in file", *problems],
                recommendation="Order the file as: server certificate, then intermediate "
                               "certificate(s). The root certificate may be omitted.",
                target=target))
        else:
            _add(F.Finding(
                "cert.chainfile", "Certificate chain file structure", F.PASS, F.SCOPE_LOCAL,
                [f"{len(certs)} certificates, correctly ordered "
                 f"({' -> '.join(c.common_name or c.subject for c in certs)})"],
                target=target))

    if err:
        _add(F.Finding("cert.parse", "Additional data in file", F.WARNING,
                           F.SCOPE_LOCAL, [err], target=target))
    return out


def _public_key_sha256_from_pem_bytes(pem: bytes) -> Tuple[Optional[str], str]:
    pub_pem = _openssl("x509", "-noout", "-pubkey", input_data=pem)
    if pub_pem[0] != 0:
        return None, pub_pem[2].strip()
    der_proc = subprocess.run(
        ["openssl", "pkey", "-pubin", "-outform", "DER"],
        input=pub_pem[1].encode(), capture_output=True, timeout=10)
    if der_proc.returncode != 0:
        return None, der_proc.stderr.decode("utf-8", "replace").strip()
    return hashlib.sha256(der_proc.stdout).hexdigest(), ""


def match_cert_key(cert_path: str, key_path: str,
                   emit: Optional[Callable[[Finding], None]] = None) -> List[Finding]:
    """Verify a private key belongs to a certificate.

    Never prints or logs key material.  Encrypted keys are rejected unless
    they can be read without a passphrase (we never prompt for one).
    """
    out: List[Finding] = []

    def _add(f: Finding) -> Finding:
        list.append(out, f)
        if emit is not None:
            emit(f)
        return f

    if not shutil.which("openssl"):
        _f = F.Finding("cert.keymatch", "Certificate/private-key match", F.NOT_TESTED,
                      F.SCOPE_LOCAL, ["openssl binary not available"])
        if emit is not None:
            emit(_f)
        return [_f]
    certs, err = load_cert_file(cert_path)
    if not certs:
        _f = F.Finding("cert.keymatch", "Certificate/private-key match", F.FAIL,
                      F.SCOPE_LOCAL, [err or "cannot parse certificate file"],
                      target=cert_path)
        if emit is not None:
            emit(_f)
        return [_f]

    cert_fp, e1 = _public_key_sha256_from_pem_bytes(certs[0].pem)
    try:
        with open(key_path, "rb") as fh:
            key_data = fh.read()
    except OSError as exc:
        _f = F.Finding("cert.keymatch", "Certificate/private-key match", F.FAIL,
                      F.SCOPE_LOCAL, [f"cannot read key file: {exc}"], target=key_path)
        if emit is not None:
            emit(_f)
        return [_f]

    if b"ENCRYPTED" in key_data[:200]:
        _add(F.Finding("cert.keymatch", "Certificate/private-key match", F.NOT_TESTED,
                           F.SCOPE_LOCAL,
                           ["the private key is passphrase-encrypted; ssl-doctor never "
                            "prompts for passphrases, so the match cannot be checked"],
                           detail="Decrypt a copy in a secure location and compare again "
                                  "with /cert match.",
                           target=key_path))
        return out

    key_pub = subprocess.run(
        ["openssl", "pkey", "-pubout", "-outform", "DER"],
        input=key_data, capture_output=True, timeout=10)
    if key_pub.returncode != 0:
        msg = key_pub.stderr.decode("utf-8", "replace").strip().splitlines()
        hint = msg[-1] if msg else "openssl could not read the key"
        _f = F.Finding("cert.keymatch", "Certificate/private-key match", F.FAIL,
                      F.SCOPE_LOCAL, [f"private key unreadable: {hint}"],
                      target=key_path)
        if emit is not None:
            emit(_f)
        return out + [_f]
    key_fp = hashlib.sha256(key_pub.stdout).hexdigest()

    if cert_fp and cert_fp == key_fp:
        _add(F.Finding(
            "cert.keymatch", "Certificate/private-key match", F.PASS, F.SCOPE_LOCAL,
            ["public key embedded in the certificate matches this private key",
             f"public-key SHA-256: {key_fp}"],
            target=cert_path))
    else:
        ev = [f"certificate public-key SHA-256: {cert_fp}", f"private key public SHA-256: {key_fp}"]
        _add(F.Finding(
            "cert.keymatch", "Certificate/private-key match", F.FAIL, F.SCOPE_LOCAL,
            ev + ["the private key does NOT belong to this certificate"],
            recommendation="The server may be serving one certificate while holding the "
                           "key of another (common after renewals). Point the web server "
                           "at the matching pair.",
            target=cert_path))
    return out
