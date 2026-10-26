"""Certificate file inspection.

Works entirely offline.  Primary parser is the standard library
(``ssl._ssl._test_decode_cert``); the system ``openssl`` binary is used only
to enrich results (signature algorithm, key type/size) and to compare a
certificate against its private key.  Private-key material is never printed,
logged, or returned - only SHA-256 digests of the DER public key.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import shutil
import ssl
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

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


def canonical_name(rdns) -> Tuple[Tuple[str, str], ...]:
    """RFC 5280 / RFC 4518 style name for comparison: attribute values
    case-folded with internal whitespace collapsed, regardless of string type."""
    return tuple((key, " ".join(str(value).casefold().split()))
                 for rdn in rdns or () for key, value in rdn)


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
    # Fields below are filled from `openssl x509 -text`; `extensions_read`
    # says whether that happened, so "no extension" and "not read" differ.
    extensions_read: bool = False
    key_type: str = ""              # RSA | EC | Ed25519 | Ed448 | DSA | <openssl name>
    key_bits: Optional[int] = None
    curve: str = ""                 # EC only, e.g. "P-256" or "prime256v1"
    is_ca: Optional[bool] = None    # Basic Constraints CA:TRUE; None = not read
    basic_constraints: bool = False  # the extension is present
    path_len: Optional[int] = None
    key_usage: List[str] = field(default_factory=list)          # RFC 5280 names
    ext_key_usage: List[str] = field(default_factory=list)      # e.g. serverAuth
    ski: str = ""                   # subject key identifier (hex, via openssl)
    aki: str = ""                   # authority key identifier (hex, via openssl)
    aia_ca_issuers: List[str] = field(default_factory=list)
    ocsp_urls: List[str] = field(default_factory=list)
    crl_urls: List[str] = field(default_factory=list)
    pem: bytes = b""
    position: int = 0               # 1-based place in its file or chain; 0 = unknown
    subject_canon: Tuple[Tuple[str, str], ...] = ()     # see canonical_name()
    issuer_canon: Tuple[Tuple[str, str], ...] = ()

    def issued_name_of(self, parent: "CertInfo") -> bool:
        """Does this certificate name `parent` as its issuer (canonical compare)?"""
        if self.issuer_canon and parent.subject_canon:
            return self.issuer_canon == parent.subject_canon
        return bool(self.issuer) and self.issuer == parent.subject

    def self_issued_name(self) -> bool:
        return self.issued_name_of(self)

    def is_self_signed(self) -> bool:
        # names only: whether its own key signed it is chainval.self_signed()
        return bool(self.subject) and self.self_issued_name()

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
    info.subject_canon = canonical_name(raw.get("subject"))
    info.issuer_canon = canonical_name(raw.get("issuer"))
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


def _openssl_raw(*args: str, input_data: bytes = b"",
                 timeout: int = 10) -> Tuple[int, bytes, str]:
    """`openssl <args>` with binary stdout; a missing binary or a hang is a result."""
    try:
        proc = subprocess.run(["openssl", *args], input=input_data,
                              capture_output=True, timeout=timeout)
    except FileNotFoundError:
        return 127, b"", "openssl binary not found"
    except subprocess.TimeoutExpired:
        return 124, b"", "openssl timed out"
    except OSError as exc:
        return 126, b"", f"openssl could not run: {exc.strerror or exc}"
    return proc.returncode, proc.stdout, proc.stderr.decode("utf-8", "replace")


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


_KEY_USAGE_NAMES = {
    "Digital Signature": "digitalSignature", "Non Repudiation": "nonRepudiation",
    "Content Commitment": "nonRepudiation", "Key Encipherment": "keyEncipherment",
    "Data Encipherment": "dataEncipherment", "Key Agreement": "keyAgreement",
    "Certificate Sign": "keyCertSign", "CRL Sign": "cRLSign",
    "Encipher Only": "encipherOnly", "Decipher Only": "decipherOnly",
}
_EKU_NAMES = {
    "TLS Web Server Authentication": "serverAuth",
    "TLS Web Client Authentication": "clientAuth", "Code Signing": "codeSigning",
    "E-mail Protection": "emailProtection", "Time Stamping": "timeStamping",
    "OCSP Signing": "OCSPSigning", "Any Extended Key Usage": "anyExtendedKeyUsage",
}
_KEY_TYPES = {"rsaEncryption": "RSA", "rsassaPss": "RSA-PSS", "id-ecPublicKey": "EC",
              "ED25519": "Ed25519", "ED448": "Ed448", "dsaEncryption": "DSA"}


def _text_extensions(text: str) -> dict:
    """`X509v3 extensions` of `openssl x509 -text` as {name: [body lines]}."""
    lines = text.splitlines()
    try:
        start = next(i for i, ln in enumerate(lines) if ln.strip() == "X509v3 extensions:")
    except StopIteration:
        return {}
    exts: dict = {}
    indent, current = None, None
    for ln in lines[start + 1:]:
        if not ln.strip():
            continue
        depth = len(ln) - len(ln.lstrip())
        if indent is None:
            indent = depth
        if depth < indent:
            break                                   # end of the extension block
        if depth == indent:
            current = ln.strip().split(":")[0].replace("X509v3 ", "").strip()
            exts[current] = []
        elif current is not None:
            exts[current].append(ln.strip())
    return exts


def _apply_openssl_text(info: CertInfo, out: str) -> None:
    m = re.search(r"Signature Algorithm:\s*([^\n]+)", out)
    if m:
        info.signature_algorithm = m.group(1).strip()
    m2 = re.search(r"Public Key Algorithm:\s*([^\n]+)", out)
    algo = m2.group(1).strip() if m2 else ""
    info.key_type = _KEY_TYPES.get(algo, algo)
    m = re.search(r"Public-Key:\s*\((\d+) bit\)", out)
    info.key_bits = int(m.group(1)) if m else {"Ed25519": 256, "Ed448": 456}.get(info.key_type)
    m = re.search(r"NIST CURVE:\s*(\S+)", out) or re.search(r"ASN1 OID:\s*(\S+)", out)
    info.curve = m.group(1) if (m and info.key_type == "EC") else ""
    if info.key_bits:
        short = "ECDSA" if info.key_type == "EC" else info.key_type
        info.public_key = f"{short} {info.key_bits} bit"
    exts = _text_extensions(out)
    bc = exts.get("Basic Constraints")
    info.basic_constraints = bc is not None
    body = " ".join(bc or [])
    info.is_ca = "CA:TRUE" in body
    m = re.search(r"pathlen:(\d+)", body)
    info.path_len = int(m.group(1)) if m else None
    info.key_usage = [_KEY_USAGE_NAMES.get(n.strip(), n.strip())
                      for n in " ".join(exts.get("Key Usage", [])).split(",") if n.strip()]
    info.ext_key_usage = [_EKU_NAMES.get(n.strip(), n.strip()) for n in
                          " ".join(exts.get("Extended Key Usage", [])).split(",") if n.strip()]
    ski = "".join(exts.get("Subject Key Identifier", [])[:1])
    info.ski = ski.replace(":", "").lower()
    aki = "".join(exts.get("Authority Key Identifier", [])[:1])
    info.aki = aki.replace("keyid:", "").replace(":", "").lower() \
        if re.fullmatch(r"(keyid:)?[0-9A-Fa-f:]+", aki) else ""
    for line in exts.get("Authority Information Access", []):
        url = line.split("URI:", 1)[1].strip() if "URI:" in line else ""
        if line.startswith("CA Issuers") and url:
            info.aia_ca_issuers.append(url)
        elif line.startswith("OCSP") and url:
            info.ocsp_urls.append(url)
    info.crl_urls = [ln.split("URI:", 1)[1].strip() for ln in
                     exts.get("CRL Distribution Points", []) if ln.startswith("URI:")]
    info.extensions_read = True


def _enrich_with_openssl(info: CertInfo) -> None:
    """Fill key, signature and extension fields via the openssl CLI."""
    if not shutil.which("openssl"):
        return
    rc, out, _ = _openssl("x509", "-noout", "-text", input_data=info.pem)
    if rc == 0:
        _apply_openssl_text(info, out)


def decode_pem(pem: bytes, enrich: bool = True) -> CertInfo:
    info = _decode_with_stdlib(pem)
    if enrich:
        _enrich_with_openssl(info)
    return info


def decode_der(der: bytes, enrich: bool = True) -> CertInfo:
    return decode_pem(der_to_pem(der), enrich=enrich)


FMT_PEM = "PEM"
FMT_DER = "DER"
FMT_PKCS7 = "PKCS#7"
FMT_PKCS12 = "PKCS#12"
FMT_KEY = "private key"
FMT_CSR = "certificate signing request"
FMT_EMPTY = "empty"
FMT_UNKNOWN = "unrecognized"

_PEM_LABEL_RE = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----")
_CERT_BEGIN = b"-----BEGIN CERTIFICATE-----"
_CERT_END = b"-----END CERTIFICATE-----"
# OID 1.2.840.113549.1.7.2 (pkcs7-signedData): a DER PKCS#7 certificate bundle
_PKCS7_SIGNED_OID = bytes.fromhex("06092a864886f70d010702")
_B64_RE = re.compile(rb"^[A-Za-z0-9+/]*={0,2}$")

_FORMAT_HINTS = {
    FMT_PKCS7: "PKCS#7 bundles are not certificates in PEM form. Extract them with: "
               "openssl pkcs7 -print_certs -in <file> -out certs.pem",
    FMT_PKCS12: "PKCS#12 bundles are not inspected directly (they hold a private key). "
                "Export the certificate only, e.g.: "
                "openssl pkcs12 -in <file> -clcerts -nokeys -out cert.pem",
    FMT_KEY: "this is a private key, not a certificate. Key material is never "
             "displayed; use '/cert match <cert> <key>' to verify pairing.",
    FMT_CSR: "this is a certificate signing request (CSR), not a certificate",
    FMT_EMPTY: "file is empty",
    FMT_UNKNOWN: "unrecognized format (expected PEM or DER certificate)",
}


@dataclass
class ParsedCertificates:
    """Everything a certificate input holds, strictly parsed.

    `problems` are fatal: a file with any problem never counts as parsed,
    even when other blocks decoded.  Key blocks are counted, never read.
    """
    format: str
    certs: List[CertInfo] = field(default_factory=list)
    problems: List[str] = field(default_factory=list)
    key_blocks: int = 0
    other_blocks: List[str] = field(default_factory=list)   # PEM labels ignored

    @property
    def ok(self) -> bool:
        return bool(self.certs) and not self.problems

    def error(self) -> Optional[str]:
        if self.problems:
            return "; ".join(self.problems)
        if not self.certs:
            return _FORMAT_HINTS.get(self.format, _FORMAT_HINTS[FMT_UNKNOWN])
        return None


def _decode_block(index: int, body: bytes) -> Tuple[Optional[CertInfo], str]:
    """One PEM certificate block -> (certificate, problem)."""
    lines = [ln.strip() for ln in body.split(b"\n") if ln.strip()]
    if any(b":" in ln for ln in lines):
        return None, f"block {index}: has PEM headers, which a certificate must not carry"
    joined = b"".join(lines)
    if not _B64_RE.match(joined) or len(joined) % 4:
        return None, f"block {index}: invalid Base64"
    try:
        der = base64.b64decode(joined, validate=True)
        return decode_der(der), ""
    except Exception:  # noqa: BLE001 - any decoder error means malformed ASN.1
        return None, f"block {index}: not a valid X.509 certificate (malformed ASN.1)"


def _der_format(data: bytes) -> str:
    elems = _der_elements(data, limit=2)
    if not elems:
        return FMT_UNKNOWN
    if elems[0] == (0x06, _PKCS7_SIGNED_OID[2:]):
        return FMT_PKCS7
    state = key_state(data)
    if state == KEY_ENCRYPTED and len(elems) >= 2 and elems[0] == (0x02, b"\x03"):
        return FMT_PKCS12
    if state in (KEY_ENCRYPTED, KEY_READABLE):
        return FMT_KEY
    return FMT_UNKNOWN


def parse_cert_bytes(data: bytes) -> ParsedCertificates:
    """Classify `data` by content and decode every certificate it holds."""
    if not data.strip():
        return ParsedCertificates(FMT_EMPTY)
    labels = [m.group(1).decode() for m in _PEM_LABEL_RE.finditer(data)]
    if not labels:
        try:
            cert = decode_der(data)
            cert.position = 1
            return ParsedCertificates(FMT_DER, [cert])
        except Exception:  # noqa: BLE001 - not a DER certificate; say what it is
            return ParsedCertificates(_der_format(data))
    out = ParsedCertificates(FMT_PEM)
    out.key_blocks = sum(1 for lb in labels if lb.endswith("PRIVATE KEY"))
    out.other_blocks = [lb for lb in labels
                        if lb != "CERTIFICATE" and not lb.endswith("PRIVATE KEY")]
    pos, index, terminated = 0, 0, 0
    while True:
        begin = data.find(_CERT_BEGIN, pos)
        if begin == -1:
            break
        index += 1
        body_start = begin + len(_CERT_BEGIN)
        end = data.find(_CERT_END, body_start)
        next_begin = data.find(b"-----BEGIN", body_start)
        if end == -1 or (next_begin != -1 and next_begin < end):
            out.problems.append(f"block {index} is not terminated "
                                "(no -----END CERTIFICATE----- line)")
            pos = body_start if next_begin == -1 else next_begin
            if next_begin == -1:
                break
            continue
        terminated += 1
        cert, problem = _decode_block(index, data[body_start:end])
        if cert is not None:
            cert.position = index
            out.certs.append(cert)
        else:
            out.problems.append(problem)
        pos = end + len(_CERT_END)
    stray_ends = data.count(_CERT_END) - terminated
    if stray_ends > 0:
        out.problems.append(f"{stray_ends} -----END CERTIFICATE----- line(s) without "
                            "a matching BEGIN")
    if index == 0:
        if "PKCS7" in labels:
            out.format = FMT_PKCS7
        elif out.key_blocks and not out.other_blocks:
            out.format = FMT_KEY
        elif any("CERTIFICATE REQUEST" in lb for lb in labels):
            out.format = FMT_CSR
        else:
            out.format = FMT_UNKNOWN
    return out


def parse_cert_file(path: str) -> ParsedCertificates:
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return ParsedCertificates(FMT_UNKNOWN, problems=[f"cannot read file: {exc}"])
    return parse_cert_bytes(data)


def load_cert_file(path: str) -> Tuple[List[CertInfo], Optional[str]]:
    """Certificates in a file, and the reason when it is not cleanly parsed.

    Kept for callers that only need the certificates; `parse_cert_file`
    returns the full picture (format, problems, ignored key blocks).
    """
    parsed = parse_cert_file(path)
    return parsed.certs, parsed.error()


def issued_by(child: CertInfo, parent: CertInfo) -> Tuple[bool, str]:
    """Did `parent` issue `child`?  Returns (verdict, method used)."""
    if not child.issued_name_of(parent):
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
        except Exception:  # noqa: BLE001 - one unreadable store entry must not hide the rest
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
    # "position 3 duplicates position 1": repeated certificates, left out of linkage
    duplicates: List[str] = field(default_factory=list)
    # contract failure kind for a defect (chain-signature, chain-misordered,
    # chain-incomplete); "" when the chain is complete
    failure: str = ""
    name_only: bool = False         # some link matched by name only (no verifier)
    anchored: Optional[bool] = None  # top reached a trusted anchor; None = no anchors given
    paths: List[str] = field(default_factory=list)   # every anchored path found


def dedupe(chain: List[CertInfo]) -> Tuple[List[CertInfo], List[str]]:
    """(chain without repeated certificates, one note per repetition).

    Positions are file/chain positions (1-based); certificates without one get
    their index here, so notes and linkage evidence name the same places.
    """
    first_at: Dict[str, int] = {}
    unique: List[CertInfo] = []
    notes: List[str] = []
    for i, c in enumerate(chain, 1):
        if not c.position:
            c.position = i
        if c.sha256 in first_at:
            notes.append(f"position {c.position} duplicates position {first_at[c.sha256]}")
            continue
        first_at[c.sha256] = c.position
        unique.append(c)
    return unique, notes


def assess_chain(chain: List[CertInfo],
                 roots: Optional[List[CertInfo]] = None) -> ChainAssessment:
    """Judge a presented/configured chain without using intermediate caches.

    `roots` are trusted root anchors.  Links are verified cryptographically
    (see `chainval.assess`); this wrapper keeps the historic entry point.
    """
    from . import chainval      # chainval builds on this module
    return chainval.assess(chain, roots)


def _inventory(chain: List[CertInfo]) -> List[str]:
    from . import chainval
    return chainval.inventory_lines(chain, chainval.classify_roles(chain))


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

    parsed = parse_cert_file(path)
    certs = parsed.certs
    name = os.path.basename(path)
    if not parsed.ok:
        # a partly decodable file is still broken: no PASS for any of it
        ev = (list(parsed.problems) or [parsed.error() or "no certificate found"])
        if parsed.problems and certs:
            ev.append(f"{len(certs)} certificate block(s) decoded; the file is not usable "
                      "as it is")
        if not certs and parsed.format not in (FMT_UNKNOWN, FMT_EMPTY):
            ev.insert(0, f"detected format: {parsed.format}")
        _add(F.Finding("cert.parse", f"Parse certificate file {name}", F.FAIL,
                       F.SCOPE_LOCAL, ev, target=target,
                       recommendation="" if not parsed.problems else
                       "The file is truncated or corrupt. Re-create it from the "
                       "certificates your CA issued, each a complete "
                       "-----BEGIN/END CERTIFICATE----- block."))
        return out

    first = certs[0]
    desc = (
        f"subject={first.subject}; issuer={first.issuer}; "
        f"valid {first.not_before:%Y-%m-%d}..{first.not_after:%Y-%m-%d} UTC"
        if first.not_before and first.not_after else
        f"subject={first.subject}; issuer={first.issuer}"
    )
    _add(
        F.Finding("cert.parse", f"Parsed certificate file {name}",
                F.PASS, F.SCOPE_LOCAL,
                [
                    desc,
                    f"format: {parsed.format}",
                    f"certificates in file: {len(certs)}",
                    *( ["a private-key block is present and was not read"
                        + (f" ({parsed.key_blocks} blocks)" if parsed.key_blocks > 1 else "")]
                       if parsed.key_blocks else [] ),
                    *( [f"other PEM blocks ignored: {', '.join(parsed.other_blocks)}"]
                       if parsed.other_blocks else [] ),
                    *( _inventory(certs) if len(certs) > 1 else [] ),
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

    # Self-signed?  Only a verified self-signature counts; equal names do not.
    if first.self_issued_name():
        from . import chainval
        verdict = chainval.self_signed(first)
        if verdict:
            _add(F.Finding(
                "cert.selfsigned", "Issued by a trusted CA?", F.WARNING, F.SCOPE_LOCAL,
                ["this is a self-signed certificate (its own key signed it, verified)"],
                recommendation="Clients will not trust this unless it is imported into "
                               "their trust store. Use a CA-issued certificate for "
                               "production.",
                target=target))
        elif verdict is False:
            _add(F.Finding(
                "cert.selfsigned", "Issued by a trusted CA?", F.WARNING, F.SCOPE_LOCAL,
                ["self-issued name, not self-signed: subject equals issuer, but another "
                 "key signed this certificate"],
                recommendation="Find the CA certificate that issued it; this certificate "
                               "cannot serve as its own trust anchor.",
                target=target))
        else:
            _add(F.Finding(
                "cert.selfsigned", "Issued by a trusted CA?", F.WARNING, F.SCOPE_LOCAL,
                ["subject and issuer are identical"],
                uncertainty=["the self-signature could not be verified (openssl not "
                             "available)"],
                target=target, failure_kind="verifier-unavailable"))

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

    from . import chainval      # chainval builds on this module
    _add(chainval.usage_finding(certs, F.SCOPE_LOCAL, target))

    # Chain structure inside the file.
    if len(certs) > 1:
        roles, wrong_leaf, structure = chainval.file_structure(certs)
        a = assess_chain(certs, load_root_anchors())
        status, kind, uncertainty = chainval.chain_verdict(a)
        if wrong_leaf:
            # what the file is for is unknown locally, so a CA first is a warning
            status = F.FAIL if status == F.FAIL else F.WARNING
            kind = kind if status == F.FAIL else chainval.FAIL_WRONG_LEAF
        elif status == F.PASS and structure:
            status, kind = F.WARNING, chainval.FAIL_HYGIENE
        if status == F.PASS:
            _add(F.Finding(
                "cert.chainfile", "Certificate chain file structure", F.PASS, F.SCOPE_LOCAL,
                [f"{len(certs)} certificates, correctly ordered "
                 f"({' -> '.join(c.common_name or c.subject for c in certs)})",
                 *a.evidence],
                target=target))
        else:
            _add(F.Finding(
                "cert.chainfile", "Certificate chain file structure", status, F.SCOPE_LOCAL,
                [f"{len(certs)} certificates in file", *a.evidence, *wrong_leaf, *structure],
                recommendation="Order the file as: server certificate, then intermediate "
                               "certificate(s) that issued it, each once. The root "
                               "certificate may be omitted.",
                target=target, failure_kind=kind, uncertainty=uncertainty))

    return out


# ---------------------------------------------------------------- key state

KEY_READABLE = "readable"
KEY_ENCRYPTED = "encrypted"
KEY_UNREADABLE = "unreadable"       # exists, but this account may not read it
KEY_MISSING = "missing"
KEY_UNSUPPORTED = "unsupported"     # not a key openssl can load here

_PLAIN_KEY_PEM = re.compile(rb"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----")
# OID 1.2.840.113549.1.7.1 (pkcs7-data): the outer content type of a PKCS#12 PFX
_PKCS7_DATA_OID = bytes.fromhex("06092a864886f70d010701")


def _der_elements(data: bytes, limit: int = 3) -> List[Tuple[int, bytes]]:
    """First `limit` (tag, value) pairs inside the outer DER SEQUENCE.

    Only the structure is inspected; nothing is decoded or kept beyond the
    caller's classification.  Returns [] when `data` is not a DER SEQUENCE.
    """
    def tlv(buf: bytes, i: int):
        if i + 2 > len(buf):
            return None
        tag, length, i = buf[i], buf[i + 1], i + 2
        if length & 0x80:
            n = length & 0x7F
            if n == 0 or n > 4 or i + n > len(buf):
                return None
            length, i = int.from_bytes(buf[i:i + n], "big"), i + n
        if i + length > len(buf):
            return None
        return tag, buf[i:i + length], i + length

    outer = tlv(data, 0)
    if outer is None or outer[0] != 0x30:
        return []
    body, pos, out = outer[1], 0, []
    while len(out) < limit:
        item = tlv(body, pos)
        if item is None:
            break
        out.append((item[0], item[1]))
        pos = item[2]
    return out


def key_state(data: bytes) -> str:
    """Classify private-key bytes without loading the key.

    `encrypted` covers legacy PEM (`Proc-Type: 4,ENCRYPTED`), PKCS#8
    `ENCRYPTED PRIVATE KEY` PEM, DER `EncryptedPrivateKeyInfo` and PKCS#12
    (whose key bags are always passphrase-protected).  `readable` means the
    bytes look like an unencrypted key; openssl may still refuse it.
    """
    head = data[:4096]
    if b"-----BEGIN ENCRYPTED PRIVATE KEY-----" in head:
        return KEY_ENCRYPTED
    if _PLAIN_KEY_PEM.search(head):
        return KEY_ENCRYPTED if b"Proc-Type: 4,ENCRYPTED" in head else KEY_READABLE
    if b"-----BEGIN" in head:
        # OPENSSH and other PEM labels: not loadable by `openssl pkey`
        return KEY_UNSUPPORTED
    elems = _der_elements(data)
    if len(elems) >= 2:
        (t1, v1), (t2, v2) = elems[0], elems[1]
        if t1 == 0x02 and v1 == b"\x03" and t2 == 0x30 and v2.startswith(_PKCS7_DATA_OID):
            return KEY_ENCRYPTED                    # PKCS#12 PFX, version 3
        if t1 == 0x30 and t2 == 0x04:
            return KEY_ENCRYPTED                    # EncryptedPrivateKeyInfo
        if t1 == 0x02:
            return KEY_READABLE                     # PKCS#8 / RSA / EC private key
    return KEY_UNSUPPORTED


def key_file_state(path: str) -> str:
    """`key_state` of a local file, or why it could not be read."""
    try:
        with open(path, "rb") as fh:
            return key_state(fh.read(1 << 20))
    except FileNotFoundError:
        return KEY_MISSING
    except PermissionError:
        return KEY_UNREADABLE
    except OSError:
        return KEY_UNREADABLE


def _public_key_sha256_from_pem_bytes(pem: bytes) -> Tuple[Optional[str], str]:
    pub_pem = _openssl("x509", "-noout", "-pubkey", input_data=pem)
    if pub_pem[0] != 0:
        return None, pub_pem[2].strip()
    rc, der, err = _openssl_raw("pkey", "-pubin", "-outform", "DER",
                                input_data=pub_pem[1].encode())
    if rc != 0:
        return None, err.strip()
    return hashlib.sha256(der).hexdigest(), ""


def match_cert_key(cert_path: str, key_path: str,
                   emit: Optional[Callable[[Finding], None]] = None) -> List[Finding]:
    """Verify a private key belongs to a certificate.

    Never prints or logs key material.  PASS and FAIL need both public-key
    digests; anything that prevents deriving one (an encrypted, unreadable or
    unsupported key, a failed openssl call) is NOT TESTED, never a mismatch.
    Passphrases are never asked for.
    """
    title = "Certificate/private-key match"

    def result(status: str, evidence: List[str], target: str, **kw) -> List[Finding]:
        f = F.Finding("cert.keymatch", title, status, F.SCOPE_LOCAL, evidence,
                      target=target, **kw)
        if emit is not None:
            emit(f)
        return [f]

    def not_tested(reason: str, target: str, kind: str = "", **kw) -> List[Finding]:
        return result(F.NOT_TESTED,
                      [reason, "the pairing could not be tested; this is not a mismatch"],
                      target, failure_kind=kind, **kw)

    if not shutil.which("openssl"):
        return not_tested("openssl binary not available", cert_path, "verifier-unavailable")
    state = key_file_state(key_path)
    if state == KEY_MISSING:
        return not_tested(f"key file not found: {key_path}", key_path)
    if state == KEY_UNREADABLE:
        return not_tested(f"key file cannot be read by this account: {key_path}",
                          key_path, "key-unreadable")
    if state == KEY_ENCRYPTED:
        return not_tested("the private key is passphrase-encrypted; ssl-doctor never "
                          "prompts for passphrases, so the match cannot be checked",
                          key_path, "key-encrypted",
                          detail="Decrypt a copy in a secure location and compare again "
                                 "with /cert match.")
    if state == KEY_UNSUPPORTED:
        return not_tested("the file is not a private key openssl can load", key_path)

    certs, err = load_cert_file(cert_path)
    if not certs:
        return not_tested(f"certificate unusable: {err or 'cannot parse certificate file'}",
                          cert_path)
    cert_fp, cert_err = _public_key_sha256_from_pem_bytes(certs[0].pem)
    if not cert_fp:
        return not_tested(f"the certificate's public key could not be derived"
                          f"{': ' + cert_err.splitlines()[-1] if cert_err else ''}",
                          cert_path, "command-failed")
    with open(key_path, "rb") as fh:
        key_data = fh.read()
    key_rc, key_der, key_err = _openssl_raw("pkey", "-passin", "pass:", "-pubout",
                                            "-outform", "DER", input_data=key_data)
    if key_rc != 0 and not key_data.lstrip().startswith(b"-----"):
        # openssl 1.1.1 does not detect DER input on its own
        key_rc, key_der, key_err = _openssl_raw("pkey", "-inform", "DER", "-passin",
                                                "pass:", "-pubout", "-outform", "DER",
                                                input_data=key_data)
    if key_rc != 0 or not key_der:
        msg = key_err.strip().splitlines()
        return not_tested(f"the key's public key could not be derived: "
                          f"{msg[-1] if msg else 'openssl could not read the key'}",
                          key_path, "command-failed")
    key_fp = hashlib.sha256(key_der).hexdigest()

    if cert_fp == key_fp:
        return result(F.PASS, ["public key embedded in the certificate matches this "
                               "private key", f"public-key SHA-256: {key_fp}"], cert_path)
    return result(
        F.FAIL, [f"certificate public-key SHA-256: {cert_fp}",
                 f"private key public SHA-256: {key_fp}",
                 "the private key does NOT belong to this certificate"], cert_path,
        recommendation="The server may be serving one certificate while holding the "
                       "key of another (common after renewals). Point the web server "
                       "at the matching pair.")
