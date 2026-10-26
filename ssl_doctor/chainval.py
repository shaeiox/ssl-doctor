"""Cryptographic checks of certificate relationships, via the system openssl.

Names and key identifiers only say which certificate *claims* to have issued
another; these functions establish whether its key actually signed it.  Only
public certificate data is handled.  When no openssl binary is available
every answer says so (``LINK_NAME_ONLY`` / ``None``) and is never a pass.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from functools import lru_cache
from typing import Dict, List, Optional, Tuple

from .certs import CertInfo

LINK_VERIFIED = "verified"
LINK_SIGNATURE_FAILED = "signature-failed"
LINK_NAME_MISMATCH = "name-mismatch"
LINK_NOT_A_CA = "not-a-ca"
LINK_NAME_ONLY = "name-only"         # names match; signatures could not be checked
LINK_UNVERIFIED = "unverified"       # openssl ran but gave no usable answer

# `openssl verify` error numbers (crypto/x509/x509_txt.c); the CLI keeps
# going after extension errors, so every error of a run is listed.
_ERR_SIGNATURE = {7}                         # certificate signature failure
_ERR_ISSUER = {2, 20, 21, 29, 30, 31}        # issuer not found / key id mismatch
_ERR_NOT_CA = {24, 79}                       # invalid CA certificate
_ERROR_RE = re.compile(r"error (\d+) at (\d+) depth lookup: ([^\n]+)")


def available() -> bool:
    return shutil.which("openssl") is not None


@lru_cache(maxsize=1)
def _isolation_flags() -> Tuple[str, ...]:
    """Flags that stop `openssl verify` from consulting the system store."""
    flags = ["-no-CApath"]
    try:
        out = subprocess.run(["openssl", "verify", "-help"], capture_output=True,
                             text=True, timeout=10)
        if "-no-CAstore" in out.stdout + out.stderr:
            flags.append("-no-CAstore")          # openssl 3.x
    except (OSError, subprocess.TimeoutExpired):
        pass
    return tuple(flags)


def _verify(anchor_pem: bytes, child_pem: bytes, extra: Tuple[str, ...] = ()
            ) -> Tuple[Optional[int], List[Tuple[int, int, str]]]:
    """Run `openssl verify` with `anchor_pem` as the only trusted certificate.

    Returns (exit status, [(error number, depth, text)]); status None when
    openssl could not run.  Times are not checked: validity is judged elsewhere.
    """
    with tempfile.TemporaryDirectory(prefix="ssldoctor-verify-") as d:
        anchor, child = os.path.join(d, "anchor.pem"), os.path.join(d, "child.pem")
        for path, data in ((anchor, anchor_pem), (child, child_pem)):
            with open(path, "wb") as fh:
                fh.write(data)
        argv = ["openssl", "verify", "-partial_chain", "-no_check_time",
                *_isolation_flags(), *extra, "-CAfile", anchor, child]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            return None, []
    errors = [(int(n), int(depth), text.strip())
              for n, depth, text in _ERROR_RE.findall(proc.stdout + proc.stderr)]
    return proc.returncode, errors


_LINK_CACHE: Dict[Tuple[str, str], Tuple[str, str]] = {}


def verify_link(child: CertInfo, parent: CertInfo) -> Tuple[str, str]:
    """(state, detail): did `parent` issue and sign `child`?

    `not-a-ca` is decided from Basic Constraints when they were read; a
    signature is never assumed from matching names.
    """
    key = (child.sha256, parent.sha256)
    if key not in _LINK_CACHE:
        _LINK_CACHE[key] = _verify_link(child, parent)
    return _LINK_CACHE[key]


def _verify_link(child: CertInfo, parent: CertInfo) -> Tuple[str, str]:
    if child.issuer != parent.subject:
        return LINK_NAME_MISMATCH, "issuer name differs from the next certificate's subject"
    if parent.extensions_read and not parent.is_ca:
        return LINK_NOT_A_CA, "the issuing certificate is not a CA (Basic Constraints)"
    if not available():
        return LINK_NAME_ONLY, "names match; signature not verified (openssl not available)"
    rc, errors = _verify(parent.pem, child.pem)
    if rc is None:
        return LINK_NAME_ONLY, "names match; signature not verified (openssl did not run)"
    if rc == 0:
        return LINK_VERIFIED, "signature verified with the issuer's public key"
    numbers = {n for n, _depth, _t in errors}
    if numbers & _ERR_SIGNATURE:
        return LINK_SIGNATURE_FAILED, "signature does not verify with the issuer's public key"
    if numbers & _ERR_NOT_CA:
        return LINK_NOT_A_CA, "the issuing certificate is not a valid CA"
    if numbers & _ERR_ISSUER:
        return LINK_NAME_MISMATCH, "issuer not matched by name and key identifier"
    detail = "; ".join(t for _n, _d, t in errors) or f"openssl verify exited {rc}"
    return LINK_UNVERIFIED, detail


_SELF_CACHE: Dict[str, Optional[bool]] = {}


def self_signed(cert: CertInfo) -> Optional[bool]:
    """True when the certificate's own key signed it; None when unknowable.

    Matching subject and issuer names alone never count: the key identifiers
    must agree (openssl only treats a certificate as self-issued then) and the
    self-signature must verify.
    """
    if cert.sha256 not in _SELF_CACHE:
        _SELF_CACHE[cert.sha256] = _self_signed(cert)
    return _SELF_CACHE[cert.sha256]


def _self_signed(cert: CertInfo) -> Optional[bool]:
    if not cert.subject or cert.subject != cert.issuer:
        return False
    if cert.aki and cert.ski and cert.aki != cert.ski:
        return False
    if not available():
        return None
    rc, errors = _verify(cert.pem, cert.pem, ("-check_ss_sig",))
    if rc is None:
        return None
    if rc == 0:
        return True
    return False if {n for n, _d, _t in errors} & _ERR_SIGNATURE else None


ROLE_LEAF = "leaf"
ROLE_INTERMEDIATE = "intermediate"
ROLE_ROOT = "root"
ROLE_UNRELATED = "unrelated"
ROLE_UNKNOWN = ""                    # extensions could not be read

_CONNECTING = (LINK_VERIFIED, LINK_NAME_ONLY)


def classify_roles(chain: List[CertInfo]) -> List[str]:
    """Role of each certificate, from Basic Constraints and signatures.

    `root` needs a verified self-signature, so a certificate whose subject
    merely equals its issuer is an `intermediate` at most.  `unrelated` means
    no issuance link (in either direction) connects it to the first
    certificate, i.e. it plays no part in that certificate's chain.
    """
    roles: List[str] = []
    for c in chain:
        if not c.extensions_read:
            roles.append(ROLE_UNKNOWN)
        elif not c.is_ca:
            roles.append(ROLE_LEAF)
        else:
            roles.append(ROLE_ROOT if self_signed(c) else ROLE_INTERMEDIATE)
    connected = {0}
    frontier = [0]
    while frontier:
        i = frontier.pop()
        for j, other in enumerate(chain):
            if j in connected or other.sha256 == chain[i].sha256:
                continue
            if (verify_link(chain[i], other)[0] in _CONNECTING
                    or verify_link(other, chain[i])[0] in _CONNECTING):
                connected.add(j)
                frontier.append(j)
    for j in range(len(chain)):
        same_as_first = chain[j].sha256 == chain[0].sha256
        if j not in connected and not same_as_first and roles[j] != ROLE_UNKNOWN:
            roles[j] = ROLE_UNRELATED
    return roles


def inventory_lines(chain: List[CertInfo], roles: List[str]) -> List[str]:
    """One evidence line per certificate, in file order."""
    out = []
    for i, (c, role) in enumerate(zip(chain, roles), 1):
        window = (f"{c.not_before:%Y-%m-%d}..{c.not_after:%Y-%m-%d}"
                  if c.not_before and c.not_after else "validity unknown")
        ca = ("CA:TRUE" if c.is_ca else "CA:FALSE") if c.extensions_read else "CA:?"
        out.append(f"#{c.position or i} {role or 'role unknown'} · "
                   f"{c.common_name or c.subject or '(no subject)'} · issuer "
                   f"{c.issuer_common_name or c.issuer or '(none)'} · "
                   f"sha256 {c.sha256[:16]}… · {window} · {ca}")
    return out


def file_structure(chain: List[CertInfo]) -> Tuple[List[str], List[str], List[str]]:
    """(roles, wrong-leaf problems, warnings) for a certificate file.

    A CA certificate in first place means the file does not start with the
    server certificate; an unrelated certificate plays no part in the chain.
    Duplicates are reported by `certs.assess_chain`.
    """
    roles = classify_roles(chain)
    problems, warnings = [], []
    if roles and roles[0] in (ROLE_INTERMEDIATE, ROLE_ROOT):
        leaf_at = next((c.position or i + 1 for i, (c, r) in enumerate(zip(chain, roles))
                        if r == ROLE_LEAF), None)
        problems.append("the first certificate is a CA certificate, not the server "
                        "certificate"
                        + (f"; the server certificate is at position {leaf_at}"
                           if leaf_at else "; the file holds no server certificate"))
    seen = set()
    for i, (c, role) in enumerate(zip(chain, roles)):
        if role == ROLE_UNRELATED and c.sha256 not in seen:
            warnings.append(f"position {c.position or i + 1} "
                            f"('{c.common_name or c.subject}') is unrelated: it neither "
                            "issued nor was issued by another certificate in the file")
        seen.add(c.sha256)
    return roles, problems, warnings


CA_ROOTS = "roots"            # a file meant to hold trust anchors only
CA_SERVICE = "service"        # a service's CA file (may carry intermediates)


def ca_file_finding(parsed, path: str, scope: str, purpose: str = CA_ROOTS,
                    source: str = ""):
    """`cert.cafile` for a parsed root/CA bundle.

    A root needs CA:TRUE and a verified self-signature; a certificate whose
    subject merely equals its issuer is named as not self-signed.  For a
    service CA file (nginx ssl_trusted_certificate) intermediates are normal
    and only listed; leaf certificates or a file without any root warn.
    """
    from . import findings as F
    title = "Root / CA bundle file"
    head = [f"{path}{f' ({source})' if source else ''}"]
    if not parsed.ok:
        return F.Finding("cert.cafile", title, F.FAIL, scope,
                         head + (list(parsed.problems) or [parsed.error() or ""]),
                         recommendation="Re-create the file from complete PEM "
                                        "certificate blocks.", target=path)
    chain = parsed.certs
    roles = classify_roles(chain)
    ev = head + [f"certificates in file: {len(chain)}",
                 *inventory_lines(chain, roles)]
    issues, unknown = [], False
    for i, (c, role) in enumerate(zip(chain, roles)):
        where = f"position {c.position or i + 1} ('{c.common_name or c.subject}')"
        if role == ROLE_UNKNOWN:
            unknown = True
        elif role == ROLE_ROOT:
            continue
        elif c.subject == c.issuer:
            issues.append(f"{where}: subject equals issuer, but it is not self-signed "
                          "(its own key did not sign it), so it is not a root")
        elif role == ROLE_LEAF:
            issues.append(f"{where}: a leaf (non-CA) certificate, not a CA")
        elif purpose == CA_ROOTS:
            issues.append(f"{where}: a {role} certificate, not a root")
    roots = roles.count(ROLE_ROOT)
    if purpose == CA_ROOTS and issues:
        issues.insert(0, "file contains non-root certificates")
    if not roots and not unknown:
        issues.append("the file holds no root certificate")
    if unknown:
        return F.Finding("cert.cafile", title, F.WARNING, scope, ev + issues,
                         uncertainty=["certificate extensions and self-signatures could "
                                      "not be checked (openssl not available), so roots "
                                      "cannot be told apart"], target=path)
    if issues:
        return F.Finding("cert.cafile", title, F.WARNING, scope, ev + issues,
                         recommendation="Keep only the CA certificates this file is meant "
                                        "to trust; a root must be self-signed.",
                         target=path)
    return F.Finding("cert.cafile", title, F.PASS, scope,
                     ev + [f"{roots} verified root certificate(s)"], target=path)
