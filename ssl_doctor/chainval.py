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
    if not child.issued_name_of(parent):
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
    if not cert.subject or not cert.self_issued_name():
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
        elif c.self_issued_name():
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


# ---------------------------------------------------------------- chain building

FAIL_SIGNATURE = "chain-signature"      # a link's signature, CA flag or path length is wrong
FAIL_MISORDERED = "chain-misordered"    # a certificate is not followed by its issuer
FAIL_INCOMPLETE = "chain-incomplete"    # the issuer of the top certificate was not sent
FAIL_UNVERIFIED = "chain-unverified"    # names match, signatures could not be checked
FAIL_HYGIENE = "chain-hygiene"          # duplicates / unrelated certificates
FAIL_WRONG_LEAF = "chain-wrong-leaf"    # the file does not start with the server certificate

MAX_PATHS = 8
MAX_DEPTH = 8

_LINK_FAILURES = {LINK_SIGNATURE_FAILED: FAIL_SIGNATURE, LINK_NOT_A_CA: FAIL_SIGNATURE,
                  LINK_NAME_MISMATCH: FAIL_MISORDERED, LINK_UNVERIFIED: FAIL_UNVERIFIED}


def _label(c: CertInfo) -> str:
    return c.common_name or c.subject or "(no subject)"


def _ensure_extensions(c: CertInfo) -> None:
    """Trust-store roots are decoded without openssl; read them on demand."""
    if not c.extensions_read:
        from . import certs
        certs._enrich_with_openssl(c)


def _anchor_candidates(child: CertInfo, roots: List[CertInfo]) -> List[CertInfo]:
    """Roots that name themselves as `child`'s issuer, key-identifier match first."""
    named = [r for r in roots if child.issued_name_of(r)]
    for r in named:
        _ensure_extensions(r)
    if child.aki:
        named.sort(key=lambda r: r.ski != child.aki)
    return named


def _paths(chain: List[CertInfo], roots: List[CertInfo]
           ) -> Tuple[List[Tuple[List[CertInfo], CertInfo, bool]], List[str]]:
    """Every anchored path from chain[0]: [(certificates, anchor, verified)], notes.

    Uses the given certificates in any order plus the anchors; bounded by
    MAX_PATHS paths of at most MAX_DEPTH certificates.
    """
    found: List[Tuple[List[CertInfo], CertInfo, bool]] = []
    notes: List[str] = []
    root_ids = {r.sha256 for r in roots}

    def walk(path: List[CertInfo], verified: bool) -> None:
        if len(found) >= MAX_PATHS or len(path) > MAX_DEPTH:
            return
        node = path[-1]
        if node.sha256 in root_ids and len(path) > 1:
            found.append((path[:-1], node, verified))
            return
        anchors = _anchor_candidates(node, roots)
        if len(anchors) > 1:
            pick = anchors[0]
            note = (f"{len(anchors)} trusted roots share the name '{node.issuer}'"
                    + (f"; the one with key identifier {pick.ski[:16]}… matches "
                       f"'{_label(node)}'" if node.aki and pick.ski == node.aki else ""))
            if note not in notes:
                notes.append(note)
        for anchor in anchors:
            if anchor.sha256 == node.sha256:
                continue
            state, _ = verify_link(node, anchor)
            if state in _CONNECTING:
                found.append((list(path), anchor, verified and state == LINK_VERIFIED))
                if len(found) >= MAX_PATHS:
                    return
        for cand in chain:
            if cand in path or not node.issued_name_of(cand) or cand.sha256 == node.sha256:
                continue
            state, _ = verify_link(node, cand)
            if state in _CONNECTING:
                walk(path + [cand], verified and state == LINK_VERIFIED)
        if not anchors and not any(node.issued_name_of(c) and c is not node for c in chain):
            note = (f"'{_label(node)}': its issuer '{node.issuer}' is not among the "
                    "trusted anchors")
            if note not in notes:
                notes.append(note)

    if chain:
        walk([chain[0]], True)
    found.sort(key=lambda p: (not p[2], len(p[0])))
    return found, notes


def _missing_issuer(top: CertInfo) -> str:
    return (f"missing issuer: '{top.issuer}'"
            + (f" (key identifier {top.aki})" if top.aki else "")
            + (f"; the certificate names {', '.join(top.aia_ca_issuers)} as where to "
               "get it" if top.aia_ca_issuers else ""))


def assess(chain: List[CertInfo], roots: Optional[List[CertInfo]] = None):
    """Verify a chain as sent, then find the anchors it reaches.

    Order: each certificate must be issued and signed by the next one (a name
    break is `broken`/misordered; a signature, CA-flag or path-length failure
    is `broken`/signature).  Completeness: the top is a verified self-signed
    root, reaches a trusted anchor, or - for a verified multi-certificate chain
    whose top issuer is unknown here - stays `complete` with `anchored` False,
    because a missing root is a trust question, not a missing intermediate.
    """
    from . import certs
    unique, duplicates = certs.dedupe(chain)
    a = _assess(unique, roots)
    a.duplicates = duplicates
    a.evidence += [f"{d} (identical certificate, ignored for linkage)" for d in duplicates]
    return a


def _assess(chain: List[CertInfo], roots: Optional[List[CertInfo]]):
    from .certs import ChainAssessment
    name_only = False
    for i in range(len(chain) - 1):
        child, parent = chain[i], chain[i + 1]
        here, nxt = child.position or i + 1, parent.position or i + 2
        state, detail = verify_link(child, parent)
        if state == LINK_NAME_ONLY:
            name_only = True
            continue
        if state != LINK_VERIFIED:
            return ChainAssessment(
                "broken", broken_at=here, failure=_LINK_FAILURES[state],
                evidence=[f"position {here}: '{_label(child)}' is not issued by "
                          f"position {nxt} ('{_label(parent)}') [{detail}]"])
    for j in range(1, len(chain)):
        limit, below = chain[j].path_len, j - 1      # CAs between the leaf and chain[j]
        if limit is not None and below > limit:
            return ChainAssessment(
                "broken", broken_at=chain[j].position or j + 1, failure=FAIL_SIGNATURE,
                evidence=[f"position {chain[j].position or j + 1}: '{_label(chain[j])}' "
                          f"allows pathLenConstraint:{limit}, but {below} CA "
                          "certificate(s) follow it in the chain"])
    top = chain[-1]
    names = " -> ".join(_label(c) for c in chain)
    linked = ("linked by name only" if name_only else "signatures verified")
    ss = self_signed(top)
    if ss or (ss is None and top.self_issued_name()):
        a = ChainAssessment("complete", top.subject, name_only=name_only or ss is None,
                            anchored=True, anchor_cert=top,
                            evidence=[f"{len(chain)} certificate(s), {linked}, ends at a "
                                      f"self-signed root ({names})"
                                      if len(chain) > 1 else
                                      "single self-signed certificate "
                                      + ("(self-signature verified)" if ss else
                                         "(self-signature not verified)")])
        if ss is None:
            a.evidence.append("self-signature not verified (openssl not available)")
        return a
    if top.self_issued_name() and ss is False:
        uncertainty_note = (f"'{_label(top)}': subject equals issuer, but it is not "
                            "self-signed, so it is not accepted as an anchor")
    else:
        uncertainty_note = ""
    if roots is not None:
        paths, notes = _paths(chain, roots)
        if paths:
            used, anchor, verified = paths[0]
            rows = [f"path {i}: " + " -> ".join(_label(c) for c in p) +
                    f" -> [{_label(r)}]" + ("" if ok else " (name only)")
                    for i, (p, r, ok) in enumerate(paths, 1)]
            ev = [f"{len(chain)} certificate(s), {linked} ({names}); anchored by "
                  f"trusted root '{_label(anchor)}'", *rows]
            if len(paths) > 1:
                ev.append("the verdict uses path 1")
            if top in used and not top.self_issued_name():
                # the anchor is reached through the top certificate, which another
                # CA issued (a cross-signed CA): its own self-signed root is not here
                ev.append(f"no trusted root named '{top.subject}' is present here, so the "
                          f"path continues through position {top.position or len(chain)} "
                          f"('{_label(top)}', issued by '{top.issuer}')")
            ev += [n for n in notes if "share the name" in n]
            return ChainAssessment("complete", anchor.subject, anchored=True,
                                   name_only=name_only or not verified, evidence=ev,
                                   paths=rows, anchor_cert=anchor)
    if len(chain) > 1:
        note = ("root anchor list unavailable on this machine" if roots is None else
                f"its issuer '{top.issuer}' is not among this machine's trusted roots "
                "(anchor unknown)")
        return ChainAssessment(
            "complete", top.issuer, anchored=None if roots is None else False,
            name_only=name_only,
            evidence=[f"{len(chain)} certificate(s), {linked} ({names})",
                      f"top certificate is a CA; {note}"]
            + ([f"trust anchor not found here: '{top.issuer}'"
                 + (f" (key identifier {top.aki})" if top.aki else "")]
               if roots is not None else [])
            + ([uncertainty_note] if uncertainty_note else []))
    return ChainAssessment(
        "incomplete", failure=FAIL_INCOMPLETE, name_only=name_only,
        anchored=None if roots is None else False,
        evidence=[f"{len(chain)} certificate(s) ({names})",
                  "intermediate certificate(s) not sent: the chain ends "
                  f"at a non-CA certificate issued by '{top.issuer}'"
                  if not top.is_ca else
                  f"the chain ends at '{_label(top)}', whose issuer was not sent",
                  _missing_issuer(top)]
        + ([uncertainty_note] if uncertainty_note else []))


def chain_verdict(a) -> Tuple[str, str, List[str]]:
    """(finding status, failure kind, uncertainty) for a ChainAssessment."""
    from . import findings as F
    if a.status == "broken":
        return (F.FAIL if a.failure == FAIL_SIGNATURE else F.WARNING), a.failure, []
    if a.status == "incomplete":
        return F.WARNING, FAIL_INCOMPLETE, []
    if a.name_only:
        return F.WARNING, FAIL_UNVERIFIED, [
            "links matched by name only; signatures not verified (openssl not available)"]
    if a.duplicates:
        return F.WARNING, FAIL_HYGIENE, []
    return F.PASS, "", []


# Key Usage bits that let a key of this type authenticate a TLS server
_LEAF_KEY_USAGE = {"RSA": {"digitalSignature", "keyEncipherment"},
                   "RSA-PSS": {"digitalSignature"},
                   "EC": {"digitalSignature", "keyAgreement"},
                   "Ed25519": {"digitalSignature"}, "Ed448": {"digitalSignature"}}


def usage_finding(chain: List[CertInfo], scope: str, target: str):
    """`chain.usage`: is the leaf usable for TLS server authentication, and may
    each issuer sign certificates?  Judged from KU / EKU / Basic Constraints."""
    from . import findings as F
    title = "Certificate usage for TLS server authentication"
    if not chain:
        return F.Finding("chain.usage", title, F.NOT_TESTED, scope,
                         ["no certificate to check"], target=target)
    leaf = chain[0]
    if not leaf.extensions_read:
        return F.Finding("chain.usage", title, F.NOT_TESTED, scope,
                         ["certificate extensions could not be read (openssl not "
                          "available)"], target=target, failure_kind="verifier-unavailable")
    fails, warns, ok = [], [], []
    eku = set(leaf.ext_key_usage)
    if eku and not eku & {"serverAuth", "anyExtendedKeyUsage"}:
        fails.append(f"'{_label(leaf)}': certificate is not valid for TLS server "
                     f"authentication (Extended Key Usage: {', '.join(leaf.ext_key_usage)})")
    else:
        ok.append(f"'{_label(leaf)}': Extended Key Usage "
                  + (", ".join(leaf.ext_key_usage) if eku else "not restricted"))
    allowed = _LEAF_KEY_USAGE.get(leaf.key_type)
    if leaf.key_usage and allowed is not None and not set(leaf.key_usage) & allowed:
        fails.append(f"'{_label(leaf)}': Key Usage {', '.join(leaf.key_usage)} does not "
                     f"allow TLS server authentication with an {leaf.key_type} key")
    if leaf.is_ca:
        warns.append(f"'{_label(leaf)}': the server certificate is itself a CA "
                     "certificate (CA:TRUE)")
    for i, c in enumerate(chain[1:], 2):
        if not c.extensions_read:
            continue
        if c.key_usage and "keyCertSign" not in c.key_usage:
            fails.append(f"position {c.position or i} ('{_label(c)}'): Key Usage "
                         f"{', '.join(c.key_usage)} lacks keyCertSign, so it may not "
                         "issue certificates")
    if fails:
        return F.Finding("chain.usage", title, F.FAIL, scope, fails + warns + ok,
                         recommendation="Use a certificate issued for TLS server "
                                        "authentication (EKU serverAuth), with "
                                        "intermediates that may sign certificates.",
                         target=target)
    if warns:
        return F.Finding("chain.usage", title, F.WARNING, scope, warns + ok,
                         recommendation="Serve an end-entity certificate (CA:FALSE) for "
                                        "the domain.", target=target)
    return F.Finding("chain.usage", title, F.PASS, scope,
                     ok + ["every issuer with a Key Usage may sign certificates"],
                     target=target)


# ---------------------------------------------------------------- trust classification

TRUST_PUBLIC = "public"
TRUST_PRIVATE = "private"
TRUST_SELF_SIGNED = "self-signed"
TRUST_UNKNOWN = "unknown"


def store_label(roots: List[CertInfo]) -> str:
    """Which trust configuration the system anchors came from, for evidence."""
    import ssl
    paths = ssl.get_default_verify_paths()
    where = paths.cafile or paths.capath or "the platform's default store"
    return f"system trust store of this machine ({where}; {len(roots)} root anchor(s))"


def _in(cert: Optional[CertInfo], anchors: List[CertInfo]) -> bool:
    if cert is None:
        return False
    return any(cert.sha256 == r.sha256 or (cert.subject_canon == r.subject_canon
                                           and cert.ski and cert.ski == r.ski)
               for r in anchors)


def trust_finding(chain: List[CertInfo], scope: str, target: str,
                  roots: List[CertInfo], private: Optional[Tuple[List[CertInfo], str]] = None,
                  now=None):
    """`chain.trust`: which trust configuration (if any) anchors this chain.

    Evaluated offline from the certificates and anchors, so a network failure
    never changes it.  The class comes from verified paths only - an issuer
    *name* that looks public proves nothing.
    """
    from datetime import datetime, timezone
    from . import findings as F
    title = "Trust anchor and trust class"
    now = now or datetime.now(timezone.utc)
    if not chain:
        return F.Finding("chain.trust", title, F.NOT_TESTED, scope,
                         ["no certificate to evaluate"], target=target)
    if not available():
        return F.Finding("chain.trust", title, F.NOT_TESTED, scope,
                         ["trust class: unknown", "signatures cannot be verified "
                          "(openssl not available), so no trust anchor can be established"],
                         target=target, failure_kind="verifier-unavailable")
    if not roots and not private:
        return F.Finding("chain.trust", title, F.NOT_TESTED, scope,
                         ["no trust anchors available: the system trust store could not "
                          "be read or is empty"], target=target)
    store = store_label(roots)
    a = assess(chain, roots) if roots else None
    if a and a.status == "complete" and a.anchored and not a.name_only             and _in(a.anchor_cert, roots):
        anchor = a.anchor_cert
        ev = [f"trust class: {TRUST_PUBLIC}", f"anchor: '{_label(anchor)}' in the {store}",
              *a.paths]
        if anchor.not_after and anchor.not_after < now:
            return F.Finding(
                "chain.trust", title, F.WARNING, scope,
                ev + [f"anchor expired on {anchor.not_after:%Y-%m-%d}"],
                uncertainty=["this is the trust store of the checking machine: clients "
                             "with other stores may build a different path, and some "
                             "ignore an anchor's expiry"],
                recommendation="Serve a chain that leads to a current root (for example "
                               "the CA's newer cross-signed intermediate).",
                target=target)
        return F.Finding("chain.trust", title, F.PASS, scope, ev, target=target)
    if private:
        cas, source = private
        pa = assess(chain, cas)
        if pa.status == "complete" and pa.anchored and not pa.name_only:
            return F.Finding(
                "chain.trust", title, F.WARNING, scope,
                [f"trust class: {TRUST_PRIVATE}",
                 f"anchor: '{_label(pa.anchor_cert)}' from {source}",
                 f"not anchored in the {store}"],
                recommendation="Clients trust this chain only if that CA is installed "
                               "in their trust store.", target=target)
    leaf = chain[0]
    if len(chain) == 1 and self_signed(leaf):
        return F.Finding("chain.trust", title, F.WARNING, scope,
                         [f"trust class: {TRUST_SELF_SIGNED}",
                          f"'{_label(leaf)}' signed itself and is not in the {store}"],
                         recommendation="Clients will not trust it unless it is imported "
                                        "into their trust store.", target=target)
    reason = ("the chain does not verify" if a and a.status == "broken" else
              "no verified path to an anchor of the " + store)
    return F.Finding("chain.trust", title, F.WARNING, scope,
                     [f"trust class: {TRUST_UNKNOWN}", reason,
                      f"top issuer: '{chain[-1].issuer}'"],
                     recommendation="If this is an internal CA, install its root on the "
                                    "clients; otherwise serve the chain your CA issued.",
                     target=target)
