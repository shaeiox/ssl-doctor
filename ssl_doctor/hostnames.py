"""Hostname coverage by a certificate, the way modern TLS clients decide it.

subjectAltName only (the CN is ignored), case-insensitive, one trailing dot
ignored, internationalised names compared as A-labels, wildcards covering
exactly one whole left-most label.  IP literals match only iPAddress entries.

The public-suffix guard is an embedded list of common multi-label suffixes
(the standard library has no Public Suffix List): `*.co.uk` is refused, an
unlisted suffix is accepted when the wildcard has at least two labels below it.
"""

from __future__ import annotations

import ipaddress
from typing import List, Optional, Tuple

# Multi-label public suffixes under which a wildcard must never match.  Not the
# full Public Suffix List; single-label TLDs are covered by the two-label rule.
_PUBLIC_SUFFIXES = frozenset("""
co.uk org.uk ac.uk gov.uk ltd.uk plc.uk net.uk me.uk sch.uk nhs.uk
com.au net.au org.au edu.au gov.au asn.au id.au
co.nz org.nz net.nz govt.nz ac.nz
co.jp ne.jp or.jp ac.jp go.jp
com.br net.br org.br gov.br
co.in net.in org.in gov.in ac.in
com.cn net.cn org.cn gov.cn edu.cn
com.mx org.mx gob.mx
co.za org.za gov.za ac.za
com.tr org.tr gov.tr
com.sg org.sg gov.sg edu.sg
com.hk org.hk gov.hk
co.kr or.kr go.kr ac.kr
com.ar com.co com.pe com.ve com.ph com.my com.tw com.ua com.pl
co.il org.il ac.il gov.il co.id or.id go.id ac.id
""".split())


def _a_label(name: str) -> Optional[str]:
    """Lower-case A-label form of `name`; None when it cannot be encoded."""
    name = name.strip().rstrip(".").lower()
    if not name:
        return None
    try:
        return name.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return name if name.isascii() else None


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def wildcard_matches(pattern: str, host: str) -> bool:
    """Does SAN `pattern` (A-label, lower case) cover `host` (A-label)?"""
    if "*" not in pattern:
        return pattern == host
    labels = pattern.split(".")
    if labels[0] != "*" or "*" in ".".join(labels[1:]):
        return False                       # partial ("w*") or non-left-most wildcard
    base = ".".join(labels[1:])
    if len(labels) < 3 or base in _PUBLIC_SUFFIXES:
        return False                       # "*.com", "*.co.uk"
    host_labels = host.split(".")
    return len(host_labels) == len(labels) and ".".join(host_labels[1:]) == base \
        and bool(host_labels[0])


def covers(san_dns: List[str], san_ip: List[str], host: str) -> Tuple[bool, str]:
    """(covered, matching SAN entry) for `host`."""
    if _is_ip(host.strip("[]")):
        target = ipaddress.ip_address(host.strip("[]"))
        for entry in san_ip:
            try:
                if ipaddress.ip_address(entry) == target:
                    return True, entry
            except ValueError:
                continue
        return False, ""
    wanted = _a_label(host)
    if wanted is None:
        return False, ""
    for entry in san_dns:
        pattern = _a_label(entry)
        if pattern is not None and wildcard_matches(pattern, wanted):
            return True, entry
    return False, ""


def why_not(san_dns: List[str], host: str) -> str:
    """A short reason when no entry covered `host` (for the evidence)."""
    wanted = _a_label(host) or host
    for entry in san_dns:
        pattern = (_a_label(entry) or entry)
        labels = pattern.split(".")
        if "*" in pattern and labels[0] != "*":
            return f"'{entry}' is a partial-label wildcard, which clients do not accept"
        if labels[0] == "*" and ".".join(labels[1:]) in _PUBLIC_SUFFIXES:
            return f"'{entry}' is a wildcard over a public suffix"
        if labels[0] == "*" and wanted == ".".join(labels[1:]):
            return f"'{entry}' does not cover the bare domain '{host}'"
        if labels[0] == "*" and wanted.endswith("." + ".".join(labels[1:])):
            return f"'{entry}' covers one label only, not '{host}'"
    return ""
