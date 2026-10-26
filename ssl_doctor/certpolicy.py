"""Lifecycle and cryptographic policy for certificates.

Validity windows of every certificate, the expiry-warning threshold (default
30 days, 1-365 per scan), intermediates that expire before the leaf, and the
key / signature-algorithm policy.  The policy is versioned so evidence says
which rules a verdict applied.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, List, Optional, Tuple

from . import findings as F
from .certs import CertInfo

DEFAULT_WARN_DAYS = 30
MIN_WARN_DAYS, MAX_WARN_DAYS = 1, 365
POLICY_VERSION = "policy 1"

_warn_days = DEFAULT_WARN_DAYS


def parse_warn_days(value) -> int:
    """Validate a threshold; raises ValueError naming the allowed range."""
    try:
        days = int(str(value).strip())
    except ValueError:
        raise ValueError(f"expiry warning threshold must be a whole number of days "
                         f"({MIN_WARN_DAYS}-{MAX_WARN_DAYS}), got {value!r}") from None
    if not MIN_WARN_DAYS <= days <= MAX_WARN_DAYS:
        raise ValueError(f"expiry warning threshold must be {MIN_WARN_DAYS}-"
                         f"{MAX_WARN_DAYS} days, got {days}")
    return days


def set_warn_days(value) -> int:
    global _warn_days
    _warn_days = parse_warn_days(value)
    return _warn_days


def warn_days() -> int:
    return _warn_days


def _days_left(c: CertInfo, now: datetime) -> Optional[int]:
    return (c.not_after - now).days if c.not_after else None


def leaf_validity(c: CertInfo, now: Optional[datetime] = None
                  ) -> Tuple[str, str, str]:
    """(status, evidence line, recommendation) for a leaf certificate."""
    now = now or datetime.now(timezone.utc)
    t = warn_days()
    if c.not_after and c.not_after < now:
        return (F.FAIL, f"certificate expired {(now - c.not_after).days} days ago "
                        f"(notAfter={c.not_after:%Y-%m-%d %H:%M UTC})",
                "Renew the certificate and deploy the new file to the server.")
    if c.not_before and c.not_before > now:
        return (F.FAIL, f"certificate is not valid until {c.not_before:%Y-%m-%d %H:%M UTC}",
                "Check the client system clock and the certificate issuance date.")
    days = _days_left(c, now)
    if days is None:
        return F.NOT_TESTED, "the certificate's validity dates could not be read", ""
    if days <= t:
        return (F.WARNING, f"certificate expires in {days} days ({c.not_after:%Y-%m-%d}; "
                           f"warning threshold {t} days)", "Renew the certificate soon.")
    return (F.PASS, f"valid until {c.not_after:%Y-%m-%d}: {days} days remaining "
                    f"(warning threshold {t} days)", "")


def _label(c: CertInfo, i: int) -> str:
    return f"position {c.position or i} ('{c.common_name or c.subject}')"


def chain_validity_finding(chain: List[CertInfo], scope: str, target: str,
                           now: Optional[datetime] = None) -> Optional[F.Finding]:
    """`chain.validity` for every certificate after the leaf; None for a lone leaf."""
    if len(chain) < 2:
        return None
    now = now or datetime.now(timezone.utc)
    t, leaf = warn_days(), chain[0]
    fails, warns, ok = [], [], []
    for i, c in enumerate(chain[1:], 2):
        where = _label(c, i)
        if c.not_after and c.not_after < now:
            fails.append(f"{where}: expired {(now - c.not_after).days} days ago "
                         f"(notAfter={c.not_after:%Y-%m-%d})")
            continue
        if c.not_before and c.not_before > now:
            fails.append(f"{where}: not valid until {c.not_before:%Y-%m-%d}")
            continue
        days = _days_left(c, now)
        if days is None:
            continue
        soon = days <= t
        if leaf.not_after and c.not_after and c.not_after < leaf.not_after:
            warns.append(f"{where}: expires on {c.not_after:%Y-%m-%d}, before the leaf "
                         f"({leaf.not_after:%Y-%m-%d}); the chain stops validating on "
                         f"{c.not_after:%Y-%m-%d}"
                         + (f" - within the warning threshold ({days} days)" if soon else ""))
        elif soon:
            warns.append(f"{where}: expires in {days} days ({c.not_after:%Y-%m-%d}; "
                         f"warning threshold {t} days)")
        else:
            ok.append(f"{where}: valid until {c.not_after:%Y-%m-%d} ({days} days)")
    title = "Validity of the other certificates in the chain"
    if fails:
        return F.Finding("chain.validity", title, F.FAIL, scope, fails + warns + ok,
                         recommendation="Replace the expired or not-yet-valid "
                                        "certificate(s) with the current intermediate "
                                        "from your CA.", target=target)
    if warns:
        return F.Finding("chain.validity", title, F.WARNING, scope, warns + ok,
                         recommendation="Install the CA's current intermediate before "
                                        "the old one expires.", target=target)
    return F.Finding("chain.validity", title, F.PASS, scope, ok, target=target)


# key policy: RSA / DSA bits, accepted EC curves
_MIN_RSA_BITS = 2048
_EC_CURVES = {"P-256", "P-384", "P-521", "prime256v1", "secp384r1", "secp521r1"}
_WEAK_SIGNATURE = ("md2", "md4", "md5", "sha1")


def _key_verdict(c: CertInfo) -> Tuple[str, str]:
    kind, bits = c.key_type, c.key_bits
    if kind in ("RSA", "RSA-PSS"):
        if bits is not None and bits < _MIN_RSA_BITS:
            return F.FAIL, f"{kind} {bits}-bit key is below the {_MIN_RSA_BITS}-bit minimum"
        return F.PASS, f"{kind} {bits or '?'}-bit key"
    if kind == "DSA":
        return F.FAIL, "DSA key: not accepted for TLS server certificates"
    if kind == "EC":
        if c.curve and c.curve not in _EC_CURVES:
            return F.WARNING, f"EC key on curve {c.curve}: not P-256/P-384/P-521"
        return F.PASS, f"EC key, curve {c.curve or '?'}"
    if kind in ("Ed25519", "Ed448"):
        return F.PASS, f"{kind} key"
    return F.WARNING, f"unknown key type '{kind or '?'}'"


def _signature_weak(algorithm: str) -> bool:
    name = algorithm.lower().replace("-", "")
    return any(w in name for w in _WEAK_SIGNATURE)


def policy_finding(chain: List[CertInfo], scope: str, target: str,
                   anchors: Iterable[str] = ()) -> F.Finding:
    """`cert.policy`: key strength and signature algorithm of every certificate.

    `anchors` are SHA-256 fingerprints of verified self-signed roots: their own
    self-signature is reported, not judged (clients do not rely on it).
    """
    title = "Key strength and signature algorithms"
    anchor_ids = set(anchors)
    if not chain or not chain[0].extensions_read:
        return F.Finding(title=title, check="cert.policy", status=F.NOT_TESTED,
                         scope=scope, target=target, failure_kind="verifier-unavailable",
                         evidence=["key and signature details could not be read "
                                   "(openssl not available)"])
    fails, warns, ok = [], [], []
    for i, c in enumerate(chain, 1):
        where = _label(c, i)
        status, text = _key_verdict(c)
        {F.FAIL: fails, F.WARNING: warns}.get(status, ok).append(f"{where}: {text}")
        sig = c.signature_algorithm or "?"
        if c.sha256 in anchor_ids:
            ok.append(f"{where}: signature {sig} (trust anchor's own self-signature, "
                      "not judged)")
        elif _signature_weak(sig):
            fails.append(f"{where}: signature algorithm {sig} is deprecated "
                         "(MD5 / SHA-1)")
        else:
            ok.append(f"{where}: signature {sig}")
    ev = [POLICY_VERSION + f": RSA >= {_MIN_RSA_BITS} bits, EC P-256/P-384/P-521, "
          "Ed25519/Ed448; no MD5/SHA-1 signatures except a root's own"]
    if fails:
        return F.Finding("cert.policy", title, F.FAIL, scope, ev + fails + warns + ok,
                         recommendation="Reissue the certificate (and use intermediates) "
                                        "with an RSA >= 2048-bit or ECDSA P-256 key and "
                                        "a SHA-256 signature.", target=target)
    if warns:
        return F.Finding("cert.policy", title, F.WARNING, scope, ev + warns + ok,
                         target=target)
    return F.Finding("cert.policy", title, F.PASS, scope, ev + ok, target=target)


def anchor_ids(chain: List[CertInfo]) -> List[str]:
    """Fingerprints of verified self-signed certificates in `chain`."""
    from . import chainval
    return [c.sha256 for c in chain if chainval.self_signed(c)]
