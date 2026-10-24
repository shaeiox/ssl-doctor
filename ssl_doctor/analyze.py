"""Diagnostic correlation: turn findings into prioritized root causes.

Rules look at the whole FindingStore (local + remote + server scopes),
distinguish confirmed errors from possible causes, cite the supporting
evidence, and rank causes so the most likely explanation comes first.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import findings as F


_TIMEOUT_KINDS = ("connect-timeout", "negotiation-timeout")


def _accepted_versions(matrix: Optional[F.Finding]) -> List[str]:
    """Protocol versions the matrix observed completing a handshake."""
    if not matrix or matrix.status not in (F.PASS, F.WARNING):
        return []
    return [row.split(":")[0] for row in matrix.evidence if ": accepted" in row]


@dataclass
class Cause:
    rank: int                     # lower = investigated first
    certainty: str                # 'confirmed' | 'probable' | 'possible'
    origin: str                   # network | server | client | certificate
    summary: str
    evidence: List[str] = field(default_factory=list)
    recommendation: str = ""
    limitations: List[str] = field(default_factory=list)  # known gaps in the evidence

    def to_dict(self) -> Dict:
        return {
            "rank": self.rank, "certainty": self.certainty, "origin": self.origin,
            "summary": self.summary, "evidence": self.evidence,
            "recommendation": self.recommendation,
            "limitations": self.limitations,
        }


@dataclass
class Unresolved:
    """A finding that stays a warning although no root cause is justified.

    `observed` is what the probe saw, `conclusion` the most the evidence
    supports, `uncertainty` why the question stays open.
    """
    check: str
    status: str
    observation: str
    observed: str
    conclusion: str
    uncertainty: List[str] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> Dict:
        return {"check": self.check, "status": self.status,
                "observation": self.observation, "observed": self.observed,
                "conclusion": self.conclusion, "uncertainty": self.uncertainty,
                "recommendation": self.recommendation}


@dataclass
class Diagnosis:
    causes: List[Cause] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    unresolved: List[Unresolved] = field(default_factory=list)

    @property
    def overall(self) -> str:
        if any(c.certainty == "confirmed" for c in self.causes):
            return "FAIL"
        if self.causes:
            return "WARNING"
        return "PASS"

    def to_dict(self) -> Dict:
        return {"overall": self.overall,
                "causes": [c.to_dict() for c in self.causes],
                "notes": self.notes,
                "unresolved": [u.to_dict() for u in self.unresolved]}


def _by_check(items: List[F.Finding], check: str) -> List[F.Finding]:
    # exact id match: 'tls.verify' must not pick up 'tls.verify.rootonly'
    return [f for f in items if f.check == check]


def _first(items: List[F.Finding], check: str) -> Optional[F.Finding]:
    sub = _by_check(items, check)
    return sub[-1] if sub else None  # most recent occurrence wins


def _severe(items: List[F.Finding]) -> List[F.Finding]:
    return [f for f in items if f.status in (F.FAIL, F.WARNING)]


def diagnose(items: List[F.Finding], context: Optional[Dict] = None) -> Diagnosis:
    ctx = context or {}
    d = Diagnosis()
    remote = [it for it in items if it.scope == F.SCOPE_REMOTE_NET]
    server = [it for it in items if it.scope == F.SCOPE_SERVER]
    local = [it for it in items if it.scope == F.SCOPE_LOCAL]
    rank = 10

    def add(certainty, origin, summary, evidence, recommendation, bump=0,
            limitations=None):
        nonlocal rank
        d.causes.append(Cause(rank + bump, certainty, origin, summary,
                              evidence, recommendation,
                              list(limitations or [])))
        rank += 10

    def note(text: str) -> None:
        if text not in d.notes:
            d.notes.append(text)

    # ---- transport first ---------------------------------------------------
    dns = _first(remote, "net.dns")
    tcp = _first(remote, "net.tcp")
    hs = _first(remote, "tls.handshake")
    verify = _first(remote, "tls.verify")

    if dns and dns.status == F.FAIL:
        add("confirmed", "network",
            "DNS resolution for the target hostname fails",
            dns.evidence, dns.recommendation)
        return _finish(d, items)
    if tcp and tcp.status == F.FAIL:
        add("confirmed", "network",
            "The TCP connection to the target port fails "
            "(firewall/routing/service down)",
            tcp.evidence, tcp.recommendation)
        return _finish(d, items)

    # ---- TLS negotiation ---------------------------------------------------
    # Attribution follows the *failure mode* recorded by the probe, never the
    # status alone: a stall and a rejection both end in FAIL but belong to
    # different owners, and only a rejection can support a protocol/cipher cause.
    matrix = _first(remote, "tls.protocols")
    if hs and (hs.status == F.FAIL
               or (hs.status == F.WARNING and hs.failure_kind in _TIMEOUT_KINDS)):
        kind = hs.failure_kind
        accepted = _accepted_versions(matrix)
        ev = ([f"handshake failure kind: {kind}"] if kind else []) + \
            hs.evidence + (matrix.evidence if matrix else [])
        single_sample = ["one scan is a single sample; a stall may be transient"]
        if hs.status == F.WARNING:
            add("probable", "network",
                "The TLS handshake stalls and completes only on a retry - "
                "intermittent path behaviour; the version probes answered",
                ev, "Repeat the measurement from another network. If the stall is "
                    "reproducible, inspect TLS-inspection devices and idle timeouts "
                    "on the path.", limitations=single_sample)
        elif kind in _TIMEOUT_KINDS and accepted:
            add("probable", "network",
                "The TLS handshake stalls although version-pinned handshakes "
                "complete - an intermittent stall or a middle-box on the path; the "
                "server answered every protocol version offered",
                ev, "Repeat the measurement and retest from another network; if it "
                    "recurs, inspect TLS-inspection devices and idle timeouts on the "
                    "path.", limitations=single_sample)
        elif kind in _TIMEOUT_KINDS:
            add("probable", "network",
                "TCP connects but no TLS version completes a handshake - the port "
                "may not serve TLS, or middle-boxes interfere",
                ev, "Confirm the port speaks TLS (openssl s_client), then inspect "
                    "firewalls/inspection devices on the path.")
        elif kind == "network-error":
            add("probable", "network",
                "The connection is reset or dropped during TLS negotiation - an "
                "inspection device or load balancer is the likely cause",
                ev, "Repeat the measurement and inspect TLS-inspection devices and "
                    "load balancers on the path.")
        elif kind == "tls-alert" and accepted:
            add("probable", "server",
                "TLS handshake fails for modern clients but some protocol "
                "versions work - protocol/cipher mismatch",
                ev, "Align enabled protocols/ciphers with the client capabilities.")
        elif kind == "tls-alert":
            add("probable", "server",
                "The server rejects the TLS handshake - the port may not serve TLS, "
                "or requires a version/cipher this client cannot offer",
                ev, "Confirm the port speaks TLS (openssl s_client) and compare its "
                    "protocol/cipher configuration with modern client defaults.")
        else:
            add("probable", "network",
                "The TLS handshake fails in an unclassified way while some protocol "
                "versions answer - cause not established",
                ev + ["the handshake failure was not classified by the probe, so no "
                      "protocol/cipher mismatch can be claimed"],
                "Repeat the scan with a current client build, then inspect the path "
                "for inspection devices.")

    # ---- server chain / nginx vhost (ranked ahead of client trust rules) ------
    # Judged from what the server sends and how nginx is configured - never
    # from this machine's trust store, whose cached intermediates can mask it.
    chain = _first(remote, "tls.chain")
    rootonly = _first(remote, "tls.verify.rootonly")
    chainfile = _first(server, "nginx.chainfile")
    vhost = _first(server, "nginx.domain")
    certref = _first(server, "nginx.certref")
    nginx_prot = _first(server, "nginx.protocols")
    chain_bad = [f for f in (chain, chainfile) if f and f.status == F.WARNING]
    rootonly_missing = bool(rootonly and rootonly.status == F.FAIL and any(
        k in " ".join(rootonly.evidence).lower()
        for k in ("local issuer", "first certificate")))
    server_chain_cause = bool(chain_bad or rootonly_missing)
    if server_chain_cause:
        joined = " ".join(e for f in chain_bad for e in f.evidence)
        broken = "is not issued by" in joined
        ev = [e for f in chain_bad for e in f.evidence] + \
             (rootonly.evidence[:1] if rootonly_missing else [])
        rec = next((f.recommendation for f in (chainfile, chain)
                    if f and f.status == F.WARNING and f.recommendation), "") or \
            (rootonly.recommendation if rootonly_missing else "")
        add("confirmed" if chain_bad else "probable", "server",
            "The server sends a wrong or misordered certificate chain - an "
            "intermediate does not match the certificate it should have issued"
            if broken else
            "The server does not send the full chain (missing intermediates) - "
            "clients without a cached intermediate fail",
            ev, rec)
    if vhost and vhost.status == F.WARNING:
        fallback = "fallback" in " ".join(vhost.evidence)
        add("probable", "server",
            "The domain has no dedicated nginx server block - a fallback block "
            "answers and may present the wrong certificate" if fallback else
            "Several nginx server blocks claim this domain - only the first one "
            "is used",
            vhost.evidence, vhost.recommendation)
    if certref and certref.status == F.WARNING:
        add("probable", "server",
            "The nginx server block for this domain has no ssl_certificate",
            certref.evidence, certref.recommendation)

    # ---- certificate validity ----------------------------------------------
    netval = _first(remote, "tls.certvalid")
    fileval = _first(local, "cert.validity")
    for val, where in ((netval, "presented by the server"),
                       (fileval, "in the inspected file")):
        if val and val.status == F.FAIL:
            add("confirmed", "certificate",
                f"The certificate {where} is outside its validity period",
                val.evidence, val.recommendation, bump=0)

    skew = _first(local, "local.clockskew")
    if skew and skew.status == F.FAIL and verify and verify.status == F.FAIL:
        add("probable", "client",
            "Client clock is significantly off and validation fails with date "
            "errors - the client, not the server, is the likely culprit",
            skew.evidence + verify.evidence,
            skew.recommendation or "Fix the client clock (NTP/w32time).")

    # ---- hostname / names ----------------------------------------------------
    namefail = None
    for c in (_first(remote, "tls.hostname"), _first(local, "cert.hostname")):
        if c and c.status == F.FAIL:
            namefail = c
    if namefail:
        sni_obs = _first(remote, "tls.sni")
        corroborate = ([f"additional observation: {e}" for e in sni_obs.evidence
                        if "observation" in e.lower()]
                       if sni_obs and sni_obs.observation == "sni-certificate-differs"
                       else [])
        add("confirmed", "certificate",
            "The certificate does not cover the hostname in use (name mismatch)",
            namefail.evidence + corroborate, namefail.recommendation)

    # ---- trust chain ---------------------------------------------------------
    chainwl = chain
    if verify and verify.status == F.FAIL:
        joined = " ".join(verify.evidence).lower()
        if ("local issuer" in joined or "first certificate" in joined) \
                and server_chain_cause:
            pass  # covered by the server chain rule above
        elif "local issuer" in joined or "first certificate" in joined:
            ev = verify.evidence + (chainwl.evidence if chainwl else [])
            if chainwl and chainwl.status == F.PASS:
                # full chain was sent: the root itself is what this machine lacks
                add("probable", "client",
                    "The server sends a complete chain, but its root CA is not "
                    "trusted by this machine (private/internal CA?)",
                    ev, "Import the issuing root CA into the trust store of the "
                        "affected clients, or use a publicly trusted certificate.")
            else:
                add("probable", "certificate",
                    "Validation cannot find the issuer: the server may omit "
                    "intermediates, or the root CA is not trusted here",
                    ev, verify.recommendation)
        elif "self signed" in joined:
            # confirmed only when the presented chain itself shows it
            direct = bool(chainwl and "self-signed" in " ".join(chainwl.evidence))
            add("confirmed" if direct else "probable", "server",
                "The server presents a self-signed certificate that clients do "
                "not trust",
                verify.evidence, verify.recommendation)
        elif "expired" in joined:
            pass  # already covered by validity rule
        elif "mismatch" in joined or "not cover" in joined:
            pass  # covered by hostname rule
        else:
            add("probable", "certificate",
                "Certificate validation failed against the system trust store",
                verify.evidence, verify.recommendation)

    # ---- local certificate file problems ---------------------------------------
    keymatch_local = _first(local, "cert.keymatch")
    if keymatch_local and keymatch_local.status == F.FAIL:
        add("confirmed", "certificate",
            "The inspected certificate file and private key do not match "
            "(the key belongs to a different certificate)",
            keymatch_local.evidence, keymatch_local.recommendation)

    # ---- SNI / vhost / pool consistency ---------------------------------------
    sni = _first(remote, "tls.sni")
    multi = _first(remote, "tls.multiip")
    cmp_srv = _first(server, "srv.compare")
    keymatch_srv = _first(server, "srv.keymatch")

    if cmp_srv and cmp_srv.status == F.FAIL:
        add("confirmed", "server",
            "The certificate actually served over the network differs from the "
            "certificate file configured on the server",
            cmp_srv.evidence, cmp_srv.recommendation)
    if keymatch_srv and keymatch_srv.status == F.FAIL:
        add("confirmed", "server",
            "The configured private key does not match the certificate on the "
            "server",
            keymatch_srv.evidence, keymatch_srv.recommendation)
    # An SNI observation ("a different default certificate is served") is not a
    # defect: name-based virtual hosting is expected to do exactly that.  Only a
    # failing handshake with the requested name is a finding of its own.
    if sni and sni.status == F.FAIL:
        add("probable", "server",
            "The endpoint does not complete a TLS handshake for the requested "
            "server name",
            sni.evidence, sni.recommendation or
            "Check that a virtual host answers for this name.", bump=40)

    # Endpoint comparison: only a measured difference between comparable
    # endpoints is a cause.  Missing evidence is reported as a note.
    if multi and multi.observation == "endpoint-certificate-difference":
        add("probable", "server",
            "Comparable endpoints behind this name present different certificate "
            "facts - clients may see different certificates depending on the "
            "endpoint they reach",
            multi.evidence, multi.recommendation, bump=30,
            limitations=["only the first endpoints returned by DNS were compared",
                         "a measured difference does not by itself prove a "
                         "misconfiguration: frontends may be deployed differently"])
    elif multi and multi.status == F.NOT_TESTED:
        detail = next((e for e in multi.evidence
                       if "inconclusive" in e.lower() or "no endpoint" in e.lower()),
                      "not enough endpoints returned certificate evidence")
        note(f"Endpoint comparison inconclusive - {detail.split(':', 1)[-1].strip()}"
             .replace("inconclusive - inconclusive", "inconclusive"))

    # ---- local trust / policy issues ------------------------------------------
    rootmiss = _first(local, "local.rootca")
    # Only meaningful when the presented chain was captured and is complete;
    # otherwise the "missing root" is an artefact of the server's chain.
    # Probable, not confirmed: this machine may not be the affected client.
    if rootmiss and rootmiss.status == F.FAIL and chain and chain.status == F.PASS \
            and not server_chain_cause:
        add("probable", "client",
            "The issuing root CA is missing from this machine's trusted root store",
            rootmiss.evidence, rootmiss.recommendation, bump=20,
            limitations=["this machine may not be the client that is failing"])
    certutil = _first(local, "local.certutil")
    if certutil and certutil.status == F.FAIL and verify and verify.status == F.PASS:
        add("probable", "client",
            "OpenSSL/system validation succeeds but the Windows chain engine "
            "fails - the failing application uses Schannel",
            certutil.evidence, certutil.recommendation, bump=20)
    proxy = _first(local, "local.proxy")
    if proxy and proxy.status == F.WARNING and verify and verify.status == F.FAIL:
        d.notes.append(
            "A proxy is configured and validation fails. If the presented issuer "
            "looks like an internal/security appliance, TLS interception is likely "
            "- install the proxy's root CA or create a bypass for this destination.")

    # ---- protocol hardening observations (warnings only) ----------------------
    # Which legacy conclusion the evidence supports decides the cause; the
    # probe classes are typed so no evidence text has to be parsed here.
    if matrix and matrix.observation == "legacy-accepted-default":
        add("possible", "server",
            "The server accepts deprecated TLS 1.0/1.1 with the default cipher "
            "policy - ordinary clients can negotiate them",
            matrix.evidence + ([matrix.detail] if matrix.detail else []),
            matrix.recommendation, bump=50)
    elif matrix and matrix.observation == "legacy-accepted-relaxed-only":
        add("possible", "server",
            "The server accepts deprecated TLS 1.0/1.1 only when legacy cipher "
            "suites are offered - a default-configured client is refused",
            matrix.evidence + ([matrix.detail] if matrix.detail else []),
            matrix.recommendation, bump=50,
            limitations=["legacy acceptance requires the relaxed cipher policy "
                         "(ALL:@SECLEVEL=0); an ordinary client cannot reach it"])
    elif matrix and matrix.observation == "legacy-accepted-unverified":
        # Only a lowered security level negotiated these versions.  That says
        # nothing about ordinary clients, so no cause is raised - but the
        # warning stays visible as an unresolved finding.
        d.unresolved.append(Unresolved(
            matrix.check, matrix.status, matrix.observation,
            observed=matrix.detail or "deprecated TLS completed a handshake only "
                                      "under a relaxed cipher policy",
            conclusion="Deprecated TLS may be enabled. The evidence supports only "
                       "that the server's TLS stack can negotiate it when legacy "
                       "cipher suites are offered; no protocol-risk cause is "
                       "raised because ordinary-client compatibility was not "
                       "established.",
            uncertainty=list(matrix.uncertainty),
            recommendation=matrix.recommendation))
    elif matrix and matrix.observation == "tls12-relaxed-only":
        add("possible", "server",
            "TLS 1.2 is reachable only with legacy cipher suites - a "
            "default-configured client is refused",
            matrix.evidence + ([matrix.detail] if matrix.detail else []),
            matrix.recommendation, bump=50,
            limitations=["TLS 1.2 acceptance required the relaxed cipher policy "
                         "(ALL:@SECLEVEL=0); many default-configured clients "
                         "cannot negotiate it"])
    elif matrix and matrix.status == F.WARNING:
        add("possible", "server",
            "Protocol configuration carries compatibility/security risks",
            matrix.evidence + ([matrix.detail] if matrix.detail else []),
            matrix.recommendation, bump=50)
    if matrix and matrix.failure_kind == "probe-inconclusive":
        # A probe that produced no answer is a gap in the evidence, never a
        # statement about what the server supports.
        inconclusive = [r for r in matrix.evidence if "inconclusive" in r]
        note("Protocol probe inconclusive: " +
             ("; ".join(inconclusive) or "a version probe returned no result") +
             " - this is a probe result, not evidence about server support")
    if nginx_prot and nginx_prot.status == F.WARNING and not (matrix and
                                                              matrix.status == F.WARNING):
        add("possible", "server", "nginx protocol configuration carries risks",
            nginx_prot.evidence + ([nginx_prot.detail] if nginx_prot.detail else []),
            nginx_prot.recommendation, bump=50)
    weak = _first(remote, "tls.weakcipher")
    if weak and weak.status == F.WARNING:
        add("possible", "server", "Server accepts obsolete ciphers",
            weak.evidence, weak.recommendation, bump=60)
    https = _first(remote, "https.response")
    if https and https.status == F.WARNING:
        d.notes.append("HTTPS layer problem observed: " + "; ".join(https.evidence)[:300]
                       + ((" " + https.recommendation) if https.recommendation else ""))

    return _finish(d, items)


def _finish(d: Diagnosis, items: List[F.Finding]) -> Diagnosis:
    d.causes.sort(key=lambda c: (c.rank,))
    if not d.causes:
        # Name what is still open instead of a generic "some checks warn";
        # findings already explained as unresolved are not repeated.
        explained = {u.check for u in d.unresolved}
        severe = [f for f in _severe(items) if f.check not in explained]
        if severe:
            listed = "; ".join(dict.fromkeys(f"{f.title} ({f.status})" for f in severe))
            d.notes.append(f"No root cause pattern matched these findings: {listed} "
                           f"- review their evidence below.")
        elif d.unresolved:
            d.notes.append("No root cause established; open warning(s): " +
                           "; ".join(u.observed for u in d.unresolved))
        elif any(f.status == F.NOT_TESTED for f in items):
            d.notes.append(
                "No root cause established: some checks could not be completed and "
                "their evidence is inconclusive (see the not-tested findings).")
        else:
            d.notes.append("All executed checks passed. If a problem persists, run "
                           "server-side checks (/server connect) and Windows client "
                           "checks (/local) for deeper evidence.")
    untested = [f.title for f in items if f.status == F.NOT_TESTED]
    if untested:
        d.notes.append("Not tested: " + "; ".join(dict.fromkeys(untested)))
    return d
