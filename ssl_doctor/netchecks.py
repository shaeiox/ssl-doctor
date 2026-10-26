"""Remote network SSL/TLS diagnostics.

Everything here targets a hostname/IP + port over the network using the
standard library only.  Checks are read-only: they never send credentials
and only make GET/HEAD requests after the TLS layer is established.
"""

from __future__ import annotations

import errno
import http.client
import ipaddress
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

from . import __version__, certs, findings as F

_VERIFY_CODES = {
    10: "certificate has expired",
    18: "self signed certificate",
    19: "self signed certificate in certificate chain",
    20: "unable to get local issuer certificate",
    21: "unable to verify the first certificate",
    62: "hostname mismatch (certificate does not cover this name)",
}


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def parse_target(text: str) -> Tuple[str, int, Optional[str], str]:
    """Normalize user input into (host, port, scheme_hint, error).

    Accepts: 'example.com', 'example.com:8443', 'https://example.com/path',
    plain IPv4/IPv6 literals.  A scheme in the input sets the default port.
    """
    import re as _re
    from urllib.parse import urlsplit

    raw = (text or "").strip()
    if not raw:
        return "", 443, None, "empty target"
    scheme_hint = None
    if _re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        parts = urlsplit(raw)
        scheme_hint = parts.scheme
        host = parts.hostname or ""
        port = parts.port or (443 if parts.scheme == "https" else 80)
        return host, port, scheme_hint, "" if host else "no hostname in URL"
    host, port = raw, None
    if raw.count(":") == 1:
        h, p = raw.rsplit(":", 1)
        if p.isdigit():
            host, port = h, int(p)
    if raw.startswith("[") and "]" in raw:           # [::1]:443
        end = raw.index("]")
        host = raw[1:end]
        rest = raw[end + 1:]
        if rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
    if port is None:
        port = 443
    if not host:
        return "", 443, scheme_hint, "empty hostname"
    if not (0 < port < 65536):
        return "", 443, scheme_hint, "invalid port number"
    return host, port, scheme_hint, ""


def domain_profile(host: str, port: int, ips: List[str], facts: Dict) -> F.Finding:
    """Summarize the target's identity: DNS, certificate names, canonical URL."""
    ev = [f"target: {host}:{port}"]
    if ips:
        ev.append(f"DNS addresses ({len(ips)}): {', '.join(ips)}")
    cert: Optional[certs.CertInfo] = facts.get("cert")
    if cert:
        names = list(cert.san_dns) + list(cert.san_ip)
        if cert.common_name and cert.common_name not in names:
            names = [cert.common_name] + names
        ev.append(f"certificate subject: {cert.subject}")
        ev.append(f"certificate identity: {', '.join(names) or '(no DNS names present)'}")
        ev.append(f"certificate issuer: {cert.issuer}")
        if cert.san_dns and not _is_ip(host):
            ok, _ = cert.matches_hostname(host)
            ev.append(f"'{host}' {'IS' if ok else 'is NOT'} a covered DNS name")
    final_url = facts.get("final_url")
    hops = facts.get("hops") or []
    if final_url:
        ev.append(f"canonical URL after redirects: {final_url}")
        from urllib.parse import urlsplit
        fh = urlsplit(final_url).hostname
        if fh and fh.lower() != host.lower():
            ev.append(f"requests for '{host}' are redirected to a different "
                      f"host '{fh}' - check you are diagnosing the right endpoint")
    if hops:
        ev.append(f"redirect chain: {' -> '.join(h for h, _s, _l in hops)}")
    status = F.PASS
    if cert and facts.get("sni") and not cert.matches_hostname(facts["sni"])[0]:
        status = F.WARNING
    return F.Finding("scan.domain", f"Domain profile for {host}", status,
                     F.SCOPE_REMOTE_NET, ev, target=f"{host}:{port}")


# ---------------------------------------------------------------- DNS / TCP

def check_dns(host: str, timeout: float = 5.0) -> Tuple[F.Finding, List[str]]:
    target = host
    if _is_ip(host):
        return F.Finding(
            "net.dns", f"DNS resolution for {host}", F.PASS, F.SCOPE_REMOTE_NET,
            [f"'{host}' is an IP literal; no DNS lookup required"],
            target=target), [host]
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return F.Finding(
            "net.dns", f"DNS resolution for {host}", F.FAIL, F.SCOPE_REMOTE_NET,
            [f"resolution failed: {exc}"],
            recommendation="Verify the hostname is correct, the client DNS servers are "
                           "reachable, and the record exists (nslookup/dig).",
            target=target), []
    except socket.timeout:
        return F.Finding(
            "net.dns", f"DNS resolution for {host}", F.FAIL, F.SCOPE_REMOTE_NET,
            [f"DNS lookup timed out after {timeout:.0f}s"],
            recommendation="Check local DNS resolver configuration and connectivity.",
            target=target), []
    finally:
        socket.setdefaulttimeout(old)
    ips = sorted({item[4][0] for item in infos})
    v4 = [i for i in ips if ":" not in i]
    v6 = [i for i in ips if ":" in i]
    return F.Finding(
        "net.dns", f"DNS resolution for {host}", F.PASS, F.SCOPE_REMOTE_NET,
        [f"IPv4: {', '.join(v4) or '(none)'}", f"IPv6: {', '.join(v6) or '(none)'}",
         f"{len(ips)} unique address(es)"],
        target=target), ips


def check_tcp(host: str, port: int, timeout: float, ip: Optional[str] = None) -> F.Finding:
    addr = ip or host
    sock = socket.socket(socket.AF_INET6 if ":" in addr else socket.AF_INET,
                         socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((addr, port))
    except socket.timeout:
        return F.Finding(
            "net.tcp", f"TCP connectivity to {host}:{port}", F.FAIL, F.SCOPE_REMOTE_NET,
            [f"connection to {addr}:{port} timed out after {timeout:.0f}s"],
            recommendation="A firewall or routing issue is likely blocking the port. "
                           "Test from another network, check local/proxy firewalls, and "
                           "verify the service listens on that port.",
            target=f"{host}:{port}")
    except ConnectionRefusedError:
        return F.Finding(
            "net.tcp", f"TCP connectivity to {host}:{port}", F.FAIL, F.SCOPE_REMOTE_NET,
            [f"{addr}:{port} actively refused the connection"],
            recommendation="Nothing is listening on this port (or a firewall sends RST). "
                           "Check the service is running and bound to this port.",
            target=f"{host}:{port}")
    except OSError as exc:
        return F.Finding(
            "net.tcp", f"TCP connectivity to {host}:{port}", F.FAIL, F.SCOPE_REMOTE_NET,
            [f"connect error to {addr}:{port}: {exc}"],
            target=f"{host}:{port}")
    finally:
        sock.close()
    return F.Finding(
        "net.tcp", f"TCP connectivity to {host}:{port}", F.PASS, F.SCOPE_REMOTE_NET,
        [f"connected to {addr}:{port} within the timeout"],
        target=f"{host}:{port}")


# ---------------------------------------------------------------- TLS core

def _make_context(verify: bool, min_v=None, max_v=None,
                  ciphers: Optional[str] = None) -> ssl.SSLContext:
    if verify:
        ctx = ssl.create_default_context()
        # modern clients ignore the CN; so must validation (SAN only)
        ctx.hostname_checks_common_name = False
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if ciphers is not None:
        try:
            ctx.set_ciphers(ciphers)
        except ssl.SSLError:
            pass
    if min_v is not None and hasattr(ssl, "TLSVersion"):
        ctx.minimum_version = min_v
    if max_v is not None and hasattr(ssl, "TLSVersion"):
        ctx.maximum_version = max_v
    return ctx


# A stall is retried once: one sample cannot distinguish an intermittent path
# from a persistent one, and the evidence must say which attempt did what.
_HANDSHAKE_RETRIES = 1

# OpenSSL's wording when the *peer* rejects our offer.  These are deterministic,
# so they are never retried and they are the only evidence that allows a
# protocol/cipher-mismatch diagnosis.
_ALERT_MARKERS = ("alert", "no shared cipher", "no cipher", "wrong version number",
                  "unsupported protocol", "handshake failure", "protocol version")

# ...and when the connection simply went away mid-handshake, which is a path
# problem even though OpenSSL reports it as an SSLError.
_NETWORK_MARKERS = ("eof occurred", "connection reset", "connection aborted",
                    "connection refused", "broken pipe", "timed out")


class _ConnectTimeout(socket.timeout):
    """The TCP connect itself timed out - the peer was never reached."""


class _NegotiationTimeout(socket.timeout):
    """TCP opened, but the peer sent no (or an incomplete) TLS response."""


def _connect(host: str, port: int, timeout: float,
             connect_ip: Optional[str] = None) -> socket.socket:
    addr = connect_ip or host
    try:
        return socket.create_connection((addr, port), timeout=timeout)
    except socket.timeout:
        raise _ConnectTimeout(f"connect to {addr}:{port} timed out") from None


def _negotiate(raw: socket.socket, ctx: ssl.SSLContext,
               server_hostname: Optional[str], timeout: float) -> ssl.SSLSocket:
    raw.settimeout(timeout)
    try:
        return ctx.wrap_socket(raw, server_hostname=server_hostname)
    except socket.timeout:
        _discard(raw)
        raise _NegotiationTimeout(
            "TLS negotiation on an open connection stalled (no server response)") from None
    except Exception:
        _discard(raw)
        raise


def _discard(raw: socket.socket) -> None:
    try:
        raw.close()
    except OSError:
        pass


def _handshake(host: str, port: int, server_hostname: Optional[str],
               ctx: ssl.SSLContext, timeout: float,
               connect_ip: Optional[str] = None) -> ssl.SSLSocket:
    return _negotiate(_connect(host, port, timeout, connect_ip), ctx,
                      server_hostname, timeout)


def _classify_negotiation_error(exc: BaseException) -> str:
    """Map a non-timeout negotiation failure onto a contract failure kind."""
    msg = str(exc).lower()
    if any(m in msg for m in _NETWORK_MARKERS):
        return "network-error"
    if isinstance(exc, ssl.SSLError) or any(m in msg for m in _ALERT_MARKERS):
        return "tls-alert"
    return "network-error"


# Readers tried in order to obtain the chain the server presented.  Tests may
# narrow this tuple to exercise fallbacks.
CHAIN_READERS = ("public-api", "private-api", "openssl-s_client")


def _cert_der(c) -> bytes:
    if isinstance(c, (bytes, bytearray)):
        return bytes(c)
    return c.public_bytes(ssl._ssl.ENCODING_DER)  # _ssl.Certificate (3.10-3.12)


def _chain_via_s_client(host: str, port: int, sni: Optional[str],
                        timeout: float) -> List[bytes]:
    import shutil
    import subprocess
    if not shutil.which("openssl"):
        raise RuntimeError("openssl binary not available")
    argv = ["openssl", "s_client", "-connect", f"{host}:{port}", "-showcerts"]
    if sni:
        argv += ["-servername", sni]
    proc = subprocess.run(argv, input=b"", capture_output=True, timeout=timeout + 5)
    blocks = certs.extract_pem_blocks(proc.stdout)
    if not blocks:
        raise RuntimeError("openssl s_client returned no certificates")
    return [certs.pem_to_der(b) for b in blocks]


def read_presented_chain(ssock: ssl.SSLSocket, host: str, port: int,
                         sni: Optional[str], timeout: float
                         ) -> Tuple[Optional[List[bytes]], str, List[str]]:
    """Return (DER chain as sent, reader used, errors).  Chain is None if unread."""
    errors: List[str] = []
    for reader in CHAIN_READERS:
        try:
            if reader == "public-api":
                fn = getattr(ssock, "get_unverified_chain", None)       # 3.13+
            elif reader == "private-api":
                fn = getattr(getattr(ssock, "_sslobj", None),
                             "get_unverified_chain", None)              # 3.10-3.12
            else:
                # release our connection first: single-connection servers
                # would otherwise block the second handshake
                ssock.close()
                return _chain_via_s_client(host, port, sni, timeout), reader, errors
            if fn is None:
                errors.append(f"{reader}: not available in this Python")
                continue
            raw = fn()
            if raw:
                return [_cert_der(c) for c in raw], reader, errors
            errors.append(f"{reader}: returned no certificates")
        except Exception as exc:  # noqa: BLE001 - try the next reader
            errors.append(f"{reader}: {exc}")
    return None, "", errors


_FAILURE_ADVICE = {
    "connect-timeout":
        "The TCP connection itself did not complete. Repeat the test from another "
        "network, and check routing/firewalls - the earlier TCP check may have used "
        "a different address.",
    "negotiation-timeout":
        "TCP opened previously, but the TLS negotiation stalls. An inspection device, "
        "an idle timeout or the wrong protocol on the port is likely.",
    "tls-alert":
        "The port may not speak TLS at all, or requires a version/cipher this client "
        "cannot offer. See the protocol matrix check.",
    "network-error":
        "The connection is reset or dropped during TLS negotiation - a TLS-inspection "
        "device or a load balancer is the likely cause.",
}

_TIMEOUT_KINDS = ("connect-timeout", "negotiation-timeout")


def _failure_summary(kind: str, addr: str, port: int) -> str:
    if kind == "connect-timeout":
        return f"could not open a TCP connection to {addr}:{port} within the timeout"
    if kind == "negotiation-timeout":
        return (f"TCP connected to {addr}:{port}, but the TLS negotiation stalled "
                f"with no server response")
    if kind == "tls-alert":
        return f"the peer at {addr}:{port} rejected the TLS handshake"
    return f"the connection to {addr}:{port} was reset or dropped during TLS negotiation"


def _presented_facts(ssock: ssl.SSLSocket, host: str, port: int,
                     sni: Optional[str], timeout: float) -> Dict:
    """Negotiated protocol/cipher plus the chain the server presented."""
    facts: Dict = {}
    try:
        proto = ssock.version() or "?"
        cipher = ssock.cipher() or ("?", "?", 0)
        der = ssock.getpeercert(binary_form=True)
        peercert = certs.decode_der(der) if der else None
        chain_der, reader, chain_errors = read_presented_chain(
            ssock, host, port, sni, timeout)
        chain: Optional[List[certs.CertInfo]] = None
        if chain_der is not None:
            chain = [certs.decode_der(c) for c in chain_der]
            if peercert:
                chain[0] = peercert
        facts.update({
            "protocol": proto,
            "cipher": cipher[0],
            "cipher_bits": cipher[2] if len(cipher) > 2 else 0,
            "cert": peercert,
            "chain": chain,               # None = the presented chain is unknown
            "chain_reader": reader,
            "chain_errors": chain_errors,
        })
    finally:
        ssock.close()
    return facts


def check_tls_basic(host: str, port: int, sni: Optional[str],
                    timeout: float, connect_ip: Optional[str] = None
                    ) -> Tuple[F.Finding, Dict]:
    """Unauthenticated TLS handshake: protocol, cipher, presented chain.

    A timeout-class failure is retried once, because a single stalled sample
    cannot be told apart from a persistent one.  A rejection by the peer is
    never retried: it is deterministic, and it is the only evidence that can
    support a protocol/cipher diagnosis.
    """
    addr = connect_ip or host
    target = f"{host}:{port}"
    facts: Dict = {"handshake_ip": addr, "handshake_attempts": 0}
    ctx = _make_context(verify=False)
    attempts: List[str] = []
    kind, ssock = "", None

    for attempt in range(1, _HANDSHAKE_RETRIES + 2):
        facts["handshake_attempts"] = attempt
        started = time.monotonic()
        try:
            ssock = _handshake(host, port, sni, ctx, timeout, connect_ip=connect_ip)
            elapsed = time.monotonic() - started
            attempts.append(f"attempt {attempt}: handshake completed in {elapsed:.1f}s")
            break
        except (_ConnectTimeout, _NegotiationTimeout) as exc:
            elapsed = time.monotonic() - started
            kind = ("connect-timeout" if isinstance(exc, _ConnectTimeout)
                    else "negotiation-timeout")
            attempts.append(f"attempt {attempt}: {exc} ({elapsed:.1f}s elapsed)")
        except (ssl.SSLError, OSError) as exc:
            kind = _classify_negotiation_error(exc)
            first = str(exc).splitlines()[0][:200] if str(exc) else type(exc).__name__
            attempts.append(f"attempt {attempt}: {first}")
            break                      # rejection/reset: retrying cannot change it

    if ssock is None:
        facts["handshake_failure"] = kind
        evidence = [_failure_summary(kind, addr, port)] + attempts
        return F.Finding(
            "tls.handshake", f"TLS handshake with {target}", F.FAIL,
            F.SCOPE_REMOTE_NET, evidence,
            recommendation=_FAILURE_ADVICE.get(kind, ""),
            target=target, failure_kind=kind), facts

    facts.update(_presented_facts(ssock, host, port, sni, timeout))
    proto = facts["protocol"]
    leaf: Optional[certs.CertInfo] = facts["cert"]
    if facts["chain"] is None:
        chain_line = "chain presented: could not be read"
    else:
        chain_line = (f"chain presented ({len(facts['chain'])}, via {facts['chain_reader']}): "
                      + " -> ".join((c.common_name or c.subject) for c in facts["chain"]))

    if kind in _TIMEOUT_KINDS:
        # Recovered stall: report it, but keep every fact the later checks need.
        facts["handshake_failure"] = kind
        return F.Finding(
            "tls.handshake", f"TLS handshake with {target}", F.WARNING,
            F.SCOPE_REMOTE_NET,
            [_failure_summary(kind, addr, port)] + attempts + [
                f"recovered on attempt {len(attempts)}: the handshake stalled, "
                f"then completed"] + (
                [f"negotiated protocol: {proto}",
                 f"cipher: {facts['cipher']} ({facts['cipher_bits']} bit)",
                 f"certificate presented: {leaf.subject}",
                 f"SHA-256: {leaf.sha256}",
                 chain_line] if leaf else []),
            detail="The handshake is not reliably reachable: an intermittent path "
                   "problem or an inspection device is likely.",
            recommendation=_FAILURE_ADVICE.get(kind, ""),
            target=target, failure_kind=kind), facts

    if not leaf:
        return F.Finding(
            "tls.handshake", f"TLS handshake with {target}", F.WARNING,
            F.SCOPE_REMOTE_NET,
            [f"handshake succeeded (protocol={proto}) but the server sent no certificate"],
            target=target), facts

    return F.Finding(
        "tls.handshake", f"TLS handshake with {target}", F.PASS,
        F.SCOPE_REMOTE_NET,
        [f"negotiated protocol: {proto}",
         f"cipher: {facts['cipher']} ({facts['cipher_bits']} bit)",
         f"certificate presented: {leaf.subject}",
         f"SHA-256: {leaf.sha256}",
         chain_line],
        target=target), facts


def _validation_unfinished(check: str, title: str, target: str, addr: str,
                           exc: BaseException) -> F.Finding:
    """A validation handshake that ended before any certificate verdict.

    Timeouts and resets say nothing about the certificate, so they are NOT
    TESTED with their failure kind; only a TLS-level rejection stays FAIL.
    """
    if isinstance(exc, (_ConnectTimeout, _NegotiationTimeout)):
        kind = ("connect-timeout" if isinstance(exc, _ConnectTimeout)
                else "negotiation-timeout")
    else:
        kind = _classify_negotiation_error(exc)
    first = str(exc).splitlines()[0][:200] if str(exc) else type(exc).__name__
    if kind == "tls-alert":
        return F.Finding(check, title, F.FAIL, F.SCOPE_REMOTE_NET,
                         [f"validated handshake with {addr} failed before verification: "
                          f"{first}"], target=target, failure_kind=kind)
    return F.Finding(
        check, title, F.NOT_TESTED, F.SCOPE_REMOTE_NET,
        [f"{_failure_summary(kind, addr, target.rsplit(':', 1)[-1])}: {first}",
         "the certificate was not validated; no conclusion about it is drawn"],
        recommendation="Repeat the scan; if the validation handshake keeps failing, "
                       "test from another network.",
        target=target, failure_kind=kind)


def check_tls_validation(host: str, port: int, sni: Optional[str],
                         timeout: float, connect_ip: Optional[str] = None) -> F.Finding:
    """Full validation handshake with the system trust store."""
    title = "Certificate validation (system trust)"
    target = f"{host}:{port}"
    addr = connect_ip or host
    if not sni:
        return F.Finding("tls.verify", title,
                         F.NOT_TESTED, F.SCOPE_REMOTE_NET,
                         ["no hostname available for verification"], target=target)
    ctx = _make_context(verify=True)
    try:
        ssock = _handshake(host, port, sni, ctx, timeout, connect_ip=connect_ip)
        ssock.close()
        return F.Finding(
            "tls.verify", title, F.PASS,
            F.SCOPE_REMOTE_NET,
            ["the presented certificate chains to a trusted root and matches "
             f"the hostname '{sni}'", f"validated against {addr}"], target=target)
    except ssl.SSLCertVerificationError as exc:
        code = getattr(exc, "verify_code", None)
        msg = getattr(exc, "verify_message", None) or str(exc)
        plain = _VERIFY_CODES.get(code, msg)
        advice = {
            10: "Renew the certificate on the server.",
            18: "The server uses a self-signed certificate. Deploy a CA-issued "
                "certificate, or (internally) import it into client trust stores.",
            19: "A self-signed/intermediate certificate appears inside the chain. "
                "Ensure the server sends the correct intermediates signed by a trusted root.",
            20: "The client cannot find the issuing CA. Usually the server forgets to "
                "send the intermediate certificate(s). Add them to the server chain.",
            21: "The first certificate could not be verified - often a wrong leaf or "
                "missing intermediates on the server.",
            62: "Install a certificate whose SAN/CN covers this hostname, or connect "
                "via the correct name.",
        }.get(code, "Inspect the chain details above and correct trust/chain issues.")
        return F.Finding(
            "tls.verify", title, F.FAIL,
            F.SCOPE_REMOTE_NET,
            [f"validation failed: {plain}", f"openssl verify detail: {msg}",
             f"validated against {addr}"],
            recommendation=advice, target=target)
    except ssl.CertificateError as exc:
        return F.Finding(
            "tls.verify", title, F.FAIL,
            F.SCOPE_REMOTE_NET, [f"hostname verification failed: {exc}"],
            recommendation="The certificate does not cover this hostname.",
            target=target)
    except (ssl.SSLError, OSError) as exc:
        return _validation_unfinished("tls.verify", title, target, addr, exc)


def check_tls_rootonly_validation(host: str, port: int, sni: Optional[str],
                                  timeout: float,
                                  roots: Optional[List[certs.CertInfo]] = None,
                                  connect_ip: Optional[str] = None) -> F.Finding:
    """Validate with trusted ROOTS only - no cached/bundled intermediates.

    This is what a client that has never seen the intermediate experiences,
    regardless of what this machine has cached.
    """
    title = "Certificate validation (roots only, no cached intermediates)"
    target = f"{host}:{port}"
    addr = connect_ip or host
    if not sni:
        return F.Finding("tls.verify.rootonly", title, F.NOT_TESTED, F.SCOPE_REMOTE_NET,
                         ["no hostname available for verification"], target=target)
    roots = certs.load_root_anchors() if roots is None else roots
    if not roots:
        return F.Finding("tls.verify.rootonly", title, F.NOT_TESTED, F.SCOPE_REMOTE_NET,
                         ["no root certificates could be read from the system store"],
                         target=target)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.hostname_checks_common_name = False
    ctx.load_verify_locations(cadata="".join(r.pem.decode("ascii") for r in roots))
    try:
        _handshake(host, port, sni, ctx, timeout, connect_ip=connect_ip).close()
        return F.Finding("tls.verify.rootonly", title, F.PASS, F.SCOPE_REMOTE_NET,
                         [f"chain validates from what the server sends, against "
                          f"{len(roots)} trusted root(s)", f"validated against {addr}"],
                         target=target)
    except ssl.SSLCertVerificationError as exc:
        code = getattr(exc, "verify_code", None)
        msg = getattr(exc, "verify_message", None) or str(exc)
        return F.Finding(
            "tls.verify.rootonly", title, F.FAIL, F.SCOPE_REMOTE_NET,
            [f"validation failed: {_VERIFY_CODES.get(code, msg)}",
             f"openssl verify detail: {msg}", f"validated against {addr}"],
            recommendation=("Clients without a cached intermediate fail here. Serve the "
                            "full chain (leaf + intermediates) from the server."
                            if code in (20, 21) else ""),
            target=target)
    except (ssl.SSLError, OSError) as exc:
        return _validation_unfinished("tls.verify.rootonly", title, target, addr, exc)


_RELAXED_CIPHER_POLICY = "ALL:@SECLEVEL=0"

# Upper bound on how long the matrix may spend relative to one probe deadline:
# every version gets at most one retry, so the worst case is 2 x versions.
PROBE_BUDGET_FACTOR = 2

_VERSION_LABELS = {
    "TLSv1": "TLS 1.0", "TLSv1.0": "TLS 1.0",
    "TLSv1.1": "TLS 1.1", "TLSv1.2": "TLS 1.2", "TLSv1.3": "TLS 1.3",
}

ACCEPTED = "accepted"
REFUSED = "refused"
INCONCLUSIVE = "inconclusive"
UNSUPPORTED = "unsupported"
# The *client* could not offer this version (build or security policy), so no
# statement about the server is possible.  Kept apart from "refused", which
# means the peer answered and said no.
CLIENT_LIMITED = "client-limited"

_LOCAL_LIMITATION_MARKERS = (
    "no protocols available", "no ciphers available", "no cipher can be selected",
    "unsupported protocol", "ca md too weak", "unknown protocol",
)


def _is_local_probe_limitation(exc: BaseException) -> bool:
    """True when the failure came from this client before the peer answered."""
    msg = str(exc).lower()
    if "alert" in msg:            # a TLS alert is the peer's answer, not our limit
        return False
    return any(marker in msg for marker in _LOCAL_LIMITATION_MARKERS)


def _probe_version(host: str, port: int, sni: Optional[str], label: str,
                   version, timeout: float, connect_ip: Optional[str],
                   relaxed: bool) -> Tuple[str, str]:
    """Probe one pinned protocol version.

    Returns (state, detail) where state is accepted / refused / inconclusive /
    unsupported / client-limited.  A timeout says nothing about the server; a
    client limitation says nothing at all beyond "this client cannot test it".
    """
    if not hasattr(ssl, "TLSVersion"):
        return UNSUPPORTED, "this Python/OpenSSL build cannot pin protocol versions"
    try:
        ctx = _make_context(verify=False, min_v=version, max_v=version,
                            ciphers=_RELAXED_CIPHER_POLICY if relaxed else None)
    except Exception as exc:      # noqa: BLE001 - a local limitation, not a verdict
        return CLIENT_LIMITED, f"local probe error: {type(exc).__name__}: {exc}"[:120]
    try:
        s = _handshake(host, port, sni, ctx, timeout, connect_ip=connect_ip)
        negotiated = s.version() or "?"
        s.close()
        return ACCEPTED, negotiated
    except (_ConnectTimeout, _NegotiationTimeout) as exc:
        return INCONCLUSIVE, f"probe timed out: {exc}"
    except ssl.SSLError as exc:
        first = str(exc).splitlines()[0][:80]
        if _is_local_probe_limitation(exc):
            return CLIENT_LIMITED, first
        return REFUSED, first
    except OSError as exc:
        return INCONCLUSIVE, f"network error: {str(exc).splitlines()[0][:100]}"
    except Exception as exc:                      # noqa: BLE001 - stay inconclusive
        return INCONCLUSIVE, f"local probe error: {type(exc).__name__}: {exc}"[:120]


# Per-version support classification (facts["probe_policy"]["support"]).
SUPPORT_DEFAULT = "default"            # accepted with the default cipher policy
SUPPORT_RELAXED_ONLY = "relaxed-only"  # accepted only when legacy suites are offered
SUPPORT_UNVERIFIED = "relaxed-only-unverified"  # accepted relaxed; ordinary clients untestable
SUPPORT_REJECTED = "rejected"
SUPPORT_INCONCLUSIVE = "inconclusive"

_LEGACY_VERSIONS = ("TLS 1.0", "TLS 1.1")


def check_protocol_matrix(host: str, port: int, sni: Optional[str],
                          timeout: float, connect_ip: Optional[str] = None,
                          negotiated: Optional[str] = None,
                          facts: Optional[Dict] = None) -> F.Finding:
    """Probe each TLS protocol version and separate what was actually proven.

    Two questions are answered per version and kept apart:

    * can the server negotiate it at all (the probe under the version's own
      policy, relaxed cipher suites for legacy versions), and
    * can an ordinary, default-configured client negotiate it (the same probe
      with this client's default security settings).

    Only the second establishes "legacy TLS is enabled for ordinary clients".
    A relaxed-only acceptance is reported as limited evidence, not as a verdict
    about normal clients.

    `negotiated` is the protocol the primary handshake established; a version it
    proved is never reported as refused or unsupported.
    """
    target = f"{host}:{port}"
    facts = facts if facts is not None else {}
    if not hasattr(ssl, "TLSVersion"):
        return F.Finding("tls.protocols", "TLS protocol version support",
                         F.NOT_TESTED, F.SCOPE_REMOTE_NET,
                         ["this Python/OpenSSL build cannot pin protocol versions"],
                         target=target)

    versions = [("TLS 1.0", ssl.TLSVersion.TLSv1, True),
                ("TLS 1.1", ssl.TLSVersion.TLSv1_1, True),
                ("TLS 1.2", ssl.TLSVersion.TLSv1_2, True),
                ("TLS 1.3", ssl.TLSVersion.TLSv1_3, False)]
    primary_label = _VERSION_LABELS.get(negotiated or "", "")
    started = time.monotonic()
    rows: List[str] = []
    support: Dict[str, str] = {}
    refused_versions: List[str] = []
    inconclusive_versions: List[str] = []
    limited_versions: List[str] = []
    # Outcome of the default-policy re-probe per version.  Kept as a state, not
    # prose: "client-limited" (this client never offered it) and "refused" (the
    # peer answered and said no) lead to opposite conclusions.
    default_probe: Dict[str, str] = {}
    attempts = 0

    def attempts_left() -> bool:
        return attempts < PROBE_BUDGET_FACTOR * (len(versions) + 3) and \
            (time.monotonic() - started) < timeout * PROBE_BUDGET_FACTOR * \
            (len(versions) + 3)

    def attempt(label: str, version, relaxed: bool) -> Tuple[str, str, bool]:
        """One probe, retried once when the result is inconclusive."""
        nonlocal attempts
        attempts += 1
        state, detail = _probe_version(host, port, sni, label, version, timeout,
                                       connect_ip, relaxed)
        retried = False
        if state == INCONCLUSIVE and attempts_left():
            attempts += 1
            retried = True
            state, detail = _probe_version(host, port, sni, label, version,
                                           timeout, connect_ip, relaxed)
        return state, detail, retried

    for label, version, legacy in versions:
        # ---- 1. can the server negotiate this version at all? ----------------
        state, detail, retried = attempt(label, version, legacy)
        if state == REFUSED and label == primary_label:
            # The primary handshake proved this version works; never call it refused.
            inconclusive_versions.append(label)
            support[label] = SUPPORT_INCONCLUSIVE
            rows.append(f"{label}: inconclusive - probe answered with an error "
                        f"({detail}), although the primary handshake negotiated "
                        f"{negotiated}")
            continue
        if state != ACCEPTED:
            if state == REFUSED:
                refused_versions.append(label)
                support[label] = SUPPORT_REJECTED
                rows.append(f"{label}: refused ({detail})")
            elif state == CLIENT_LIMITED:
                limited_versions.append(label)
                support[label] = SUPPORT_INCONCLUSIVE
                rows.append(f"{label}: inconclusive - this client could not offer the "
                            f"version ({detail})")
            else:
                inconclusive_versions.append(label)
                support[label] = SUPPORT_INCONCLUSIVE
                cite = (f"; the primary handshake negotiated {negotiated}"
                        if label == primary_label else "")
                budget_note = ("" if retried else
                               "; retry skipped: probe budget exhausted")
                rows.append(f"{label}: inconclusive - {detail}{cite}{budget_note}")
            continue

        accepted_note = " after 1 retry" if retried else ""
        rows.append((f"{label}: accepted under relaxed cipher policy ({detail})"
                     if legacy else f"{label}: accepted ({detail})") + accepted_note)
        if not legacy:
            support[label] = SUPPORT_DEFAULT
            continue

        # ---- 2. can an ordinary, default-configured client negotiate it? -----
        d_state, d_detail, d_retried = attempt(label, version, False)
        default_probe[label] = d_state
        if d_state == ACCEPTED:
            support[label] = SUPPORT_DEFAULT
            rows.append(f"{label}: also accepted with the default cipher policy "
                        f"({d_detail}) - a default-configured modern client can "
                        f"negotiate it")
        elif d_state == REFUSED:
            support[label] = SUPPORT_RELAXED_ONLY
            rows.append(f"{label}: accepted only under the relaxed cipher policy - "
                        f"the server refuses a default-configured client ({d_detail})")
        elif d_state == CLIENT_LIMITED:
            support[label] = SUPPORT_UNVERIFIED
            rows.append(f"{label}: default-policy probe cannot establish ordinary-client "
                        f"compatibility - this client could not offer {label} under "
                        f"its default security settings ({d_detail}); nothing was "
                        f"sent to the server, so this is not a server rejection")
        else:
            support[label] = SUPPORT_UNVERIFIED
            rows.append(f"{label}: default-policy probe cannot establish ordinary-client "
                        f"compatibility - no definite answer ({d_detail})")

    legacy_confirmed = [v for v in _LEGACY_VERSIONS
                        if support.get(v) in (SUPPORT_DEFAULT, SUPPORT_RELAXED_ONLY)]
    legacy_unverified = [v for v in _LEGACY_VERSIONS
                         if support.get(v) == SUPPORT_UNVERIFIED]
    accepted_any = [v for v, st in support.items()
                    if st in (SUPPORT_DEFAULT, SUPPORT_RELAXED_ONLY, SUPPORT_UNVERIFIED)]

    facts["probe_policy"] = {
        "negotiated": negotiated or "",
        "relaxed_versions": [label for label, _v, legacy in versions if legacy],
        "support": support,
        "confirmed_legacy": legacy_confirmed,
        "unverified_legacy": legacy_unverified,
        "default_probe": default_probe,
    }

    status, notes = F.PASS, []
    if not accepted_any:
        status = F.FAIL
        notes.append("no TLS version completed a handshake")
    elif accepted_any == ["TLS 1.3"]:
        notes.append("only TLS 1.3 supported")

    if legacy_confirmed:
        status = F.WARNING
        confirmed_default = [v for v in legacy_confirmed
                             if support[v] == SUPPORT_DEFAULT]
        relaxed_only = [v for v in legacy_confirmed
                        if support[v] == SUPPORT_RELAXED_ONLY]
        if confirmed_default:
            notes.append(f"deprecated {', '.join(confirmed_default)} accepted with the "
                         f"default cipher policy - ordinary clients can negotiate "
                         f"them (security/policy risk)")
        if relaxed_only:
            notes.append(f"deprecated {', '.join(relaxed_only)} accepted only when "
                         f"legacy cipher suites are offered; a default-configured "
                         f"client is refused (security/policy risk)")
    elif legacy_unverified:
        status = F.WARNING
        notes.append(f"deprecated {', '.join(legacy_unverified)} completed a handshake "
                     f"only under the relaxed cipher policy {_RELAXED_CIPHER_POLICY}; "
                     f"whether ordinary clients can negotiate them was NOT established "
                     f"by this probe")

    # Why the probes cannot settle ordinary-client compatibility, kept apart from
    # the evidence rows (what was observed) and the diagnosis (what follows).
    uncertainty: List[str] = []
    if legacy_unverified:
        uncertainty.append(
            f"a handshake under {_RELAXED_CIPHER_POLICY} shows only that the server "
            f"can negotiate {', '.join(legacy_unverified)} when legacy cipher suites "
            f"are offered at a lowered security level; ordinary clients do not offer "
            f"those suites")
        limited = [v for v in legacy_unverified if default_probe.get(v) == CLIENT_LIMITED]
        unanswered = [v for v in legacy_unverified if v not in limited]
        if limited:
            uncertainty.append(
                f"the default-policy probe for {', '.join(limited)} was never sent: "
                f"this client cannot offer the version under its default security "
                f"settings, so no server answer exists to tell acceptance from "
                f"rejection")
        if unanswered:
            uncertainty.append(
                f"the default-policy probe for {', '.join(unanswered)} produced no "
                f"definite answer (timeout or local error)")

    if support.get("TLS 1.2") == SUPPORT_RELAXED_ONLY:
        status = F.WARNING
        notes.append("TLS 1.2 is reachable only with legacy cipher suites - many "
                     "clients with default settings cannot connect")
    if support.get("TLS 1.2") == SUPPORT_REJECTED and accepted_any:
        status = F.WARNING
        notes.append("TLS 1.2 was refused - many clients cannot connect")
    if inconclusive_versions:
        if status == F.PASS:
            status = F.WARNING
        notes.append("probe inconclusive for " + ", ".join(inconclusive_versions) +
                     " - no conclusion about server support is drawn for those versions")
    if limited_versions:
        notes.append("this client could not offer " + ", ".join(limited_versions) +
                     " - that is a limitation of the test, not a server property")

    observation = ""
    if any(support.get(v) == SUPPORT_DEFAULT for v in legacy_confirmed):
        observation = "legacy-accepted-default"
    elif legacy_confirmed:
        observation = "legacy-accepted-relaxed-only"
    elif legacy_unverified:
        observation = "legacy-accepted-unverified"
    elif support.get("TLS 1.2") == SUPPORT_RELAXED_ONLY:
        observation = "tls12-relaxed-only"
    elif inconclusive_versions:
        observation = "probe-inconclusive"

    failure_kind = ""
    if not accepted_any:
        if refused_versions and len(refused_versions) == len(versions):
            failure_kind = "no-version-accepted"
        elif len(inconclusive_versions) == len(versions):
            failure_kind = "no-version-answered"
    elif inconclusive_versions and not failure_kind:
        failure_kind = "probe-inconclusive"

    if status == F.PASS:
        recommendation = ""
    elif legacy_confirmed:
        recommendation = ("Disable TLS 1.0/1.1 (and legacy cipher suites) and serve "
                          "TLS 1.2 and 1.3 only.")
    elif legacy_unverified:
        # Unconfirmed: ask for a controlled verification, and say what it can and
        # cannot prove, instead of presuming the versions are enabled.
        name = sni or host
        recommendation = (
            f"Not confirmed - verify before changing anything. Run a controlled test "
            f"from a client that can still offer {', '.join(legacy_unverified)}, e.g. "
            f"`openssl s_client -connect {host}:{port} -servername {name} -tls1` "
            f"(and `-tls1_1`); on OpenSSL 3.x add `-cipher 'DEFAULT:@SECLEVEL=0'`, "
            f"or use a client configured like the legacy clients you must support or "
            f"exclude. Limitations: a success shows only that the server negotiates "
            f"the version with a client offering those cipher suites, not that your "
            f"real clients can; a refusal covers only the suites that client offered. "
            f"The server's own protocol configuration (e.g. nginx `ssl_protocols`) is "
            f"authoritative - if policy forbids TLS 1.0/1.1, disable them there.")
    elif support.get("TLS 1.2") == SUPPORT_RELAXED_ONLY:
        recommendation = ("Configure TLS 1.2 to accept modern cipher suites under the "
                          "default policy so ordinary clients can connect, then remove "
                          "the legacy suites.")
    else:
        recommendation = ("Enable TLS 1.2 and 1.3 with the default cipher policy and "
                          "investigate the versions that were refused or inconclusive.")

    return F.Finding(
        "tls.protocols", "TLS protocol version support", status, F.SCOPE_REMOTE_NET,
        rows, detail="; ".join(notes), recommendation=recommendation,
        target=target, failure_kind=failure_kind, observation=observation,
        uncertainty=uncertainty)


def _sni_cert(host: str, port: int, server_name: Optional[str],
              timeout: float) -> certs.CertInfo:
    """Certificate served for this server name (raises on failure)."""
    ctx = _make_context(verify=False)
    s = _handshake(host, port, server_name, ctx, timeout)
    try:
        der = s.getpeercert(binary_form=True)
    finally:
        s.close()
    if not der:
        raise ssl.SSLError("the server sent no certificate")
    return certs.decode_der(der, enrich=False)


def check_sni_difference(host: str, port: int, sni: str,
                         timeout: float) -> F.Finding:
    """Report how the server answers with and without SNI.

    A different certificate for clients that send no SNI is what name-based TLS
    virtual hosting is supposed to do (default vhost, CDN, shared hosting), so
    it is recorded as an observation.  The defect question - does the endpoint
    serve a certificate for the requested name? - is answered by tls.hostname.
    """
    title = "Behaviour with and without SNI"
    target = f"{host}:{port}"
    if _is_ip(host):
        return F.Finding("tls.sni", title, F.NOT_TESTED, F.SCOPE_REMOTE_NET,
                         ["target is an IP literal; SNI comparison not applicable"],
                         target=target)

    try:
        with_sni = _sni_cert(host, port, sni, timeout)
    except (ssl.SSLError, OSError) as exc:
        return F.Finding("tls.sni", title, F.FAIL, F.SCOPE_REMOTE_NET,
                         [f"handshake with SNI '{sni}' failed: {exc}"],
                         recommendation="The endpoint does not serve TLS for this "
                                        "name. Check the virtual host that should "
                                        "answer for it.",
                         target=target)

    try:
        without_sni = _sni_cert(host, port, None, timeout)
    except (ssl.SSLError, OSError) as exc:
        return F.Finding(
            "tls.sni", title, F.NOT_TESTED, F.SCOPE_REMOTE_NET,
            [f"without SNI the probe failed: {str(exc).splitlines()[0][:120]}",
             f"with SNI '{sni}' the server serves SHA-256 {with_sni.sha256[:24]}...",
             "SNI dependence could not be determined from this probe"],
            detail="Some servers require SNI or reset connections that omit it. "
                   "That is a client-compatibility fact, not a configuration defect.",
            target=target, observation="sni-without-probe-failed")

    covers = with_sni.matches_hostname(sni)[0]
    coverage_line = (f"with SNI '{sni}' the served certificate covers that name"
                     if covers else
                     f"with SNI '{sni}' the served certificate does NOT cover that name")
    if with_sni.sha256 == without_sni.sha256:
        return F.Finding(
            "tls.sni", title, F.PASS, F.SCOPE_REMOTE_NET,
            ["the same certificate is served with and without SNI", coverage_line],
            target=target)

    return F.Finding(
        "tls.sni", title, F.PASS, F.SCOPE_REMOTE_NET,
        [f"observation: without SNI the server serves a different certificate "
         f"(SHA-256 {without_sni.sha256[:24]}... vs {with_sni.sha256[:24]}... with SNI)",
         coverage_line,
         "a default certificate for clients that send no SNI is legitimate for "
         "name-based TLS virtual hosting (default vhost, CDN or shared hosting)",
         "clients that send the requested name (every modern client) receive the "
         "certificate above"],
        detail="Observation only. Whether the endpoint is misconfigured depends on "
               "tls.hostname and tls.verify for the requested name, not on the "
               "certificate used for clients that send no SNI.",
        target=target, observation="sni-certificate-differs")


_ENDPOINT_CAP = 4          # bound the number of extra connections per scan

# Endpoint states: what a probe actually produced.  Only "negotiated" carries
# certificate evidence, so only it may take part in a comparison.
EP_NEGOTIATED = "negotiated"
EP_REJECTED = "tls-rejected"
EP_UNREACHABLE = "tcp-unreachable"
EP_TIMEOUT = "timed-out"
EP_NO_CERT = "probe-unavailable"


def _is_unreachable(exc: BaseException) -> bool:
    """True when the failure means the address could not be reached at all."""
    if isinstance(exc, (_ConnectTimeout, _NegotiationTimeout)):
        return False
    if isinstance(exc, ssl.SSLError) and "timed out" not in str(exc).lower():
        return False
    code = getattr(exc, "errno", None)
    if code in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ECONNREFUSED,
                errno.EADDRNOTAVAIL, errno.ENETDOWN, errno.EHOSTDOWN):
        return True
    text = str(exc).lower()
    return any(m in text for m in ("unreachable", "no route", "refused",
                                   "not known", "name or service not known"))


def _probe_endpoint(host: str, port: int, sni: Optional[str], timeout: float,
                    ip: str) -> Dict:
    """Probe one address and report *what happened*, not just a fingerprint.

    Returns {"ip", "state", "detail", "sha256", "hostname_ok", "chain_status",
    "sni"}.  Certificate fields are filled only for state "negotiated"; every
    other state explains why no certificate evidence exists.
    """
    record = {"ip": ip, "state": EP_UNREACHABLE, "detail": "", "sha256": "",
              "hostname_ok": None, "chain_status": "", "sni": sni}
    ssock = None
    try:
        ctx = _make_context(verify=False)
        ssock = _handshake(host, port, sni, ctx, timeout, connect_ip=ip)
        der = ssock.getpeercert(binary_form=True)
        name_for_chain = host if not _is_ip(host) else None
        chain_der, _reader, _errors = read_presented_chain(
            ssock, host, port, sni, timeout)
        ssock = None
    except (_ConnectTimeout, _NegotiationTimeout) as exc:
        record.update(state=EP_TIMEOUT, detail=str(exc))
        return record
    except ssl.SSLError as exc:
        record.update(state=EP_REJECTED, detail=str(exc).splitlines()[0][:120])
        return record
    except OSError as exc:
        if _is_unreachable(exc):
            record.update(state=EP_UNREACHABLE, detail=str(exc).splitlines()[0][:120])
        else:
            record.update(state=EP_TIMEOUT, detail=str(exc).splitlines()[0][:120])
        return record
    finally:
        if ssock is not None:
            _discard(ssock)

    if not der:
        record.update(state=EP_NO_CERT, detail="handshake succeeded without a certificate")
        return record
    leaf = certs.decode_der(der, enrich=False)
    record.update(state=EP_NEGOTIATED, sha256=leaf.sha256,
                  hostname_ok=(leaf.matches_hostname(sni)[0] if sni else None))
    if chain_der is not None:
        chain = [certs.decode_der(c) for c in chain_der]
        chain[0] = leaf
        try:
            record["chain_status"] = certs.assess_chain(
                chain, certs.load_root_anchors() if len(chain) == 1 else None).status
        except Exception:            # noqa: BLE001 - chain judgement is best effort
            record["chain_status"] = "unread"
    return record


def _describe_endpoint(rec: Dict) -> str:
    ip, state = rec["ip"], rec["state"]
    if state == EP_NEGOTIATED:
        bits = [f"SHA-256 {rec['sha256'][:16]}..."]
        if rec.get("hostname_ok") is not None:
            bits.append("covers the requested name" if rec["hostname_ok"]
                        else "does NOT cover the requested name")
        if rec.get("chain_status"):
            bits.append(f"chain {rec['chain_status']}")
        return f"{ip}: negotiated - " + ", ".join(bits)
    reason = f" ({rec['detail']})" if rec.get("detail") else ""
    return f"{ip}: {state}{reason}"


def check_multi_ip(host: str, port: int, ips: List[str], timeout: float,
                   sni: Optional[str] = None, facts: Optional[Dict] = None
                   ) -> F.Finding:
    """Compare certificate evidence across the addresses DNS returned.

    A certificate difference is reported only when at least two endpoints
    completed a handshake for the same server name and their certificate facts
    differ.  An unreachable, rejected or timed-out endpoint produced no
    certificate, so it can never be evidence of a difference.
    """
    target = f"{host}:{port}"
    facts = facts if facts is not None else {}
    server_name = sni if sni is not None else (None if _is_ip(host) else host)
    uniq = sorted(set(ips))
    facts["endpoints"] = []
    if len(uniq) < 2:
        facts["endpoint_comparison"] = {"probed": 0, "comparable": 0,
                                        "difference": False, "attribute": ""}
        return F.Finding("tls.multiip", "Multiple endpoint comparison", F.NOT_TESTED,
                         F.SCOPE_REMOTE_NET,
                         ["DNS returned fewer than two addresses - nothing to compare"],
                         target=target)

    probe_ips = uniq[:_ENDPOINT_CAP]
    records = [_probe_endpoint(host, port, server_name, timeout, ip)
               for ip in probe_ips]
    rows = [_describe_endpoint(r) for r in records]
    comparable = [r for r in records
                  if r["state"] == EP_NEGOTIATED and r.get("sni") == server_name]
    facts["endpoints"] = records
    facts["endpoint_comparison"] = {"probed": len(records), "comparable": len(comparable),
                                    "addresses": len(uniq),
                                    "difference": False, "attribute": ""}
    scope = (f"probed {len(records)} of {len(uniq)} address(es), server name "
             f"'{server_name or '-'}', timeout {timeout:.0f}s")
    # A match is a statement about the comparable endpoints only.
    unchecked = len(uniq) - len(comparable)
    coverage = (f"; {unchecked} of {len(uniq)} DNS address(es) were not compared "
                f"(not probed or no comparable certificate)" if unchecked else "")

    if len(comparable) < 2:
        only = [r for r in records if r["state"] != EP_NEGOTIATED]
        if comparable:
            summary = (f"endpoint comparison inconclusive: {len(comparable)} of "
                       f"{len(records)} endpoints yielded a certificate")
            kind, obs = "probe-inconclusive", "endpoint-comparison-inconclusive"
        else:
            summary = ("endpoint comparison inconclusive: no endpoint yielded a "
                       "certificate")
            kind = ("endpoint-unreachable"
                    if only and all(r["state"] in (EP_UNREACHABLE, EP_TIMEOUT)
                                    for r in only) else "probe-inconclusive")
            obs = "endpoint-comparison-inconclusive"
        return F.Finding(
            "tls.multiip", "Multiple endpoint comparison", F.NOT_TESTED,
            F.SCOPE_REMOTE_NET,
            [summary, f"{scope}; {len(comparable)} comparable of "
                     f"{len(records)} probed", *rows],
            detail="Comparing certificates needs at least two endpoints that "
                   "completed a handshake for the same server name.",
            recommendation="Entrypoints in this network could not all be reached. "
                           "Retest from a network with the same address-family "
                           "reachability before concluding anything about the "
                           "certificates behind the name.",
            target=target, failure_kind=kind, observation=obs)

    differences = []
    if len({r["sha256"] for r in comparable}) > 1:
        differences.append("certificate identity")
    covered = {r["hostname_ok"] for r in comparable if r["hostname_ok"] is not None}
    if len(covered) > 1:
        differences.append("hostname coverage")
    chains = {r["chain_status"] for r in comparable if r["chain_status"]}
    if len(chains) > 1:
        differences.append("chain status")

    if not differences:
        facts["endpoint_comparison"].update({"comparable": len(comparable)})
        return F.Finding(
            "tls.multiip", "Multiple endpoint comparison", F.PASS, F.SCOPE_REMOTE_NET,
            [f"the {len(comparable)} comparable endpoint(s) present the same "
             f"certificate facts{coverage}", f"{scope}", *rows],
            uncertainty=([f"consistency is established for {len(comparable)} of "
                          f"{len(uniq)} DNS addresses only"] if unchecked else []),
            target=target)

    facts["endpoint_comparison"].update({"difference": True,
                                         "attribute": ", ".join(differences)})
    return F.Finding(
        "tls.multiip", "Multiple endpoint comparison", F.WARNING, F.SCOPE_REMOTE_NET,
        [f"{len(comparable)} comparable endpoints differ in: "
         f"{', '.join(differences)}",
         "the difference is measured, not inferred: every listed endpoint completed "
         "a handshake for the same server name",
         f"{scope}", *rows],
        detail="Different frontends behind one name can legitimately serve different "
               "certificates; this reports the measured difference, not its cause.",
        recommendation="If every client should see the same certificate, align "
                       "certificate deployment across the endpoints listed above.",
        target=target, observation="endpoint-certificate-difference")


def check_weak_ciphers(host: str, port: int, sni: Optional[str],
                       timeout: float) -> F.Finding:
    """Best-effort probe for obsolete ciphers (RC4, 3DES, DES, EXPORT, NULL)."""
    target = f"{host}:{port}"
    ctx = _make_context(verify=False, ciphers="RC4:3DES:DES:EXPORT:NULL:@SECLEVEL=0")
    if hasattr(ssl, "TLSVersion"):
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        s = _handshake(host, port, sni, ctx, timeout)
        cipher = s.cipher()
        s.close()
        return F.Finding(
            "tls.weakcipher", "Obsolete cipher acceptance", F.WARNING,
            F.SCOPE_REMOTE_NET,
            [f"server accepted a legacy cipher: {cipher[0]} "
             f"({cipher[2]} bit) when only weak suites were offered"],
            recommendation="Disable RC4/3DES/DES/EXPORT/NULL suites in the server "
                           "TLS configuration.",
            target=target)
    except ssl.SSLError as exc:
        msg = str(exc)
        if "no cipher" in msg.lower() or "handshake failure" in msg.lower() \
                or "sslv3 alert" in msg.lower():
            return F.Finding(
                "tls.weakcipher", "Obsolete cipher acceptance", F.PASS,
                F.SCOPE_REMOTE_NET,
                ["server refused a connection offering only obsolete ciphers"],
                target=target)
        return F.Finding(
            "tls.weakcipher", "Obsolete cipher acceptance", F.NOT_TESTED,
            F.SCOPE_REMOTE_NET, [f"probe inconclusive: {msg.splitlines()[0][:100]}"],
            target=target)
    except OSError as exc:
        return F.Finding(
            "tls.weakcipher", "Obsolete cipher acceptance", F.NOT_TESTED,
            F.SCOPE_REMOTE_NET, [f"probe failed: {exc}"], target=target)


def check_https(host: str, port: int, sni: Optional[str], timeout: float,
                max_redirects: int = 5) -> Tuple[F.Finding, Dict]:
    """Fetch '/' over HTTPS and follow redirects (read-only)."""
    target = f"{host}:{port}"
    facts: Dict = {"hops": [], "server_time": None, "final_url": None}
    current_host, current_port = host, port
    rows = []
    for _ in range(max_redirects + 1):
        try:
            ctx = _make_context(verify=False)
            conn = http.client.HTTPSConnection(
                current_host, current_port, timeout=timeout, context=ctx)
            conn.request("GET", "/", headers={"Host": current_host,
                                              "User-Agent": "ssl-doctor/" + __version__,
                                              "Connection": "close"})
            resp = conn.getresponse()
            body = resp.read(512)
            loc = resp.getheader("Location")
            server = resp.getheader("Server") or "?"
            date_hdr = resp.getheader("Date")
            if date_hdr:
                try:
                    from email.utils import parsedate_to_datetime
                    facts["server_time"] = parsedate_to_datetime(date_hdr)
                except (TypeError, ValueError, IndexError):
                    pass            # a malformed Date header: clock skew is simply not measured
            rows.append(
                f"https://{current_host}:{current_port}/ -> "
                f"{resp.status} {resp.reason} (Server: {server})")
            conn.close()
            if resp.status in (301, 302, 303, 307, 308) and loc:
                from urllib.parse import urlsplit
                parts = urlsplit(loc if "://" in loc else
                                 f"https://{current_host}:{current_port}{loc}")
                if parts.scheme not in ("https", "http"):
                    break
                if parts.scheme == "http":
                    rows.append(f"redirect downgrades to plain HTTP: {loc}")
                next_port = parts.port or (443 if parts.scheme == "https" else 80)
                facts["hops"].append((current_host, resp.status, loc))
                current_host, current_port = parts.hostname or current_host, next_port
                facts["final_url"] = f"{parts.scheme}://{current_host}:{next_port}/"
                continue
            facts["final_url"] = f"https://{current_host}:{current_port}/"
            return F.Finding("https.response", "HTTPS response analysis", F.PASS,
                             F.SCOPE_REMOTE_NET, rows, target=target), facts
        except socket.timeout:
            rows.append(f"https://{current_host}:{current_port}/ -> timeout")
            return F.Finding("https.response", "HTTPS response analysis", F.WARNING,
                             F.SCOPE_REMOTE_NET, rows,
                             recommendation="TLS works but HTTP stalls - application or "
                                            "proxy layer issue.", target=target), facts
        except (ssl.SSLError, http.client.HTTPException, OSError) as exc:
            rows.append(f"https://{current_host}:{current_port}/ -> {exc}")
            return F.Finding("https.response", "HTTPS response analysis", F.WARNING,
                             F.SCOPE_REMOTE_NET, rows, target=target), facts
    rows.append(f"more than {max_redirects} redirects (possible redirect loop)")
    return F.Finding("https.response", "HTTPS response analysis", F.WARNING,
                     F.SCOPE_REMOTE_NET, rows,
                     recommendation="Check redirect rules; a loop or http<->https "
                                    "flip breaks clients.", target=target), facts


def check_presented_chain(facts: Dict, host: str, port: int) -> F.Finding:
    """Judge the chain the server sent; records the verdict in `facts`.

    Sets facts["chain_status"] (complete | incomplete | broken | unread) and
    facts["anchor"] (DN of the root clients must trust, when determinable).
    """
    target = f"{host}:{port}"
    chain = facts.get("chain")
    facts["chain_status"], facts["anchor"] = "unread", ""
    if chain is None:
        return F.Finding(
            "tls.chain", "Chain sent by server", F.NOT_TESTED, F.SCOPE_REMOTE_NET,
            ["the presented certificate chain could not be read",
             *facts.get("chain_errors", [])],
            recommendation="Inspect manually: openssl s_client -connect "
                           f"{host}:{port} -servername <name> -showcerts",
            target=target)
    leaf = chain[0]
    if len(chain) == 1 and leaf.is_self_signed():
        facts["chain_status"], facts["anchor"] = "complete", leaf.subject
        return F.Finding("tls.chain", "Chain sent by server", F.PASS, F.SCOPE_REMOTE_NET,
                         ["single self-signed certificate (no chain to send)"],
                         target=target)
    roots = certs.load_root_anchors() if len(chain) == 1 else None
    a = certs.assess_chain(chain, roots)
    facts["chain_status"], facts["anchor"] = a.status, a.anchor
    ev = a.evidence + [f"read via: {facts.get('chain_reader') or '?'}"]
    if a.status == "complete":
        return F.Finding("tls.chain", "Chain sent by server", F.PASS, F.SCOPE_REMOTE_NET,
                         ev, target=target)
    rec = ("Fix the order/content of the chain file on the server: leaf first, then the "
           "intermediate that issued it." if a.status == "broken" else
           "Serve the full chain: put the leaf followed by the issuing intermediate(s) in "
           "the server's certificate file (nginx: ssl_certificate). Clients without a "
           "cached intermediate fail otherwise.")
    return F.Finding("tls.chain", "Chain sent by server", F.WARNING, F.SCOPE_REMOTE_NET,
                     ev, recommendation=rec, target=target)


def export_facts(facts: Dict) -> Dict:
    """The contract's structured `facts` block from a remote scan's facts."""
    leaf = facts.get("cert")
    return {
        "leaf": {"sha256": leaf.sha256, "subject": leaf.subject,
                 "not_after": leaf.not_after.isoformat() if leaf.not_after else None}
        if leaf else None,
        "chain_status": facts.get("chain_status", "unread"),
        "handshake_ip": facts.get("handshake_ip"),
        "handshake_failure": facts.get("handshake_failure", ""),
        "endpoints": facts.get("endpoints", []),
        "endpoint_comparison": facts.get("endpoint_comparison"),
        "probe_policy": facts.get("probe_policy"),
    }


# ---------------------------------------------------------------- orchestrator

def _note_handshake_coherence(hs: F.Finding, matrix: F.Finding) -> None:
    """Keep a failed handshake and a working protocol matrix from contradicting.

    The two checks answer different questions, so the failed one must say which
    versions did answer - otherwise "handshake fails" plus "TLS 1.2/1.3 accepted"
    reads as one endpoint that cannot negotiate TLS at all.
    """
    accepted = [r.split(":")[0] for r in matrix.evidence if ": accepted" in r]
    if not accepted:
        return
    if hs.failure_kind in _TIMEOUT_KINDS:
        hs.evidence.append(
            f"per-version probes completed for {', '.join(accepted)} - the failure is a "
            f"stall on the default path, not a protocol/cipher rejection")
    elif hs.failure_kind == "tls-alert":
        hs.evidence.append(
            f"per-version probes accepted {', '.join(accepted)} - the server rejected "
            f"this offer while accepting those")


def run_remote_diagnostics(host: str, port: int = 443, sni: Optional[str] = None,
                           timeout: float = 8.0,
                           emit: Optional[Callable[[F.Finding], None]] = None
                           ) -> Tuple[List[F.Finding], Dict]:
    """Run the full remote check suite against one endpoint.

    Returns (findings, facts).  `facts` carries structured values the CLI
    session stores for later correlation/clock analysis.

    When `emit` is provided, each finding is delivered to it as it is produced,
    in addition to being returned (for live CLI streaming).
    """
    out: List[F.Finding] = []
    facts: Dict = {"host": host, "port": port}
    server_name = sni or (None if _is_ip(host) else host)
    facts["sni"] = server_name

    def _add(f: F.Finding) -> F.Finding:
        list.append(out, f)
        if emit is not None:
            emit(f)
        return f

    dns_f, ips = check_dns(host, timeout)
    _add(dns_f)
    facts["ips"] = ips
    if not ips and not _is_ip(host):
        _add(F.Finding(
            "tls.handshake", f"TLS handshake with {host}:{port}", F.NOT_TESTED,
            F.SCOPE_REMOTE_NET, ["skipped: DNS failure"], target=f"{host}:{port}"))
        return out, facts

    tcp_f = check_tcp(host, port, timeout, ip=ips[0] if ips else None)
    _add(tcp_f)
    if tcp_f.status != F.PASS:
        _add(F.Finding(
            "tls.handshake", f"TLS handshake with {host}:{port}", F.NOT_TESTED,
            F.SCOPE_REMOTE_NET, ["skipped: TCP failure"], target=f"{host}:{port}"))
        return out, facts

    # Probe the address the TCP check proved reachable; comparing several
    # addresses stays the job of check_multi_ip().
    verified_ip = ips[0] if ips else None
    hs_f, hs_facts = check_tls_basic(host, port, server_name, timeout,
                                     connect_ip=verified_ip)
    facts.update(hs_facts)
    if hs_f.status == F.FAIL:
        matrix_f = check_protocol_matrix(host, port, server_name, timeout,
                                         connect_ip=verified_ip,
                                         negotiated=facts.get("protocol"),
                                         facts=facts)
        # Annotate before emitting: a streamed finding is printed as it is added.
        _note_handshake_coherence(hs_f, matrix_f)
        _add(hs_f)
        _add(matrix_f)
        return out, facts
    _add(hs_f)

    # Leaf self-checks over the network-presented cert.
    leaf = facts.get("cert")
    if leaf:
        if leaf.is_expired():
            _add(F.Finding(
                "tls.certvalid", "Presented certificate validity", F.FAIL,
                F.SCOPE_REMOTE_NET,
                [f"server presents an EXPIRED certificate "
                 f"(notAfter={leaf.not_after:%Y-%m-%d}; {-leaf.days_to_expiry()} days ago)"],
                recommendation="Renew/redeploy the certificate on the server.",
                target=f"{host}:{port}"))
        elif leaf.not_yet_valid():
            _add(F.Finding(
                "tls.certvalid", "Presented certificate validity", F.FAIL,
                F.SCOPE_REMOTE_NET,
                [f"server presents a certificate not valid until "
                 f"{leaf.not_before:%Y-%m-%d}"],
                recommendation="Check issuance and the client clock.",
                target=f"{host}:{port}"))
        elif (leaf.days_to_expiry() or 365) <= 30:
            _add(F.Finding(
                "tls.certvalid", "Presented certificate validity", F.WARNING,
                F.SCOPE_REMOTE_NET,
                [f"certificate expires in {leaf.days_to_expiry()} days"],
                target=f"{host}:{port}"))
        else:
            _add(F.Finding(
                "tls.certvalid", "Presented certificate validity", F.PASS,
                F.SCOPE_REMOTE_NET,
                [f"valid until {leaf.not_after:%Y-%m-%d} "
                 f"({leaf.days_to_expiry()} days remaining)"],
                target=f"{host}:{port}"))

        if server_name:
            ok, names = leaf.matches_hostname(server_name)
            _add(F.Finding(
                "tls.hostname", f"Hostname match for '{server_name}'",
                F.PASS if ok else F.FAIL, F.SCOPE_REMOTE_NET,
                ["certificate covers the name" if ok else
                 f"certificate subjectAltName ({', '.join(names) or 'none'}) does not "
                 f"include '{server_name}'"] +
                ([f"no subjectAltName: CN '{leaf.common_name}' is ignored by modern "
                  "clients"] if not leaf.san_dns and leaf.common_name else []),
                recommendation="" if ok else
                "Connect using a covered name or install a certificate that covers "
                "this hostname.",
                target=f"{host}:{port}"))

        _add(check_presented_chain(facts, host, port))

    _add(check_tls_validation(host, port, server_name, timeout, connect_ip=verified_ip))
    _add(check_tls_rootonly_validation(host, port, server_name, timeout,
                                       connect_ip=verified_ip))
    _add(check_protocol_matrix(host, port, server_name, timeout,
                               connect_ip=verified_ip,
                               negotiated=facts.get("protocol"), facts=facts))
    _add(check_sni_difference(host, port, server_name or host, timeout))
    _add(check_multi_ip(host, port, ips, timeout, sni=server_name, facts=facts))
    _add(check_weak_ciphers(host, port, server_name, timeout))
    https_f, https_facts = check_https(host, port, server_name, timeout)
    facts.update(https_facts)
    facts["server_time_epoch"] = (
        facts["server_time"].timestamp() if facts.get("server_time") else None)
    _add(https_f)
    return out, facts
