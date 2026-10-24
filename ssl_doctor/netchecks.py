"""Remote network SSL/TLS diagnostics.

Everything here targets a hostname/IP + port over the network using the
standard library only.  Checks are read-only: they never send credentials
and only make GET/HEAD requests after the TLS layer is established.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

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


def _handshake(host: str, port: int, server_hostname: Optional[str],
               ctx: ssl.SSLContext, timeout: float,
               connect_ip: Optional[str] = None) -> ssl.SSLSocket:
    addr = connect_ip or host
    raw = socket.create_connection((addr, port), timeout=timeout)
    try:
        return ctx.wrap_socket(raw, server_hostname=server_hostname)
    except Exception:
        raw.close()
        raise


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


def check_tls_basic(host: str, port: int, sni: Optional[str],
                    timeout: float) -> Tuple[F.Finding, Dict]:
    """Unauthenticated TLS handshake: protocol, cipher, presented chain."""
    facts: Dict = {}
    ctx = _make_context(verify=False)
    try:
        ssock = _handshake(host, port, sni, ctx, timeout)
    except socket.timeout:
        return F.Finding(
            "tls.handshake", f"TLS handshake with {host}:{port}", F.FAIL,
            F.SCOPE_REMOTE_NET, [f"handshake/connect timed out after {timeout:.0f}s"],
            recommendation="TCP opened previously, but the TLS negotiation stalls. "
                           "An inspection device or wrong protocol on the port is likely.",
            target=f"{host}:{port}"), facts
    except (ssl.SSLError, OSError) as exc:
        return F.Finding(
            "tls.handshake", f"TLS handshake with {host}:{port}", F.FAIL,
            F.SCOPE_REMOTE_NET, [f"handshake failed: {exc}"],
            recommendation="The port may not speak TLS at all, or requires a version/"
                           "cipher this client cannot offer. See the protocol matrix check.",
            target=f"{host}:{port}"), facts

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

    if not facts.get("cert"):
        return F.Finding(
            "tls.handshake", f"TLS handshake with {host}:{port}", F.WARNING,
            F.SCOPE_REMOTE_NET,
            [f"handshake succeeded (protocol={proto}) but the server sent no certificate"],
            target=f"{host}:{port}"), facts

    leaf: certs.CertInfo = facts["cert"]
    if facts["chain"] is None:
        chain_line = "chain presented: could not be read"
    else:
        chain_line = (f"chain presented ({len(facts['chain'])}, via {facts['chain_reader']}): "
                      + " -> ".join((c.common_name or c.subject) for c in facts["chain"]))
    return F.Finding(
        "tls.handshake", f"TLS handshake with {host}:{port}", F.PASS,
        F.SCOPE_REMOTE_NET,
        [f"negotiated protocol: {proto}",
         f"cipher: {facts['cipher']} ({facts['cipher_bits']} bit)",
         f"certificate presented: {leaf.subject}",
         f"SHA-256: {leaf.sha256}",
         chain_line],
        target=f"{host}:{port}"), facts


def check_tls_validation(host: str, port: int, sni: Optional[str],
                         timeout: float) -> F.Finding:
    """Full validation handshake with the system trust store."""
    target = f"{host}:{port}"
    if not sni:
        return F.Finding("tls.verify", "Certificate validation (system trust)",
                         F.NOT_TESTED, F.SCOPE_REMOTE_NET,
                         ["no hostname available for verification"], target=target)
    ctx = _make_context(verify=True)
    try:
        ssock = _handshake(host, port, sni, ctx, timeout)
        ssock.close()
        return F.Finding(
            "tls.verify", "Certificate validation (system trust)", F.PASS,
            F.SCOPE_REMOTE_NET,
            ["the presented certificate chains to a trusted root and matches "
             f"the hostname '{sni}'"], target=target)
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
            "tls.verify", "Certificate validation (system trust)", F.FAIL,
            F.SCOPE_REMOTE_NET,
            [f"validation failed: {plain}", f"openssl verify detail: {msg}"],
            recommendation=advice, target=target)
    except ssl.CertificateError as exc:
        return F.Finding(
            "tls.verify", "Certificate validation (system trust)", F.FAIL,
            F.SCOPE_REMOTE_NET, [f"hostname verification failed: {exc}"],
            recommendation="The certificate does not cover this hostname.",
            target=target)
    except (ssl.SSLError, OSError) as exc:
        return F.Finding(
            "tls.verify", "Certificate validation (system trust)", F.FAIL,
            F.SCOPE_REMOTE_NET, [f"validated handshake failed before verification: {exc}"],
            target=target)


def check_tls_rootonly_validation(host: str, port: int, sni: Optional[str],
                                  timeout: float,
                                  roots: Optional[List[certs.CertInfo]] = None
                                  ) -> F.Finding:
    """Validate with trusted ROOTS only - no cached/bundled intermediates.

    This is what a client that has never seen the intermediate experiences,
    regardless of what this machine has cached.
    """
    title = "Certificate validation (roots only, no cached intermediates)"
    target = f"{host}:{port}"
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
        _handshake(host, port, sni, ctx, timeout).close()
        return F.Finding("tls.verify.rootonly", title, F.PASS, F.SCOPE_REMOTE_NET,
                         [f"chain validates from what the server sends, against "
                          f"{len(roots)} trusted root(s)"], target=target)
    except ssl.SSLCertVerificationError as exc:
        code = getattr(exc, "verify_code", None)
        msg = getattr(exc, "verify_message", None) or str(exc)
        return F.Finding(
            "tls.verify.rootonly", title, F.FAIL, F.SCOPE_REMOTE_NET,
            [f"validation failed: {_VERIFY_CODES.get(code, msg)}",
             f"openssl verify detail: {msg}"],
            recommendation=("Clients without a cached intermediate fail here. Serve the "
                            "full chain (leaf + intermediates) from the server."
                            if code in (20, 21) else ""),
            target=target)
    except (ssl.SSLError, OSError) as exc:
        return F.Finding("tls.verify.rootonly", title, F.FAIL, F.SCOPE_REMOTE_NET,
                         [f"validated handshake failed before verification: {exc}"],
                         target=target)


def check_protocol_matrix(host: str, port: int, sni: Optional[str],
                          timeout: float) -> F.Finding:
    """Probe each TLS protocol version individually."""
    if not hasattr(ssl, "TLSVersion"):
        return F.Finding("tls.protocols", "TLS protocol version support",
                         F.NOT_TESTED, F.SCOPE_REMOTE_NET,
                         ["this Python/OpenSSL build cannot pin protocol versions"],
                         target=f"{host}:{port}")
    rows, supported, refused = [], [], []
    versions = [
        ("TLS 1.0", ssl.TLSVersion.TLSv1),
        ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
        ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
        ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
    ]
    for label, ver in versions:
        ctx = _make_context(verify=False, min_v=ver, max_v=ver,
                            ciphers="ALL:@SECLEVEL=0" if ver in (
                                ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1,
                                ssl.TLSVersion.TLSv1_2) else None)
        try:
            s = _handshake(host, port, sni, ctx, timeout)
            rows.append(f"{label}: accepted ({s.version()})")
            supported.append(label)
            s.close()
        except ssl.SSLError as exc:
            rows.append(f"{label}: refused ({str(exc).splitlines()[0][:80]})")
            refused.append(label)
        except OSError as exc:
            rows.append(f"{label}: network error ({exc})")
            refused.append(label)

    status = F.PASS
    notes = []
    if not supported:
        status = F.FAIL
        notes.append("no TLS version could complete a handshake")
    elif supported == ["TLS 1.3"]:
        notes.append("only TLS 1.3 supported")
    if any(v in supported for v in ("TLS 1.0", "TLS 1.1")):
        if status == F.PASS:
            status = F.WARNING
        notes.append("deprecated TLS 1.0/1.1 are enabled (security/policy risk and "
                     "a sign of legacy configuration)")
    if "TLS 1.2" not in supported and supported:
        status = F.WARNING
        notes.append("TLS 1.2 refused - many clients cannot connect to this server")
    return F.Finding(
        "tls.protocols", "TLS protocol version support", status, F.SCOPE_REMOTE_NET,
        rows, detail="; ".join(notes),
        recommendation=("Enable TLS 1.2 (and 1.3) and disable 1.0/1.1 for a modern, "
                        "interoperable configuration." if status != F.PASS else ""),
        target=f"{host}:{port}")


def check_sni_difference(host: str, port: int, sni: str, timeout: float) -> F.Finding:
    """Compare the certificate with and without SNI."""
    target = f"{host}:{port}"
    if _is_ip(host):
        return F.Finding("tls.sni", "SNI dependence", F.NOT_TESTED,
                         F.SCOPE_REMOTE_NET,
                         ["target is an IP literal; SNI comparison not applicable"],
                         target=target)

    def fp(server_name: Optional[str]) -> str:
        ctx = _make_context(verify=False)
        s = _handshake(host, port, server_name, ctx, timeout)
        der = s.getpeercert(binary_form=True)
        s.close()
        return certs.decode_der(der, enrich=False).sha256 if der else ""

    try:
        with_sni = fp(sni)
    except (ssl.SSLError, OSError) as exc:
        return F.Finding("tls.sni", "SNI dependence", F.FAIL, F.SCOPE_REMOTE_NET,
                         [f"handshake with SNI '{sni}' failed: {exc}"],
                         target=target)
    try:
        without_sni = fp(None)
    except (ssl.SSLError, OSError) as exc:
        return F.Finding(
            "tls.sni", "SNI dependence", F.WARNING, F.SCOPE_REMOTE_NET,
            [f"without SNI the server fails: {exc}",
             f"with SNI '{sni}' it serves cert SHA-256 {with_sni[:16]}..."],
            recommendation="This server requires SNI. Very old clients (or wrong "
                           "default vhost configs) will fail here.",
            target=target)
    if with_sni != without_sni:
        return F.Finding(
            "tls.sni", "SNI dependence", F.WARNING, F.SCOPE_REMOTE_NET,
            ["the server presents DIFFERENT certificates with and without SNI",
             f"with SNI:    {with_sni[:24]}...",
             f"without SNI: {without_sni[:24]}..."],
            recommendation="Clients not sending the correct SNI server name receive a "
                           "different (possibly wrong) certificate. Check virtual-host "
                           "configuration and the default SSL site.",
            target=target)
    return F.Finding(
        "tls.sni", "SNI dependence", F.PASS, F.SCOPE_REMOTE_NET,
        ["same certificate served with and without SNI"], target=target)


def check_multi_ip(host: str, port: int, ips: List[str], timeout: float) -> F.Finding:
    """When DNS returned several IPs, compare the certificate each presents."""
    target = f"{host}:{port}"
    uniq = sorted(set(ips))
    if len(uniq) < 2:
        return F.Finding("tls.multiip", "Multiple endpoint comparison", F.NOT_TESTED,
                         F.SCOPE_REMOTE_NET,
                         ["DNS returned fewer than two addresses"],
                         target=target)
    rows, fps = [], {}
    for ip in uniq[:4]:  # cap probes
        try:
            ctx = _make_context(verify=False)
            s = _handshake(host, port, host if not _is_ip(host) else None, ctx,
                           timeout, connect_ip=ip)
            der = s.getpeercert(binary_form=True)
            s.close()
            fp = certs.decode_der(der, enrich=False).sha256 if der else "(no cert)"
        except (ssl.SSLError, OSError) as exc:
            fp = f"handshake failed: {str(exc).splitlines()[0][:60]}"
        fps[ip] = fp
        rows.append(f"{ip}: {fp[:32] if fp.startswith(('0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f')) else fp}")
    distinct = {v for v in fps.values()}
    if len(distinct) == 1:
        return F.Finding("tls.multiip", "Multiple endpoint comparison", F.PASS,
                         F.SCOPE_REMOTE_NET,
                         ["all endpoints present the same certificate", *rows],
                         target=target)
    return F.Finding(
        "tls.multiip", "Multiple endpoint comparison", F.WARNING, F.SCOPE_REMOTE_NET,
        ["endpoints present DIFFERENT results (load-balanced pools with inconsistent "
         "certificates cause intermittent failures)", *rows],
        recommendation="Align certificate deployment across all nodes/IPs.",
        target=target)


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
                except Exception:
                    pass
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
    }


# ---------------------------------------------------------------- orchestrator

def run_remote_diagnostics(host: str, port: int = 443, sni: Optional[str] = None,
                           timeout: float = 8.0) -> Tuple[List[F.Finding], Dict]:
    """Run the full remote check suite against one endpoint.

    Returns (findings, facts).  `facts` carries structured values the CLI
    session stores for later correlation/clock analysis.
    """
    out: List[F.Finding] = []
    facts: Dict = {"host": host, "port": port}
    server_name = sni or (None if _is_ip(host) else host)
    facts["sni"] = server_name

    dns_f, ips = check_dns(host, timeout)
    out.append(dns_f)
    facts["ips"] = ips
    if not ips and not _is_ip(host):
        out.append(F.Finding(
            "tls.handshake", f"TLS handshake with {host}:{port}", F.NOT_TESTED,
            F.SCOPE_REMOTE_NET, ["skipped: DNS failure"], target=f"{host}:{port}"))
        return out, facts

    tcp_f = check_tcp(host, port, timeout, ip=ips[0] if ips else None)
    out.append(tcp_f)
    if tcp_f.status != F.PASS:
        out.append(F.Finding(
            "tls.handshake", f"TLS handshake with {host}:{port}", F.NOT_TESTED,
            F.SCOPE_REMOTE_NET, ["skipped: TCP failure"], target=f"{host}:{port}"))
        return out, facts

    hs_f, hs_facts = check_tls_basic(host, port, server_name, timeout)
    out.append(hs_f)
    facts.update(hs_facts)
    if hs_f.status == F.FAIL:
        out.append(check_protocol_matrix(host, port, server_name, timeout))
        return out, facts

    # Leaf self-checks over the network-presented cert.
    leaf = facts.get("cert")
    if leaf:
        if leaf.is_expired():
            out.append(F.Finding(
                "tls.certvalid", "Presented certificate validity", F.FAIL,
                F.SCOPE_REMOTE_NET,
                [f"server presents an EXPIRED certificate "
                 f"(notAfter={leaf.not_after:%Y-%m-%d}; {-leaf.days_to_expiry()} days ago)"],
                recommendation="Renew/redeploy the certificate on the server.",
                target=f"{host}:{port}"))
        elif leaf.not_yet_valid():
            out.append(F.Finding(
                "tls.certvalid", "Presented certificate validity", F.FAIL,
                F.SCOPE_REMOTE_NET,
                [f"server presents a certificate not valid until "
                 f"{leaf.not_before:%Y-%m-%d}"],
                recommendation="Check issuance and the client clock.",
                target=f"{host}:{port}"))
        elif (leaf.days_to_expiry() or 365) <= 30:
            out.append(F.Finding(
                "tls.certvalid", "Presented certificate validity", F.WARNING,
                F.SCOPE_REMOTE_NET,
                [f"certificate expires in {leaf.days_to_expiry()} days"],
                target=f"{host}:{port}"))
        else:
            out.append(F.Finding(
                "tls.certvalid", "Presented certificate validity", F.PASS,
                F.SCOPE_REMOTE_NET,
                [f"valid until {leaf.not_after:%Y-%m-%d} "
                 f"({leaf.days_to_expiry()} days remaining)"],
                target=f"{host}:{port}"))

        if server_name:
            ok, names = leaf.matches_hostname(server_name)
            out.append(F.Finding(
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

        out.append(check_presented_chain(facts, host, port))

    out.append(check_tls_validation(host, port, server_name, timeout))
    out.append(check_tls_rootonly_validation(host, port, server_name, timeout))
    out.append(check_protocol_matrix(host, port, server_name, timeout))
    out.append(check_sni_difference(host, port, server_name or host, timeout))
    out.append(check_multi_ip(host, port, ips, timeout))
    out.append(check_weak_ciphers(host, port, server_name, timeout))
    https_f, https_facts = check_https(host, port, server_name, timeout)
    facts.update(https_facts)
    facts["server_time_epoch"] = (
        facts["server_time"].timestamp() if facts.get("server_time") else None)
    out.append(https_f)
    return out, facts
