"""Local system diagnostics for the machine ssl-doctor runs on.

Windows-specific checks (certificate stores, CertEnroll/Schannel events,
winhttp proxy, certutil chain validation) activate automatically when the
tool is executed on Windows and report NOT TESTED elsewhere - nothing here
requires network access.
"""

from __future__ import annotations

import os
import platform
import shutil
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from typing import Callable, List, Optional

from . import findings as F

IS_WINDOWS = sys.platform.startswith("win")


def check_os_and_clock(server_time_epoch: Optional[float] = None) -> List[F.Finding]:
    out: List[F.Finding] = []
    now = datetime.now(timezone.utc)
    try:
        tz = datetime.now().astimezone().tzinfo
    except Exception:
        tz = None
    out.append(F.Finding(
        "local.os", "Operating system and clock", F.PASS, F.SCOPE_LOCAL,
        [f"OS: {platform.platform()}",
         f"Python: {platform.python_version()} / {ssl.OPENSSL_VERSION}",
         f"system time (UTC): {now:%Y-%m-%d %H:%M:%S}",
         f"local timezone: {tz}"]))
    if server_time_epoch:
        skew = int(now.timestamp() - server_time_epoch)
        adjective = "ahead of" if skew >= 0 else "behind"
        if abs(skew) > 300:
            out.append(F.Finding(
                "local.clockskew", "System clock vs server clock", F.FAIL, F.SCOPE_LOCAL,
                [f"this machine is {abs(skew)}s {adjective} the remote server's clock",
                 "a wrong clock makes valid certificates appear expired/not-yet-valid"],
                recommendation="Synchronize the system clock (w32time / NTP) and retry.",
                detail="clock-skew evidence: HTTP Date header of the remote server"))
        elif abs(skew) > 60:
            out.append(F.Finding(
                "local.clockskew", "System clock vs server clock", F.WARNING,
                F.SCOPE_LOCAL,
                [f"clock differs by {abs(skew)}s from the server"],
                recommendation="Consider enabling automatic time synchronization."))
        else:
            out.append(F.Finding(
                "local.clockskew", "System clock vs server clock", F.PASS,
                F.SCOPE_LOCAL, [f"clock skew to server: {skew}s (acceptable)"]))
    return out


def check_proxy_config() -> F.Finding:
    evidence = []
    envs = {k: os.environ.get(k) for k in
            ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy")}
    shown = {k: v for k, v in envs.items() if v}
    if shown:
        evidence += [f"env {k}={v}" for k, v in sorted(shown.items())]
    if IS_WINDOWS:
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
            enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
            server, _ = winreg.QueryValueEx(key, "ProxyServer")
            try:
                auto, _ = winreg.QueryValueEx(key, "AutoConfigURL")
            except OSError:
                auto = None
            winreg.CloseKey(key)
            evidence.append(f"WinINet ProxyEnable={enabled} ProxyServer={server!r}"
                            + (f" AutoConfigURL={auto!r}" if auto else ""))
        except OSError as exc:
            evidence.append(f"could not read WinINet proxy settings: {exc}")
    if not evidence:
        return F.Finding("local.proxy", "Proxy configuration", F.PASS, F.SCOPE_LOCAL,
                         ["no proxy environment variables set; direct connections"])
    return F.Finding(
        "local.proxy", "Proxy configuration", F.WARNING, F.SCOPE_LOCAL, evidence,
        detail="A proxy in the path can terminate TLS itself (corporate MITM). "
               "If clients see an unexpected issuer, compare it with the proxy's CA.",
        recommendation="If the proxy intercepts TLS, its root CA must be installed in "
                       "the client trust stores.")


def check_cert_stores() -> F.Finding:
    if not IS_WINDOWS:
        return F.Finding(
            "local.certstore", "Windows certificate stores", F.NOT_TESTED,
            F.SCOPE_LOCAL,
            ["not running on Windows; Windows trust stores cannot be examined here"])
    try:
        ev = [f"Python/OpenSSL build: {ssl.OPENSSL_VERSION}"]
        if not hasattr(ssl, "enum_certificates"):
            raise AttributeError("enum_certificates unavailable")
        for store in ("ROOT", "CA", "MY"):
            certs = ssl.enum_certificates(store)  # type: ignore[attr-defined]
            ev.append(f"{store}: {len(certs)} certificate(s)")
        return F.Finding("local.certstore", "Windows certificate stores", F.PASS,
                         F.SCOPE_LOCAL, ev)
    except Exception as exc:
        return F.Finding("local.certstore", "Windows certificate stores", F.WARNING,
                         F.SCOPE_LOCAL, [f"could not enumerate stores: {exc}"])


def check_issuer_in_windows_root(issuer_names: List[str],
                                 anchor_unknown: str = "") -> Optional[F.Finding]:
    """Check whether the chain's expected root CA exists in the Windows ROOT store.

    `issuer_names` must be root anchors determined by path building, never a
    guess from an incomplete chain; pass `anchor_unknown` (the reason) instead.
    """
    if not IS_WINDOWS:
        return None
    if anchor_unknown:
        return F.Finding("local.rootca", "Issuing CA present in Windows ROOT store",
                         F.NOT_TESTED, F.SCOPE_LOCAL,
                         [f"{anchor_unknown}; anchor cannot be determined"])
    if not issuer_names:
        return None
    try:
        roots = ssl.enum_certificates("ROOT")  # type: ignore[attr-defined]
        subjects = set()
        from .certs import decode_der
        for entry in roots:  # (cert_bytes, encoding_type, trust)
            der = entry[0]
            try:
                subjects.add(decode_der(der, enrich=False).subject)
            except Exception:  # noqa: BLE001 - skip an unreadable store entry, keep the rest
                continue
        missing = [n for n in issuer_names if n not in subjects]
        if not missing:
            return F.Finding("local.rootca", "Issuing CA present in Windows ROOT store",
                             F.PASS, F.SCOPE_LOCAL,
                             [f"trusted anchors include: {', '.join(issuer_names)}"])
        return F.Finding(
            "local.rootca", "Issuing CA present in Windows ROOT store", F.FAIL,
            F.SCOPE_LOCAL,
            [f"not found in ROOT store: {', '.join(missing)}"],
            recommendation="This client does not trust the issuing CA. Export the root "
                           "certificate from the issuing server and import it into the "
                           "machine's 'Trusted Root Certification Authorities' store "
                           "(or deploy via Group Policy).")
    except Exception as exc:
        return F.Finding("local.rootca", "Issuing CA present in Windows ROOT store",
                         F.NOT_TESTED, F.SCOPE_LOCAL, [str(exc)])


def check_certutil_verify(cert_path: str) -> F.Finding:
    """Windows chain validation via certutil (uses Windows chain engine)."""
    if not IS_WINDOWS:
        return F.Finding(
            "local.certutil", "Chain validation with Windows chain engine (certutil)",
            F.NOT_TESTED, F.SCOPE_LOCAL, ["certutil is only available on Windows"])
    if not shutil.which("certutil"):
        return F.Finding(
            "local.certutil", "Chain validation with Windows chain engine (certutil)",
            F.NOT_TESTED, F.SCOPE_LOCAL, ["certutil not found in PATH"])
    try:
        proc = subprocess.run(["certutil", "-verify", "-urlfetch", cert_path],
                              capture_output=True, timeout=60, text=True)
    except subprocess.TimeoutExpired:
        return F.Finding("local.certutil",
                         "Chain validation with Windows chain engine (certutil)",
                         F.NOT_TESTED, F.SCOPE_LOCAL, ["certutil timed out"])
    tail = [ln.strip() for ln in (proc.stdout + proc.stderr).splitlines() if ln.strip()][-6:]
    ok = proc.returncode == 0 and "Expired" not in proc.stdout \
        and "ERROR" not in proc.stdout.upper()
    return F.Finding(
        "local.certutil", "Chain validation with Windows chain engine (certutil)",
        F.PASS if ok else F.FAIL, F.SCOPE_LOCAL, tail,
        recommendation="" if ok else
        "Windows cannot build/verify the chain. Compare with the OpenSSL/system result: "
        "a different outcome here means the app uses the Windows stack.")


def check_schannel_events(limit: int = 10) -> F.Finding:
    """Relevant Schannel errors from the Windows System event log."""
    if not IS_WINDOWS:
        return F.Finding("local.events", "Schannel event log (Windows)", F.NOT_TESTED,
                         F.SCOPE_LOCAL, ["only available on Windows"])
    if not shutil.which("wevtutil"):
        return F.Finding("local.events", "Schannel event log (Windows)", F.NOT_TESTED,
                         F.SCOPE_LOCAL, ["wevtutil not found"])
    try:
        proc = subprocess.run(
            ["wevtutil", "qe", "System", "/q:*[System[(Provider[@Name='Schannel'])]]",
             "/c:%d" % limit, "/rd:true", "/f:text"],
            capture_output=True, timeout=30, text=True)
    except subprocess.TimeoutExpired:
        return F.Finding("local.events", "Schannel event log (Windows)", F.NOT_TESTED,
                         F.SCOPE_LOCAL, ["wevtutil timed out"])
    text = proc.stdout.strip()
    if not text:
        return F.Finding("local.events", "Schannel event log (Windows)", F.PASS,
                         F.SCOPE_LOCAL, ["no recent Schannel events found"])
    lines = [ln for ln in text.splitlines() if ln.strip()][:limit * 2]
    return F.Finding("local.events", "Schannel event log (Windows)", F.WARNING,
                     F.SCOPE_LOCAL, lines,
                     detail="Schannel errors (e.g. 36887/36888 fatal alerts) corroborate "
                            "TLS failures observed by Windows applications.")


def run_local_for_remote(facts: dict, cert_path: Optional[str] = None,
                         emit: Optional[Callable[[F.Finding], None]] = None) -> List[F.Finding]:
    """Client-machine checks in the context of a remote scan's `facts`.

    The expected root comes from path building over the presented chain
    (netchecks.check_presented_chain); an incomplete chain has no anchor.
    On Windows, without `cert_path`, the presented leaf goes to certutil.
    """
    issuers: List[str] = []
    anchor_unknown = ""
    if facts.get("cert"):
        status = facts.get("chain_status", "unread")
        if status == "complete" and facts.get("anchor"):
            issuers = [facts["anchor"]]
        else:
            anchor_unknown = {"incomplete": "presented chain incomplete",
                              "broken": "presented chain is not correctly linked",
                              }.get(status, "presented chain could not be read")
    tmp_leaf = ""
    if not cert_path and IS_WINDOWS and facts.get("cert"):
        import tempfile
        with tempfile.NamedTemporaryFile("wb", suffix=".cer", delete=False) as fh:
            fh.write(facts["cert"].pem)
            tmp_leaf = cert_path = fh.name
    try:
        return run_local_diagnostics(server_time_epoch=facts.get("server_time_epoch"),
                                     chain_issuer_names=issuers, cert_path=cert_path,
                                     anchor_unknown=anchor_unknown, emit=emit)
    finally:
        if tmp_leaf:
            os.unlink(tmp_leaf)


def run_local_diagnostics(server_time_epoch: Optional[float] = None,
                          chain_issuer_names: Optional[List[str]] = None,
                          cert_path: Optional[str] = None,
                          anchor_unknown: str = "",
                          emit: Optional[Callable[[F.Finding], None]] = None) -> List[F.Finding]:
    out: List[F.Finding] = []
    def _add(f: F.Finding) -> F.Finding:
        list.append(out, f)
        if emit is not None:
            emit(f)
        return f

    for _f in check_os_and_clock(server_time_epoch):
        _add(_f)
    _add(check_proxy_config())
    _add(check_cert_stores())
    root_check = check_issuer_in_windows_root(chain_issuer_names or [], anchor_unknown)
    if root_check:
        _add(root_check)
    if cert_path:
        _add(check_certutil_verify(cert_path))
    _add(check_schannel_events())
    return out
