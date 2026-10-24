"""Interactive command-line interface for SSL Doctor.

A persistent REPL with slash commands.  Colours disable automatically when
stdout is not a terminal or NO_COLOR is set.  A spinner shows progress during
network/SSH work.  Also supports one-shot batch usage:

    python3 ssldoctor.py -c "/tls example.com" -c "/report html out.html"
"""

from __future__ import annotations

import getpass
import os
import shlex
import sys
import threading
import time
from typing import Dict, List, Optional

from . import APP_NAME, __version__
from . import findings as F
from .analyze import diagnose
from . import certs as certmod
from . import local as localmod
from . import netchecks
from . import report as reportmod
from . import server as servermod

_TW_ENABLED = False
_TW_CPS = 40.0
_TW_BATCH = False


def _tw_type(text: str) -> None:
    """Print text, using the typewriter effect when active."""
    global _TW_ENABLED, _TW_CPS, _TW_BATCH
    active = (_TW_ENABLED and not _TW_BATCH
              and bool(getattr(sys.stdout, "isatty", lambda: False)()))
    if not active:
        print(text)
        return
    cps = _TW_CPS if _TW_CPS >= 1 else 1.0
    for ch in str(text):
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(1.0 / cps)
    sys.stdout.write("\n")
    sys.stdout.flush()

_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
if sys.platform.startswith("win"):  # enable ANSI on modern Windows consoles
    try:
        os.system("")
    except Exception:
        pass


class C:
    GREEN = "\033[32m"; RED = "\033[31m"; YELLOW = "\033[33m"
    BLUE = "\033[34m"; CYAN = "\033[36m"; GRAY = "\033[90m"
    BOLD = "\033[1m"; DIM = "\033[2m"; RESET = "\033[0m"


def paint(text: str, *codes: str) -> str:
    if not _USE_COLOR or not codes:
        return text
    return "".join(codes) + text + C.RESET


_STATUS_COLOR = {
    F.PASS: C.GREEN, F.FAIL: C.RED, F.WARNING: C.YELLOW, F.NOT_TESTED: C.GRAY,
}

_SCOPE_LABEL = {
    F.SCOPE_LOCAL: "local",
    F.SCOPE_REMOTE_NET: "network",
    F.SCOPE_SERVER: "server",
}

SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


class Spinner:
    """Minimal progress spinner; falls back to plain text off-tty."""

    def __init__(self, text: str) -> None:
        self.text = text
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def __enter__(self) -> "Spinner":
        if _USE_COLOR:
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
        else:
            print(paint(f"… {self.text}", C.GRAY))
        return self

    def _run(self) -> None:
        i = 0
        while not self._stop.is_set():
            sys.stdout.write(f"\r{paint(SPINNER[i % len(SPINNER)], C.CYAN)} {self.text}")
            sys.stdout.flush()
            i += 1
            time.sleep(0.09)
        sys.stdout.write("\r" + " " * (len(self.text) + 3) + "\r")
        sys.stdout.flush()

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=0.5)


# ------------------------------------------------------------------- output

def print_finding(f: F.Finding, verbose: bool = True) -> None:
    color = _STATUS_COLOR.get(f.status, "")
    scope = paint(_SCOPE_LABEL.get(f.scope, f.scope), C.DIM)
    _tw_type(f"[{paint(f.status, color, C.BOLD):>9}] {f.title}  {paint('·', C.GRAY)} {scope}")
    if not verbose:
        return
    for line in f.evidence:
        _tw_type(f"          {paint('·', C.GRAY)} {line}")
    if f.detail:
        _tw_type(paint(f"          {f.detail}", C.DIM))
    if f.recommendation:
        _tw_type(paint(f"          fix: {f.recommendation}", C.CYAN))


def print_findings(items: List[F.Finding]) -> None:
    for f in items:
        print_finding(f)
    if items:
        c = {s: sum(1 for f in items if f.status == s) for s in _STATUS_COLOR}
        _tw_type(paint(
            f"\n{c[F.PASS]} passed · {c[F.FAIL]} failed · {c[F.WARNING]} warnings · "
            f"{c[F.NOT_TESTED]} not tested", C.GRAY))


def _status_line(status: str) -> str:
    return paint(f"[{status}]", _STATUS_COLOR.get(status, ""), C.BOLD)


# ------------------------------------------------------------------- CLI


class SSLDoctorCLI:
    def __init__(self) -> None:
        self.store = F.FindingStore()
        self.net_timeout = 8.0
        self.cmd_timeout = 20.0
        self.server: Optional[servermod.ServerSession] = None
        self.remote_facts: Dict = {}
        self._diagnosis = None
        self._running = True
        self._BATCH_MODE = False
        # typewriter state
        self._typewriter_enabled = False
        self._typewriter_cps = 40.0
        # sync module globals
        global _TW_ENABLED, _TW_CPS, _TW_BATCH
        _TW_ENABLED = False
        _TW_CPS = 40.0
        _TW_BATCH = False

    @property
    def _STREAM_OUTPUT(self) -> bool:
        is_tty = bool(getattr(sys.stdout, "isatty", lambda: False)())
        return is_tty and not getattr(self, "_BATCH_MODE", False)

    @property
    def _batch_mode(self) -> bool:
        return getattr(self, "_BATCH_MODE", False)

    @property
    def _typewriter_active(self) -> bool:
        if not getattr(self, "_typewriter_enabled", False):
            return False
        if getattr(self, "_BATCH_MODE", False):
            return False
        return bool(getattr(sys.stdout, "isatty", lambda: False)())

    def _write(self, text: str = "") -> None:
        global _TW_ENABLED, _TW_CPS, _TW_BATCH
        _TW_ENABLED = getattr(self, "_typewriter_enabled", False)
        _TW_CPS = getattr(self, "_typewriter_cps", 40.0)
        _TW_BATCH = getattr(self, "_BATCH_MODE", False)
        # route through module-level typewriter printer
        _tw_type(text)

    def out(self, text: str = "") -> None:
        self._write(text)

    def error(self, text: str) -> None:
        self._write(paint(f"error: {text}", C.RED))

    def note(self, text: str) -> None:
        self._write(paint(text, C.GRAY))

    def prompt(self, label: str, default: str = "") -> str:
        suffix = paint(f" [{default}]", C.GRAY) if default else ""
        try:
            val = input(f"{paint(label, C.CYAN)}{suffix}: ").strip()
        except EOFError:
            return default
        return val or default

    def _meta(self) -> Dict:
        tgt = self.remote_facts
        target = ""
        if tgt.get("host"):
            target = f"{tgt['host']}:{tgt.get('port', 443)}"
        return {"target": target,
                "network_timeout": self.net_timeout,
                "command_timeout": self.cmd_timeout,
                "ssh_connected": bool(self.server and self.server.connected)}

    def _emit_finding(self, f: F.Finding) -> None:
        print_finding(f)
        try:
            sys.stdout.flush()
        except Exception:  # noqa: BLE001
            pass

    def _print_result(self, result) -> None:
        if result is None:
            return
        if isinstance(result, tuple):
            findings = result[0]
            if isinstance(findings, list):
                print_findings(findings)
            elif findings is not None:
                print_finding(findings)
            return
        if isinstance(result, list):
            print_findings(result)
        else:
            print_finding(result)

    def _run_phase(self, text: str, fn, *args, **kwargs):
        """Run a check phase, streaming findings on tty/interactive mode."""
        if self._STREAM_OUTPUT:
            print(paint(f"… {text}", C.GRAY))
            try:
                sys.stdout.flush()
            except Exception:  # noqa: BLE001
                pass
            emit = self._emit_finding
            # Try passing emit through; fall back to manual emission.
            try:
                result = fn(*args, emit=emit, **kwargs)
            except TypeError:
                result = fn(*args, **kwargs)
                self._emit_result(result)
            return result
        with Spinner(text):
            result = fn(*args, **kwargs)
        self._print_result(result)
        return result

    def _emit_result(self, result) -> None:
        if result is None:
            return
        if isinstance(result, tuple):
            result = result[0]
        if isinstance(result, list):
            for f in result:
                self._emit_finding(f)
        else:
            self._emit_finding(result)

    # ---------------- command dispatch ----------------
    def execute(self, line: str) -> bool:
        """Execute one command line. Returns False when the session should end."""
        line = line.strip()
        if not line:
            return True
        if not line.startswith("/"):
            if line.lower() in ("help", "?"):
                line = "/help"
            else:
                self.error("commands start with '/'. Try /help")
                return True
        try:
            args = shlex.split(line[1:])
        except ValueError as exc:
            self.error(str(exc))
            return True
        if not args:
            return True
        cmd, rest = args[0].lower(), args[1:]
        handler = getattr(self, f"cmd_{cmd}", None)
        if handler is None:
            self.error(f"unknown command /{cmd}. Try /help")
            return True
        try:
            handler(rest)
        except KeyboardInterrupt:
            self.note("\ninterrupted")
        except Exception as exc:  # never crash the session on a check bug
            self.error(f"{type(exc).__name__}: {exc}")
        return self._running

    # ---------------- individual commands ----------------
    def cmd_help(self, args: List[str]) -> None:
        rows = [
            ("/scan [target]", "full workflow: identify domain -> client-side -> (SSH) server-side -> diagnosis"),
            ("/scan [target] --client-only", "only client-side: network path + this machine"),
            ("/scan [target] --server-only", "only server-side: SSH + nginx SSL config + presented-cert comparison"),
            ("/scan [target] --with-server", "combined run without the SSH yes/no prompt"),
            ("/tls <host> [port] [--sni name]", "remote TLS/HTTPS diagnostics (default port 443; URLs ok)"),
            ("/local", "diagnostics for this machine (Windows-aware)"),
            ("/cert inspect <file> [hostname]", "parse a PEM/DER certificate or chain file"),
            ("/cert match <cert> <key>", "verify a private key belongs to a certificate"),
            ("/server connect", "interactive SSH setup for authorized server-side checks"),
            ("/server status", "show SSH session state"),
            ("/server overview", "remote OS / web-server identification"),
            ("/server nginx [domain[:port]]", "examine nginx SSL config: vhost match, protocols, ciphers, cert/key"),
            ("/server cert <file> [key]", "inspect cert (and key pairing) on the server"),
            ("/server config", "scan readable web-server TLS/vhost configuration"),
            ("/server logs", "recent TLS-related service log entries (if readable)"),
            ("/server compare", "configured certificate vs certificate served on the network"),
            ("/server disconnect", "close the SSH session"),
            ("/diagnose", "correlate all findings into prioritized root causes"),
            ("/findings", "list everything recorded this session"),
            ("/report [html|json|both] [path]", "write a report (default: html)"),
            ("/typewriter [on|off|speed <n>]", "toggle typewriter output effect (tty only)"),
            ("/clear", "discard recorded findings"),
            ("/version", "show version"),
            ("/exit", "leave ssl-doctor"),
        ]
        self.out(paint(f"{APP_NAME} commands:", C.BOLD))
        for c, d in rows:
            self.out(f"  {paint(c, C.CYAN):<44} {d}")

    def cmd_version(self, args: List[str]) -> None:
        self.out(f"{APP_NAME} v{__version__}")

    def cmd_exit(self, args: List[str]) -> None:
        if self.server:
            self.server.disconnect()
        self._running = False

    cmd_quit = cmd_exit           # type: ignore[assignment]

    def cmd_clear(self, args: List[str]) -> None:
        self.store.clear()
        self._diagnosis = None
        self.note("findings cleared")

    def cmd_timeout(self, args: List[str]) -> None:
        if not args:
            self.out(f"network timeout: {self.net_timeout}s · remote command timeout: "
                     f"{self.cmd_timeout}s  (usage: /timeout <net_s> [cmd_s])")
            return
        try:
            self.net_timeout = float(args[0])
            if len(args) > 1:
                self.cmd_timeout = float(args[1])
            self.out(f"timeouts set: network {self.net_timeout}s, "
                     f"remote commands {self.cmd_timeout}s")
        except ValueError:
            self.error("usage: /timeout <net_s> [cmd_s]")

    def cmd_typewriter(self, args: List[str]) -> None:
        sub = args[0].lower() if args else "status"
        if sub in ("on", "off", "status"):
            if sub == "on":
                if not self._typewriter_active and not (sys.stdout.isatty() if hasattr(sys.stdout, "isatty") else False):
                    self.error("typewriter mode requires an interactive terminal")
                    return
                self._typewriter_enabled = (sub == "on")
            elif sub == "off":
                self._typewriter_enabled = False
            # status
            self.out(f"typewriter: {'on' if self._typewriter_enabled else 'off'} "
                     f"· speed {self._typewriter_cps:g} cps "
                     f"· active {self._typewriter_active}")
            return
        if sub == "speed":
            if len(args) < 2:
                self.error("usage: /typewriter speed <chars-per-second>")
                return
            try:
                cps = float(args[1])
            except ValueError:
                self.error("speed must be a number")
                return
            if cps < 1:
                self.error("speed must be >= 1")
                return
            self._typewriter_cps = cps
            self.out(f"typewriter speed set to {cps:g} cps")
            return
        self.error("usage: /typewriter [on|off|speed <cps>]")
        scope = args[0] if args else ""
        items = self.store.by_scope(scope) if scope else self.store.all()
        if not items:
            self.note("no findings recorded yet - run /scan or /tls first")
            return
        print_findings(items)

    # ---------------- /cert ----------------
    def cmd_cert(self, args: List[str]) -> None:
        if not args or args[0] == "inspect":
            rest = args[1:] if args and args[0] == "inspect" else args
            if not rest:
                self.error("usage: /cert inspect <file> [hostname]")
                return
            path = os.path.expanduser(rest[0])
            hostname = rest[1] if len(rest) > 1 else ""
            items = self._run_phase(f"inspecting {os.path.basename(path)}",
                                    certmod.inspect_cert_file, path, hostname)
            self.store.extend(items)
            return
        if args[0] == "match":
            if len(args) < 3:
                self.error("usage: /cert match <cert-file> <key-file>")
                return
            cpath, kpath = (os.path.expanduser(a) for a in args[1:3])
            self.note("key material is never displayed; only digests are compared")
            items = self._run_phase("comparing public keys",
                                    certmod.match_cert_key, cpath, kpath)
            self.store.extend(items)
            return
        self.error("usage: /cert inspect <file> [hostname] | /cert match <cert> <key>")

    # ---------------- /tls ----------------
    def _sni_arg(self, args: List[str]) -> Optional[str]:
        if "--sni" in args:
            i = args.index("--sni")
            if i + 1 < len(args):
                return args[i + 1]
        return None

    def _gather_remote(self, host: str, port: int, sni: Optional[str],
                      profile: bool = True) -> List[F.Finding]:
        text = f"running remote TLS diagnostics against {host}:{port}"
        result = self._run_phase(text, netchecks.run_remote_diagnostics,
                                 host, port, sni=sni, timeout=self.net_timeout)
        items, facts = result
        if profile and facts.get("cert"):
            prof = netchecks.domain_profile(
                host, port, facts.get("ips", []), facts)
            items.insert(0, prof)
            if self._STREAM_OUTPUT:
                self._emit_finding(prof)
            else:
                print_finding(prof)
        self.store.extend(items)
        self.remote_facts = facts
        self._diagnosis = None
        return items

    def cmd_tls(self, args: List[str]) -> None:
        positional = [a for a in args if not a.startswith("--")]
        if not positional:
            self.error("usage: /tls <host|host:port|https://url> [--sni name]")
            return
        target = positional[0]
        if len(positional) > 1 and positional[1].isdigit():
            target = f"{positional[0]}:{positional[1]}"
        host, port, _scheme, err = netchecks.parse_target(target)
        if err:
            self.error(err)
            return
        self._gather_remote(host, port, self._sni_arg(args))
        self.note(paint("next: /diagnose or /report html", C.GRAY))

    cmd_remote = cmd_tls           # type: ignore[assignment]

    # ---------------- /local ----------------
    def cmd_local(self, args: List[str]) -> None:
        cert_path = args[0] if args else None
        items = self._run_phase("collecting local system information",
                                localmod.run_local_for_remote, self.remote_facts, cert_path)
        self.store.extend(items)

    # ---------------- /scan (guided) ----------------
    def cmd_scan(self, args: List[str]) -> None:
        pos = [a for a in args if not a.startswith("--")]
        target = pos[0] if pos else self.prompt("target hostname or host:port")
        host, port, _scheme, err = netchecks.parse_target(target)
        if err:
            self.error(err)
            return
        sni = self._sni_arg(args)
        mode = "combined"
        with_server = "--with-server" in args
        if "--server-only" in args:
            mode = "server"
        elif "--client-only" in args:
            mode = "client"

        if mode == "combined" and not with_server:
            ans = self.prompt("run authorized server-side checks too (SSH)? (yes/no)",
                              "no")
            with_server = ans.lower() in ("yes", "y")
        steps_total = {"client": 3, "server": 2}.get(
            mode, 4 if with_server else 3)
        step = 0

        def head(title: str) -> None:
            nonlocal step
            step += 1
            self.out(paint(f"\n== Step {step}/{steps_total}: {title}", C.BOLD))

        if mode in ("client", "combined"):
            head(f"domain identification + network checks for {host}:{port}")
            self._gather_remote(host, port, sni)
            head("client machine checks (this system)")
            self.cmd_local([])

        if mode == "server":
            head(f"server-side checks for {host}:{port} (SSH)")
            self._scan_server_side(host, port, sni)
        elif mode == "combined" and with_server:
            head("server-side checks (nginx SSL config, via SSH)")
            self._scan_server_side(host, port, sni)
        elif mode == "combined":
            self.note("server-side checks skipped; run later with /server connect or "
                      "/scan <target> --server-only")

        head("diagnosis")
        self.cmd_diagnose([])

    def _scan_server_side(self, host: str, port: int, sni: Optional[str]) -> None:
        """Authorized server-side sweep: nginx SSL config + presented-cert compare."""
        if not self.remote_facts.get("cert"):
            # presented cert is needed to compare 'configured vs served'
            with Spinner(f"measuring the public endpoint {host}:{port}"):
                dns_f, ips = netchecks.check_dns(host, self.net_timeout)
                hs_f, hs_facts = netchecks.check_tls_basic(
                    host, port, sni or (None if netchecks._is_ip(host) else host),
                    self.net_timeout)
            extras = [dns_f, hs_f,
                      netchecks.domain_profile(host, port, ips,
                                               {**hs_facts, "ips": ips})]
            self.store.extend(extras)
            self.remote_facts.update(hs_facts)
            print_findings(extras)
        if not (self.server and self.server.connected):
            self._server_connect()
        if not (self.server and self.server.connected):
            return
        srv = self.server
        domain = srv.cfg.tls_host or host
        if self._STREAM_OUTPUT:
            print(paint("… reading server identity (read-only)", C.GRAY))
            sys.stdout.flush()
            items = srv.overview(emit=self._emit_finding) + srv.webserver_detection(emit=self._emit_finding)
        else:
            with Spinner("reading server identity (read-only)"):
                items = srv.overview() + srv.webserver_detection()
            print_findings(items)
        self.store.extend(items)

        if self._STREAM_OUTPUT:
            print(paint(f"… examining nginx SSL configuration for '{domain}:{port}'", C.GRAY))
            sys.stdout.flush()
            items = srv.nginx_scan(domain, port, emit=self._emit_finding)
        else:
            with Spinner(f"examining nginx SSL configuration for '{domain}:{port}'"):
                items = srv.nginx_scan(domain, port)
            print_findings(items)
        self.store.extend(items)

        presented = ""
        cert = self.remote_facts.get("cert")
        if cert:
            presented = cert.sha256
        cmp_f = srv.compare_configured_vs_presented(presented, emit=self._emit_finding if self._STREAM_OUTPUT else None)
        if not self._STREAM_OUTPUT:
            # buffered: emit happens inside compare only if emit passed; we passed None, so print here
            print_finding(cmp_f)
        items = [cmp_f]

        if self._STREAM_OUTPUT:
            print(paint("… scanning TLS service logs (read-only)", C.GRAY))
            sys.stdout.flush()
            log_items = srv.log_scan(emit=self._emit_finding)
        else:
            with Spinner("scanning TLS service logs (read-only)"):
                log_items = srv.log_scan()
            print_findings(log_items)
        items = items + log_items
        self.store.extend(items)

    # ---------------- /server ----------------
    def cmd_server(self, args: List[str]) -> None:
        sub = args[0].lower() if args else "status"
        if sub == "connect":
            self._server_connect()
            return
        if sub == "disconnect":
            if self.server:
                self.server.disconnect()
                self.server = None
                self.out("SSH session closed")
            else:
                self.note("not connected")
            return
        if sub == "status":
            if self.server and self.server.connected:
                c = self.server.cfg
                self.out(f"connected: {c.username}@{c.host}:{c.port} "
                         f"(TLS target {c.tls_host or c.host}:{c.tls_port})")
            else:
                self.note("no active SSH session - /server connect")
            return

        if not (self.server and self.server.connected):
            self.error("not connected - run /server connect first")
            return
        srv = self.server
        if sub == "overview":
            if self._STREAM_OUTPUT:
                print(paint("… querying server", C.GRAY))
                sys.stdout.flush()
                items = srv.overview(emit=self._emit_finding) + srv.webserver_detection(emit=self._emit_finding)
            else:
                with Spinner("querying server"):
                    items = srv.overview() + srv.webserver_detection()
        elif sub == "nginx":
            domain, port = srv.cfg.tls_host, srv.cfg.tls_port
            if len(args) > 1:
                domain, port, _scheme, err = netchecks.parse_target(args[1])
                if err:
                    self.error(err)
                    return
                if ":" not in args[1].split("//")[-1]:
                    port = srv.cfg.tls_port      # bare domain: session's TLS port
            if self._STREAM_OUTPUT:
                print(paint(f"… examining nginx SSL configuration for '{domain}:{port}'", C.GRAY))
                sys.stdout.flush()
                items = srv.nginx_scan(domain, port, emit=self._emit_finding)
            else:
                with Spinner(f"examining nginx SSL configuration for '{domain}:{port}'"):
                    items = srv.nginx_scan(domain, port)
        elif sub == "cert":
            if len(args) < 2:
                self.error("usage: /server cert <remote-cert-path> [remote-key-path]")
                return
            cert_path = args[1]
            key_path = args[2] if len(args) > 2 else ""
            self.note("key material stays on the server; only digests are compared")
            if self._STREAM_OUTPUT:
                print(paint(f"… inspecting {cert_path} on the server", C.GRAY))
                sys.stdout.flush()
                items = srv.scan_cert(cert_path, key_path, emit=self._emit_finding)
                paths = [cert_path] + ([key_path] if key_path else [])
                perm_items = srv.file_permissions(paths)
                for f in perm_items:
                    self._emit_finding(f)
                items = items + perm_items
            else:
                with Spinner(f"inspecting {cert_path} on the server"):
                    items = srv.scan_cert(cert_path, key_path)
                    paths = [cert_path] + ([key_path] if key_path else [])
                    items += srv.file_permissions(paths)
        elif sub == "config":
            if self._STREAM_OUTPUT:
                print(paint("… reading TLS/vhost configuration (read-only)", C.GRAY))
                sys.stdout.flush()
                items = srv.tls_config_scan(emit=self._emit_finding)
            else:
                with Spinner("reading TLS/vhost configuration (read-only)"):
                    items = srv.tls_config_scan()
        elif sub == "logs":
            if self._STREAM_OUTPUT:
                print(paint("… scanning service logs (read-only)", C.GRAY))
                sys.stdout.flush()
                items = srv.log_scan(emit=self._emit_finding)
            else:
                with Spinner("scanning service logs (read-only)"):
                    items = srv.log_scan()
        elif sub == "compare":
            presented = ""
            cert = self.remote_facts.get("cert")
            if cert:
                presented = cert.sha256
            cmp_f = srv.compare_configured_vs_presented(
                presented, emit=self._emit_finding if self._STREAM_OUTPUT else None)
            if not self._STREAM_OUTPUT:
                print_finding(cmp_f)
            items = [cmp_f]
        else:
            self.error("usage: /server connect|status|overview|nginx [domain]|cert|"
                       "config|logs|compare|disconnect")
            return
        self.store.extend(items)
        if not self._STREAM_OUTPUT:
            print_findings(items)
        self.out(paint("SSH connection setup (credentials are never displayed "
                       "or written to disk):", C.BOLD))
        host = self.prompt("SSH hostname or IP")
        if not host:
            self.error("hostname required")
            return
        ssh_port_s = self.prompt("SSH port", "22")
        if not ssh_port_s.isdigit():
            self.error("invalid port")
            return
        user = self.prompt("SSH username", getpass.getuser())
        auth = ""
        while auth not in ("1", "2"):
            auth = self.prompt("auth method: 1=password  2=private key", "2")
        password, key_path, method = "", "", "key"
        if auth == "1":
            method = "password"
            try:
                password = getpass.getpass("SSH password (hidden): ")
            except EOFError:
                self.error("cannot read password in this terminal")
                return
            if not password:
                self.error("empty password")
                return
        else:
            key_path = os.path.expanduser(self.prompt("private key path",
                                                      "~/.ssh/id_rsa"))
            if not os.path.exists(key_path):
                self.error(f"key not found: {key_path}")
                return
        tls_host = self.prompt("TLS target hostname (blank = SSH host)", "")
        tls_port_s = self.prompt("TLS target port", "443")
        tls_port = int(tls_port_s) if tls_port_s.isdigit() else 443

        timeout = self.net_timeout
        with Spinner(f"verifying host key of {host}"):
            key = servermod.host_key_status(host, int(ssh_port_s), timeout)
        if key.status == "unreachable":
            self.error(f"cannot reach the SSH service / host key: {key.detail}")
            self.store.add(F.Finding(
                "ssh.hostkey", "SSH host key verification", F.FAIL, F.SCOPE_SERVER,
                [key.detail], target=f"{host}:{ssh_port_s}"))
            return
        if key.status == "changed":
            self.error("HOST KEY CHANGED - possible MITM. Refusing to connect.")
            for fp in key.fingerprints:
                self.out("  " + paint(fp, C.RED))
            self.note("Verify with the server admin out-of-band, then remove the stale "
                      "entry from ~/.ssl-doctor/known_hosts before retrying.")
            self.store.add(F.Finding(
                "ssh.hostkey", "SSH host key verification", F.FAIL, F.SCOPE_SERVER,
                [key.detail, *key.fingerprints], target=f"{host}:{ssh_port_s}"))
            return
        if key.status == "unknown":
            self.out(paint("The host key is not in the ssl-doctor trust store:", C.YELLOW))
            for fp in key.fingerprints:
                self.out("  " + fp)
            ans = self.prompt("Trust this key and save it for future sessions? (yes/no)",
                              "no").lower()
            if ans not in ("yes", "y"):
                self.note("connection aborted before authentication")
                return
            ok, msg = servermod.store_host_key(host, int(ssh_port_s), timeout)
            if not ok:
                self.error(msg)
                return
            self.note(msg)

        cfg = servermod.SSHConfig(
            host=host, port=int(ssh_port_s), username=user, auth=method,
            key_path=key_path, connect_timeout=timeout,
            command_timeout=self.cmd_timeout,
            tls_host=tls_host or host, tls_port=tls_port)
        if self.server:
            self.server.disconnect()
        self.server = servermod.ServerSession(cfg, password=password)
        with Spinner(f"connecting to {user}@{host}"):
            items = self.server.connect()
        self.store.extend(items)
        print_findings(items)
        if self.server.connected:
            if tls_host and tls_host != host:
                self.note(f"TLS target recorded as {tls_host}:{tls_port} (differs from "
                          f"SSH endpoint)")
            self.note(paint("next: /server overview, /server cert <path> [key], "
                            "/server compare", C.GRAY))

    # ---------------- /diagnose ----------------
    def cmd_diagnose(self, args: List[str]) -> None:
        items = self.store.all()
        if not items:
            self.note("nothing to diagnose yet - run /scan, /tls, /local or /server "
                      "checks first")
            return
        ctx = {"cert": self.remote_facts.get("cert")}
        self._diagnosis = diagnose(items, ctx)
        self.out(paint("Diagnosis", C.BOLD,
                       C.GREEN if self._diagnosis.overall == "PASS" else
                       C.RED if self._diagnosis.overall == "FAIL" else C.YELLOW))
        if not self._diagnosis.causes:
            self.out("  no confirmed or probable root causes identified")
        for i, c in enumerate(self._diagnosis.causes, 1):
            mark = {"confirmed": C.RED, "probable": C.YELLOW,
                    "possible": C.GRAY}[c.certainty]
            self.out(f"  {i}. [{paint(c.certainty.upper(), mark)} · {c.origin}] "
                     f"{c.summary}")
            for e in c.evidence[:4]:
                self.out(paint(f"       evidence: {e}", C.DIM))
            if c.recommendation:
                self.out(paint(f"       fix: {c.recommendation}", C.CYAN))
        for n in self._diagnosis.notes:
            self.out(paint(f"  note: {n}", C.GRAY))
        self.note("\ngenerate a report with /report html")

    # ---------------- /report ----------------
    def cmd_report(self, args: List[str]) -> None:
        fmt = "html"
        path = ""
        for a in args:
            if a in ("html", "json", "both"):
                fmt = a
            else:
                path = a
        items = self.store.all()
        if not items:
            self.note("no findings yet - run some checks first")
            return
        diag = self._diagnosis
        if diag is None:
            diag = diagnose(items, {"cert": self.remote_facts.get("cert")})
            self._diagnosis = diag
        meta = self._meta()
        secrets = self.server.known_secrets() if self.server else []
        facts = netchecks.export_facts(self.remote_facts) \
            if self.remote_facts.get("cert") else None
        ts = time.strftime("%Y%m%d-%H%M%S")
        written = []
        if fmt in ("json", "both"):
            p = path if path.lower().endswith(".json") else \
                (path + ".json" if path else f"ssl-doctor-report-{ts}.json")
            reportmod.write_json(p, items, diag, meta, secrets, facts)
            written.append(p)
        if fmt in ("html", "both"):
            p = path if (path and path.lower().endswith(".html")) else \
                (path + ".html" if path else f"ssl-doctor-report-{ts}.html")
            reportmod.write_html(p, items, diag, meta, secrets, facts)
            written.append(p)
        for p in written:
            self.out(f"report written: {paint(os.path.abspath(p), C.CYAN)}")

    # ---------------- REPL ----------------
    def banner(self) -> None:
        self.out(paint(f"{APP_NAME} v{__version__}", C.BOLD, C.CYAN))
        self.out("Offline SSL/TLS diagnostic tool. Type /help for commands.")
        self.note("all checks are read-only; credentials are never logged\n")

    def repl(self) -> int:
        self.banner()
        while self._running:
            try:
                line = input(paint("ssl-doctor> ", C.GREEN, C.BOLD))
            except (EOFError, KeyboardInterrupt):
                self.out("")
                break
            if line.strip().lower() in ("/exit", "/quit", "exit", "quit"):
                self.cmd_exit([])
                break
            self.execute(line)
        if self.server:
            self.server.disconnect()
        self.note("bye")
        return 0


# ------------------------------------------------------------------- main

def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["agent"]:
        from . import agent
        try:
            return agent.main(argv[1:])
        except agent.AgentError as exc:
            print(paint(f"error: {exc}", C.RED))
            return 1
    cli = SSLDoctorCLI()

    batch: List[str] = []
    i = 0
    while i < len(argv):
        if argv[i] == "-c" and i + 1 < len(argv):
            batch.append(argv[i + 1])
            i += 2
        elif argv[i] == "--timeout" and i + 1 < len(argv):
            try:
                cli.net_timeout = float(argv[i + 1])
            except ValueError:
                pass
            i += 2
        elif argv[i] == "--typewriter":
            cli._typewriter_enabled = True
            i += 1
        elif argv[i] == "--typewriter-speed" and i + 1 < len(argv):
            try:
                cli._typewriter_cps = float(argv[i + 1])
            except ValueError:
                pass
            i += 2
        elif argv[i].startswith("/"):
            batch.append(" ".join(argv[i:]))
            break
        else:
            i += 1

    if batch:
        cli._BATCH_MODE = True
        cli.banner()
        for line in batch:
            print(paint(f"ssl-doctor> {line}", C.GREEN, C.BOLD))
            if not cli.execute(line):
                break
        diag = cli._diagnosis
        if diag is None and len(cli.store):
            try:
                diag = diagnose(cli.store.all(), {})
            except Exception:
                diag = None
        return 1 if (diag and diag.overall == "FAIL") else 0
    return cli.repl()


if __name__ == "__main__":
    raise SystemExit(main())
