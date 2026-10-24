"""Authorized server-side diagnostics over SSH.

Backend: the system OpenSSH client (no third-party dependency; paramiko is
used automatically if it happens to be importable).  Security properties:

* Passwords are NEVER placed on the command line.  For password auth an
  SSH_ASKPASS helper (0700, created in the tool's private state directory)
  replies from an environment variable; the ssh process runs in a new
  session without a controlling terminal, so it cannot prompt interactively.
* Host keys are verified before every connection against the tool's own
  known_hosts file (~/.ssl-doctor/known_hosts).  Unknown or CHANGED keys are
  reported loudly; nothing is ever auto-accepted or auto-changed - storing a
  newly-trusted key requires an explicit user confirmation in the CLI.
* All remote commands are read-only.  No sudo, no service restarts, no
  configuration edits.
"""

from __future__ import annotations

import os
import shlex
import shutil
import stat
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from . import findings as F

STATE_DIR = os.path.expanduser("~/.ssl-doctor")


def _ensure_state_dir() -> str:
    os.makedirs(STATE_DIR, exist_ok=True)
    try:
        os.chmod(STATE_DIR, 0o700)
    except OSError:
        pass
    return STATE_DIR


@dataclass
class SSHConfig:
    host: str
    port: int = 22
    username: str = ""
    auth: str = "key"              # 'key' or 'password'
    key_path: str = ""
    connect_timeout: float = 10.0
    command_timeout: float = 20.0
    # The SSL/TLS endpoint to diagnose when it differs from the SSH endpoint.
    tls_host: str = ""
    tls_port: int = 443


@dataclass
class HostKeyInfo:
    status: str                    # trusted | unknown | changed | unreachable
    fingerprints: List[str]
    detail: str = ""


# ---------------------------------------------------------------- nginx parsing
# Pure-text helpers (locally executed on config gathered from the server).

def _strip_nginx_comments(text: str) -> str:
    out = []
    for line in text.splitlines():
        cut, q = len(line), None
        for i, ch in enumerate(line):
            if q:
                if ch == q:
                    q = None
            elif ch in ("'", '"'):
                q = ch
            elif ch == "#":
                cut = i
                break
        out.append(line[:cut])
    return "\n".join(out)


def _parse_nginx_nodes(text: str):
    """Parse nginx config into a tree of (name, args, children|None)."""
    import re
    tokens = re.findall(r"[{};]|[^\s{};]+", _strip_nginx_comments(text))

    def walk(i: int):
        nodes = []
        while i < len(tokens):
            tok = tokens[i]
            if tok == "}":
                return nodes, i + 1
            if tok in ("{", ";"):
                i += 1
                continue
            name, args, i = tok, [], i + 1
            while i < len(tokens) and tokens[i] not in ("{", ";", "}"):
                args.append(tokens[i])
                i += 1
            if i < len(tokens) and tokens[i] == "{":
                children, i = walk(i + 1)
                nodes.append((name, args, children))
            elif i < len(tokens) and tokens[i] == ";":
                nodes.append((name, args, None))
                i += 1
            else:
                nodes.append((name, args, None))
        return nodes, i

    tree, _ = walk(0)
    return tree


def _collect_server_blocks(nodes) -> List[List]:
    """All 'server { ... }' blocks anywhere in the tree (http or stream)."""
    out = []
    for name, args, children in nodes or []:
        if name == "server" and children is not None:
            out.append(children)
        if children:
            out.extend(_collect_server_blocks(children))
    return out


def _block_directives(block: List) -> Dict[str, List[List[str]]]:
    """Directive name -> list of argument lists (direct children only)."""
    out: Dict[str, List[List[str]]] = {}
    for name, args, children in block:
        if children is None:
            out.setdefault(name, []).append(args)
    return out


def _listen_ports(listens: List[List[str]]) -> List[str]:
    ports = []
    for args in listens:
        if not args:
            continue
        addr = args[0]
        port = addr.rsplit(":", 1)[-1].strip("[]")
        ports.append(port.split("/")[0])
    return ports


def _nginx_name_matches(pattern: str, domain: str) -> Tuple[str, int]:
    """Classify a server_name pattern against `domain`.

    Returns (kind, strength): kind is 'exact', 'leading' (*.x / .x),
    'trailing' (x.*), 'regex' or ''; strength ranks wildcards (longer wins).
    """
    import re
    d = domain.lower().rstrip(".")
    p = pattern.lower().strip('"\'')
    if p in ("_", ""):
        return "", 0                   # catch-all names never match by name
    if p.startswith("~"):
        try:
            return ("regex", 0) if re.search(pattern.lstrip("~").strip('"\''),
                                             domain, re.IGNORECASE) else ("", 0)
        except re.error:
            return "", 0
    if p == d:
        return "exact", len(p)
    if p.startswith("*.") and d.endswith(p[1:]):
        return "leading", len(p)
    if p.startswith(".") and (d == p[1:] or d.endswith(p)):
        return "leading", len(p)
    if p.endswith(".*") and d.startswith(p[:-1]):
        return "trailing", len(p)
    return "", 0


def _match_nginx_server(blocks: List[Dict[str, List[List[str]]]], domain: str,
                        port: int = 443):
    """Server block nginx selects for `domain` on `port`.

    Mirrors nginx: only blocks listening on the port; exact name (first
    wins), longest leading wildcard, longest trailing wildcard, first
    matching regex; else that port's default_server, else its first block.
    Returns (candidate, how, notes) with candidate = (dirs, ports, name).
    """
    on_port = []
    for dirs in blocks:
        ports = _listen_ports(dirs.get("listen", []))
        if str(port) in ports:
            on_port.append((dirs, ports))
    if not on_port:
        return None, f"no server block listens on port {port}", []
    notes: List[str] = []
    best: Dict[str, Tuple] = {}
    for dirs, ports in on_port:
        for n in (n for args in dirs.get("server_name", []) for n in args):
            kind, strength = _nginx_name_matches(n, domain)
            if not kind:
                continue
            if kind == "exact" and "exact" in best:
                notes.append(f"conflicting server name '{n}' on port {port}: nginx "
                             "ignores every block after the first")
                continue
            if kind not in best or (kind in ("leading", "trailing")
                                    and strength > best[kind][3]):
                best[kind] = (dirs, ports, n, strength)
    for kind, how in (("exact", "exact server_name match"),
                      ("leading", "leading-wildcard server_name match"),
                      ("trailing", "trailing-wildcard server_name match"),
                      ("regex", "regex server_name match")):
        if kind in best:
            return best[kind][:3], how, notes
    for dirs, ports in on_port:
        if any("default_server" in a for a in dirs.get("listen", [])
               if a and a[0].rsplit(":", 1)[-1].strip("[]") == str(port)):
            return (dirs, ports, "(default_server)"), "default_server fallback", notes
    dirs, ports = on_port[0]
    return ((dirs, ports, f"(first server block on port {port})"),
            "first-block fallback - nginx uses the first server block for the port "
            "when no server_name matches", notes)


def _http_level_directives(nodes) -> Dict[str, List[List[str]]]:
    """Directives set directly in http{} - inherited by its server blocks."""
    for name, _args, children in nodes or []:
        if name == "http" and children is not None:
            return _block_directives(children)
    return {}


# ---------------------------------------------------------------- host keys

def _scan_host_keys(host: str, port: int, timeout: float) -> Tuple[List[str], str]:
    """Return ('host keytype base64' lines, error)."""
    if not shutil.which("ssh-keyscan"):
        return [], "ssh-keyscan not available"
    try:
        proc = subprocess.run(
            ["ssh-keyscan", "-T", str(int(timeout)), "-p", str(port), host],
            capture_output=True, timeout=timeout + 5, text=True)
    except subprocess.TimeoutExpired:
        return [], f"host key scan timed out after {timeout:.0f}s"
    lines = [ln for ln in proc.stdout.splitlines()
             if ln.strip() and not ln.startswith("#")]
    if not lines:
        err = proc.stderr.strip().splitlines()
        return [], err[-1] if err else "no host keys retrieved (SSH service reachable?)"
    return lines, ""


def host_key_status(host: str, port: int, timeout: float = 8.0) -> HostKeyInfo:
    kh_path = os.path.join(_ensure_state_dir(), "known_hosts")
    if not os.path.exists(kh_path):
        open(kh_path, "a").close()
        os.chmod(kh_path, 0o600)

    scan, err = _scan_host_keys(host, port, timeout)
    if not scan:
        return HostKeyInfo("unreachable", [], err)

    # Fingerprints of the scanned keys (via a temp file, not argv secrets).
    fps: List[str] = []
    tmp = os.path.join(STATE_DIR, ".scan.tmp")
    with open(tmp, "w") as fh:
        fh.write("\n".join(scan) + "\n")
    os.chmod(tmp, 0o600)
    try:
        proc = subprocess.run(["ssh-keygen", "-lf", tmp],
                              capture_output=True, timeout=10, text=True)
        fps = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
    finally:
        os.unlink(tmp)

    scanned_keys: Dict[str, str] = {}
    for ln in scan:
        parts = ln.split()
        if len(parts) >= 3:
            scanned_keys[parts[1]] = parts[2]

    # ssh stores non-default ports in bracket form: [host]:port
    lookup = host if port == 22 else f"[{host}]:{port}"
    proc = subprocess.run(["ssh-keygen", "-F", lookup, "-f", kh_path],
                          capture_output=True, timeout=10, text=True)
    known: Dict[str, str] = {}
    for ln in proc.stdout.splitlines():
        parts = ln.split()
        if len(parts) >= 3 and not ln.startswith("#"):
            known[parts[1]] = parts[2]

    if not known:
        return HostKeyInfo("unknown", fps,
                           "host key not yet trusted for this host")
    mismatches = [t for t, blob in known.items()
                  if t in scanned_keys and scanned_keys[t] != blob]
    if mismatches:
        return HostKeyInfo(
            "changed", fps,
            f"the remote host key CHANGED for type(s) {', '.join(mismatches)} "
            "- possible man-in-the-middle attack or server reinstallation")
    if any(t in known and known[t] == blob for t, blob in scanned_keys.items()):
        return HostKeyInfo("trusted", fps, "")
    return HostKeyInfo("unknown", fps,
                       "host presents key types not yet in the trust store")


def store_host_key(host: str, port: int, timeout: float = 8.0) -> Tuple[bool, str]:
    """Persist the currently presented host key. Requires prior user consent."""
    scan, err = _scan_host_keys(host, port, timeout)
    if not scan:
        return False, err
    kh_path = os.path.join(_ensure_state_dir(), "known_hosts")
    with open(kh_path, "a") as fh:
        fh.write("\n".join(scan) + "\n")
    return True, "host key stored in " + kh_path


# ---------------------------------------------------------------- SSH session

class ServerSession:
    """A thin, stateful wrapper around the system ssh client."""

    def __init__(self, cfg: SSHConfig, password: str = "") -> None:
        self.cfg = cfg
        self._password = password  # kept in memory only; never logged/printed
        self._askpass_path: Optional[str] = None
        self.connected = False
        # populated by cert scans
        self.last_remote_cert_sha256: str = ""
        self.nginx_cert_path: str = ""
        self.nginx_key_path: str = ""

    # -- plumbing ----------------------------------------------------------
    def _base_argv(self) -> List[str]:
        cfg = self.cfg
        kh_path = os.path.join(_ensure_state_dir(), "known_hosts")
        argv = [
            "ssh",
            "-p", str(cfg.port),
            "-o", f"ConnectTimeout={int(cfg.connect_timeout)}",
            "-o", f"UserKnownHostsFile={kh_path}",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "PreferredAuthentications=" + (
                "publickey" if cfg.auth == "key" else "password"),
            "-o", "PubkeyAuthentication=" + ("yes" if cfg.auth == "key" else "no"),
            "-o", "BatchMode=" + ("yes" if cfg.auth == "key" else "no"),
            "-o", "NumberOfPasswordPrompts=1",
        ]
        if cfg.auth == "key" and cfg.key_path:
            argv += ["-i", cfg.key_path]
        argv.append(f"{cfg.username}@{cfg.host}")
        return argv

    def _spawn_env(self) -> Dict[str, str]:
        env = dict(os.environ)
        if self.cfg.auth == "password" and self._password:
            askpass = os.path.join(_ensure_state_dir(), "askpass.sh")
            with open(askpass, "w") as fh:
                fh.write("#!/bin/sh\nprintf '%s\\n' \"$SSL_DOCTOR_PW\"\n")
            os.chmod(askpass, stat.S_IRWXU)
            self._askpass_path = askpass
            env.update({
                "SSH_ASKPASS": askpass,
                "SSH_ASKPASS_REQUIRE": "force",   # OpenSSH >= 8.4
                "DISPLAY": "ssl-doctor:0",        # fallback for older OpenSSH
                "SSL_DOCTOR_PW": self._password,
            })
        env.pop("SSH_AUTH_SOCK", None) if self.cfg.auth == "password" else None
        return env

    def run(self, remote_cmd: str) -> Tuple[int, str, str, str]:
        """Run a read-only remote command. Returns (rc, out, err, fatal_note)."""
        cmd = self._base_argv() + ["--", remote_cmd]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, timeout=self.cfg.command_timeout,
                text=True, env=self._spawn_env(), stdin=subprocess.DEVNULL,
                start_new_session=True)
        except FileNotFoundError:
            return 127, "", "", "ssh client not found on this machine"
        except subprocess.TimeoutExpired:
            return 124, "", "", \
                f"command timed out after {self.cfg.command_timeout:.0f}s"
        return proc.returncode, proc.stdout, proc.stderr, ""

    # -- lifecycle ---------------------------------------------------------
    def connect(self) -> List[F.Finding]:
        out: List[F.Finding] = []
        target = f"{self.cfg.host}:{self.cfg.port}"
        key = host_key_status(self.cfg.host, self.cfg.port,
                              self.cfg.connect_timeout)
        if key.status == "unreachable":
            out.append(F.Finding(
                "ssh.hostkey", "SSH host key verification", F.FAIL, F.SCOPE_SERVER,
                [f"cannot retrieve host key: {key.detail}"],
                recommendation="Check that the SSH service is reachable on this host/port.",
                target=target))
            return out
        if key.status == "changed":
            out.append(F.Finding(
                "ssh.hostkey", "SSH host key verification", F.FAIL, F.SCOPE_SERVER,
                [key.detail, *key.fingerprints,
                 "connection refused: ssl-doctor will never connect over a changed key"],
                recommendation="Verify with the server administrator out-of-band. Only "
                               "then remove the stale entry from "
                               "~/.ssl-doctor/known_hosts and re-run /server connect.",
                target=target))
            return out
        if key.status != "trusted":
            out.append(F.Finding(
                "ssh.hostkey", "SSH host key verification", F.FAIL, F.SCOPE_SERVER,
                [key.detail, *key.fingerprints],
                detail="The CLI must ask the user to explicitly trust this key before "
                       "any connection is attempted.",
                target=target))
            return out
        out.append(F.Finding(
            "ssh.hostkey", "SSH host key verification", F.PASS, F.SCOPE_SERVER,
            ["host key matches the trusted record", *key.fingerprints],
            target=target))

        rc, so, se, fatal = self.run("true")
        if fatal:
            out.append(F.Finding(
                "ssh.auth", "SSH authentication", F.FAIL, F.SCOPE_SERVER, [fatal],
                target=target))
            return out
        if rc != 0:
            msg = (se or so).strip()
            friendly = "authentication failed"
            if "Permission denied" in msg:
                friendly = ("authentication failed: Permission denied (check username/"
                            + ("key" if self.cfg.auth == "key" else "password") + ")")
            elif "Host key verification failed" in msg:
                friendly = "host key verification failed at connect time"
            out.append(F.Finding(
                "ssh.auth", "SSH authentication", F.FAIL, F.SCOPE_SERVER,
                [friendly, msg[:200] if msg and friendly != msg else ""],
                target=target))
            return out
        self.connected = True
        out.append(F.Finding(
            "ssh.auth", "SSH authentication", F.PASS, F.SCOPE_SERVER,
            [f"authenticated as {self.cfg.username}@{self.cfg.host} "
             f"via {'public key' if self.cfg.auth == 'key' else 'password'}",
             "session is read-only; ssl-doctor runs no privileged commands"],
            target=target))
        return out

    def known_secrets(self) -> List[str]:
        """Values reports must scrub (never displayed; used for redaction only)."""
        return [self._password] if self._password else []

    def disconnect(self) -> None:
        self.connected = False
        self._password = ""
        if self._askpass_path and os.path.exists(self._askpass_path):
            try:
                os.unlink(self._askpass_path)
            except OSError:
                pass
            self._askpass_path = None

    # -- diagnostics -------------------------------------------------------
    def _need_conn(self) -> Optional[F.Finding]:
        if not self.connected:
            return F.Finding("ssh.state", "SSH session state", F.NOT_TESTED,
                             F.SCOPE_SERVER, ["not connected; run /server connect first"])
        return None

    def overview(self) -> List[F.Finding]:
        if (err := self._need_conn()):
            return [err]
        rc, so, se, fatal = self.run(
            "uname -a; echo ---; cat /etc/os-release 2>/dev/null | head -n 3; echo ---; id")
        if fatal or rc != 0:
            return [F.Finding("srv.os", "Server OS and identity", F.FAIL, F.SCOPE_SERVER,
                              [fatal or (se.strip() or f"rc={rc}")])]
        return [F.Finding("srv.os", "Server OS and identity", F.PASS, F.SCOPE_SERVER,
                          [ln.rstrip() for ln in so.splitlines() if ln.strip()])]

    def webserver_detection(self) -> List[F.Finding]:
        if (err := self._need_conn()):
            return [err]
        rc, so, se, fatal = self.run(
            "for b in nginx apache2 httpd; do "
            "if command -v $b >/dev/null 2>&1; then "
            "echo \"$b -> $(command -v $b)\"; $($b -v 2>&1 | head -n1); fi; "
            "done; "
            "command -v openssl >/dev/null 2>&1 && echo \"openssl: $(openssl version)\"")
        if fatal:
            return [F.Finding("srv.web", "Web server detection", F.FAIL, F.SCOPE_SERVER,
                              [fatal])]
        lines = [ln.strip() for ln in (so + se).splitlines() if ln.strip()]
        if not lines:
            return [F.Finding(
                "srv.web", "Web server detection", F.WARNING, F.SCOPE_SERVER,
                ["no nginx/apache binaries found in the PATH of this account"],
                recommendation="Confirm which service terminates TLS (load balancer? "
                               "IIS? another host?) and re-target the checks.")]
        return [F.Finding("srv.web", "Web server detection", F.PASS, F.SCOPE_SERVER,
                          lines)]

    def scan_cert(self, cert_path: str, key_path: str = "") -> List[F.Finding]:
        """Inspect a certificate (and optionally key pairing) ON the server."""
        if (err := self._need_conn()):
            return [err]
        out: List[F.Finding] = []
        q = shlex.quote
        rc, so, se, fatal = self.run(
            f"openssl x509 -noout -subject -issuer -dates -serial -fingerprint -sha256 "
            f"-ext subjectAltName -in {q(cert_path)} 2>&1; echo rc=$?")
        if fatal:
            return [F.Finding("srv.cert", f"Server certificate {cert_path}", F.FAIL,
                              F.SCOPE_SERVER, [fatal], target=cert_path)]
        if "rc=0" not in so:
            out.append(F.Finding(
                "srv.cert", f"Server certificate {cert_path}", F.FAIL, F.SCOPE_SERVER,
                [ln for ln in so.splitlines() if ln.strip()][-4:] or ["unreadable"],
                recommendation="Check the path and read permissions for the service "
                               "account.", target=cert_path))
            return out
        fp = ""
        ev = []
        for ln in so.splitlines():
            ln = ln.strip()
            if "fingerprint=" in ln.lower():
                fp = ln.split("=", 1)[1].replace(":", "").lower()
            elif ln and not ln.startswith("rc="):
                ev.append(ln)
        self.last_remote_cert_sha256 = fp
        out.append(F.Finding(
            "srv.cert", f"Server certificate {cert_path}", F.PASS, F.SCOPE_SERVER,
            ev + ([f"sha256: {fp}"] if fp else []), target=cert_path))

        if key_path:
            rc2, so2, se2, _ = self.run(
                f"chash=$(openssl x509 -noout -pubkey -in {q(cert_path)} 2>/dev/null | "
                f"openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1); "
                f"khash=$(openssl pkey -in {q(key_path)} -pubout -outform DER 2>/dev/null | "
                f"sha256sum | cut -d' ' -f1); echo \"cert=$chash\"; echo \"key=$khash\"")
            cert_h = key_h = ""
            for ln in so2.splitlines():
                if ln.startswith("cert="):
                    cert_h = ln[5:].strip()
                elif ln.startswith("key="):
                    key_h = ln[4:].strip()
            if not cert_h or not key_h:
                out.append(F.Finding(
                    "srv.keymatch", "Certificate/key pairing on server", F.WARNING,
                    F.SCOPE_SERVER,
                    ["could not derive public key fingerprints (permissions or "
                     "unsupported key type)"],
                    detail=se2.strip()[:200], target=cert_path))
            elif cert_h == key_h:
                out.append(F.Finding(
                    "srv.keymatch", "Certificate/key pairing on server", F.PASS,
                    F.SCOPE_SERVER,
                    ["configured certificate and private key match",
                     f"public-key sha256: {cert_h}"],
                    target=cert_path))
            else:
                out.append(F.Finding(
                    "srv.keymatch", "Certificate/key pairing on server", F.FAIL,
                    F.SCOPE_SERVER,
                    ["the configured private key does NOT match the configured "
                     "certificate",
                     f"cert pubkey sha256: {cert_h}", f"key pubkey sha256: {key_h}"],
                    recommendation="Point the web server at the correct key/cert pair. "
                                   "This commonly happens after a renewal where only the "
                                   "certificate was replaced.",
                    target=cert_path))
        return out

    def file_permissions(self, paths: List[str]) -> List[F.Finding]:
        if (err := self._need_conn()):
            return [err]
        out: List[F.Finding] = []
        q = shlex.quote
        for p in paths:
            rc, so, se, fatal = self.run(
                f"stat -c '%U %G %a %n' {q(p)} 2>&1 || echo MISSING")
            line = so.strip().splitlines()[0] if so.strip() else ""
            if fatal or not line or "MISSING" in line or rc != 0:
                out.append(F.Finding(
                    "srv.perms", f"Permissions on {os.path.basename(p)}", F.WARNING,
                    F.SCOPE_SERVER, [line or se.strip() or "unreadable / missing"],
                    target=p))
                continue
            user, group, mode, name = (line.split() + ["", "", "", ""])[:4]
            warn = p.lower().endswith((".key",)) and int(mode[-1]) > 0
            out.append(F.Finding(
                "srv.perms", f"Permissions on {os.path.basename(p)}",
                F.WARNING if warn else F.PASS, F.SCOPE_SERVER,
                [f"{name}: owner={user} group={group} mode={mode}"] +
                (["private key is readable by 'other' users"] if warn else []),
                recommendation="Restrict private keys: chmod 600/640 root:<service>."
                if warn else "",
                target=p))
        return out

    def tls_config_scan(self) -> List[F.Finding]:
        """Find configured certs/vhosts. Read-only; degrades without privileges."""
        if (err := self._need_conn()):
            return [err]
        rc, so, se, fatal = self.run(
            "(nginx -T 2>/dev/null | grep -iE 'server_name|listen|ssl_certificate' | head -n 40; "
            "apache2ctl -S 2>/dev/null | head -n 30) ; "
            "grep -rniE 'ssl_certificate|SSLS.*ertificate' /etc/nginx/conf.d /etc/nginx/sites-enabled "
            "/etc/apache2/sites-enabled /etc/httpd/conf.d 2>/dev/null | head -n 30")
        lines = [ln.rstrip()[:200] for ln in so.splitlines() if ln.strip()]
        if fatal:
            return [F.Finding("srv.tlsconf", "TLS virtual host configuration", F.FAIL,
                              F.SCOPE_SERVER, [fatal])]
        if not lines:
            return [F.Finding(
                "srv.tlsconf", "TLS virtual host configuration", F.NOT_TESTED,
                F.SCOPE_SERVER,
                ["no readable TLS configuration found for this account"],
                recommendation="Re-run with an account that can read the web server "
                               "configuration, or supply cert/key paths directly with "
                               "/server cert <cert> [key].")]
        finding = F.Finding("srv.tlsconf", "TLS virtual host configuration", F.PASS,
                            F.SCOPE_SERVER, lines)
        return [finding]

    def log_scan(self) -> List[F.Finding]:
        if (err := self._need_conn()):
            return [err]
        rc, so, se, fatal = self.run(
            "for f in /var/log/nginx/error.log /var/log/apache2/error.log "
            "/var/log/httpd/ssl_error_log; do "
            "if [ -r $f ]; then echo \"== $f\"; "
            "grep -iE 'ssl|certificate' $f 2>/dev/null | tail -n 8; fi; done")
        lines = [ln.rstrip()[:200] for ln in so.splitlines() if ln.strip()]
        if fatal:
            return [F.Finding("srv.logs", "TLS-related service log entries", F.FAIL,
                              F.SCOPE_SERVER, [fatal])]
        if not lines:
            return [F.Finding("srv.logs", "TLS-related service log entries",
                              F.NOT_TESTED, F.SCOPE_SERVER,
                              ["no readable TLS log entries found for this account"],
                              recommendation="Re-run with an account that can read the "
                                             "web server error logs.")]
        return [F.Finding("srv.logs", "TLS-related service log entries", F.WARNING,
                          F.SCOPE_SERVER, lines)]

    def nginx_scan(self, domain: str, port: int = 443) -> List[F.Finding]:
        """Deep read of the nginx SSL configuration, focused on `domain`:`port`.

        Gathers config read-only (``nginx -T`` when permitted, otherwise the
        readable conf files), parses it locally, picks the server block that
        answers for the domain, and verifies the referenced certificate/key.
        """
        if (err := self._need_conn()):
            return [err]
        out: List[F.Finding] = []
        sources = ""
        # 1. try full dump (needs privileged account on most systems)
        rc, so, se, fatal = self.run("nginx -T 2>/dev/null")
        if not fatal and rc == 0 and so.strip():
            sources = so
            used = "nginx -T (full effective configuration)"
        else:
            # 2. readable config files (incl. sites-enabled + conf.d)
            rc2, so2, se2, fatal2 = self.run(
                "for f in /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf "
                "/etc/nginx/sites-enabled/* /usr/local/nginx/conf/nginx.conf "
                "/usr/local/etc/nginx/nginx.conf; do "
                "if [ -r \"$f\" ]; then echo \"--- FILE: $f\"; cat \"$f\"; fi; done")
            if fatal2:
                return [F.Finding("nginx.conf", "Nginx TLS configuration", F.FAIL,
                                  F.SCOPE_SERVER, [fatal2])]
            sources, used = so2, "readable files under /etc/nginx (and local conf dirs)"
        if not sources.strip() or "server" not in sources:
            return [F.Finding(
                "nginx.conf", "Nginx TLS configuration", F.NOT_TESTED, F.SCOPE_SERVER,
                ["no readable nginx configuration for account "
                 f"'{self.cfg.username}' (nginx -T typically needs elevated rights)"],
                recommendation="Re-run with an account allowed to read the nginx "
                               "configuration, or use /server cert <path> [key] with "
                               "the certificate paths directly.")]
        out.append(F.Finding("nginx.conf", "Nginx TLS configuration", F.PASS,
                             F.SCOPE_SERVER, [f"configuration source: {used}"]))

        nodes = _parse_nginx_nodes(sources)
        raw_blocks = _collect_server_blocks(nodes)
        blocks = [_block_directives(b) for b in raw_blocks]
        ssl_blocks = []
        for dirs in blocks:
            listens = dirs.get("listen", [])
            if any("ssl" in a for a in listens) or "443" in _listen_ports(listens):
                ssl_blocks.append(dirs)
        out.append(F.Finding(
            "nginx.blocks", "Nginx server blocks", F.PASS, F.SCOPE_SERVER,
            [f"server blocks total: {len(blocks)}, TLS-enabled: {len(ssl_blocks)}",
             *[f"listen {' / '.join(' '.join(a) for a in d.get('listen', ['-']))} · "
               f"server_name {' '.join(n for a in d.get('server_name', []) for n in a) or '(none)'}"
               for d in ssl_blocks[:8]]]))

        match, how, notes = _match_nginx_server(blocks, domain, port)
        if not match:
            out.append(F.Finding(
                "nginx.domain", f"Nginx vhost for '{domain}'", F.WARNING,
                F.SCOPE_SERVER, [f"no server block found: {how}"],
                recommendation="TLS may be terminated elsewhere (load balancer, "
                               "another process). Verify what answers on 443.",
                target=self.cfg.host))
            return out
        matched_dirs = match[0]
        names = [n for a in matched_dirs.get("server_name", []) for n in a]
        # wildcard/regex matches are normal; only fallbacks and conflicts warn
        status = F.WARNING if "fallback" in how or notes else F.PASS
        ev = [f"selected by: {how}",
              f"matched server_name entry: {match[2]}",
              f"server block names: {', '.join(names) or '(none)'}",
              f"listen: {' / '.join(' '.join(a) for a in matched_dirs.get('listen', ['-']))}",
              *notes]
        if "fallback" in how:
            ev.append("nginx answered with a FALLBACK server block - the domain has "
                      "no dedicated vhost; clients may receive the wrong certificate")
        out.append(F.Finding(
            "nginx.domain", f"Nginx vhost for '{domain}'", status, F.SCOPE_SERVER, ev,
            recommendation="" if status == F.PASS else
            "Create/align a server block whose server_name covers this domain.",
            target=self.cfg.host))

        # Protocols / ciphers of the matched block
        prot_args = matched_dirs.get("ssl_protocols", [])
        if prot_args:
            prots = prot_args[0]
            legacy = [p for p in prots if p.rstrip("v").rstrip(";") in ("TLSv1", "TLSv1.0", "TLSv1.1")
                      or p in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3")]
            st = F.WARNING if legacy else F.PASS
            out.append(F.Finding(
                "nginx.protocols", "Nginx ssl_protocols", st, F.SCOPE_SERVER,
                [f"ssl_protocols {' '.join(prots)}"] +
                ([f"deprecated: {', '.join(legacy)}"] if legacy else
                 ["modern protocol set"]),
                recommendation="Restrict to 'TLSv1.2 TLSv1.3' unless legacy clients "
                               "must be supported." if legacy else "",
                target=self.cfg.host))
        else:
            out.append(F.Finding(
                "nginx.protocols", "Nginx ssl_protocols", F.WARNING, F.SCOPE_SERVER,
                ["no ssl_protocols directive in the matched block - nginx/OS defaults "
                 "apply and vary between builds"],
                detail="Explicitly configuring 'ssl_protocols TLSv1.2 TLSv1.3;' avoids "
                       "surprises after upgrades.",
                target=self.cfg.host))
        ciphers = matched_dirs.get("ssl_ciphers", [])
        out.append(F.Finding(
            "nginx.ciphers", "Nginx ssl_ciphers", F.PASS if ciphers else F.NOT_TESTED,
            F.SCOPE_SERVER,
            [f"ssl_ciphers {' '.join(ciphers[0])}" if ciphers else
             "no explicit ssl_ciphers (openssl defaults; usually fine)"] +
            ([f"ssl_prefer_server_ciphers {' '.join(a[0])}"
              for a in matched_dirs.get("ssl_prefer_server_ciphers", [])]),
            target=self.cfg.host))

        # Certificate / key referenced by the matched vhost (or inherited from http{})
        http_dirs = _http_level_directives(nodes)
        inherited = []
        for name in ("ssl_certificate", "ssl_certificate_key"):
            if not matched_dirs.get(name) and http_dirs.get(name):
                matched_dirs = {**matched_dirs, name: http_dirs[name]}
                inherited.append(name)
        cert_paths = [a[0] for a in matched_dirs.get("ssl_certificate", []) if a]
        key_paths = [a[0] for a in matched_dirs.get("ssl_certificate_key", []) if a]
        if cert_paths:
            out.append(F.Finding(
                "nginx.certref", "ssl_certificate in matched vhost", F.PASS,
                F.SCOPE_SERVER,
                [f"ssl_certificate {cert_paths[0]}"
                 + (" (inherited from http{})" if "ssl_certificate" in inherited else ""),
                 f"ssl_certificate_key {key_paths[0] if key_paths else '(none)'}"
                 + (" (inherited from http{})" if "ssl_certificate_key" in inherited
                    else "")],
                target=self.cfg.host))
        if not cert_paths:
            out.append(F.Finding(
                "nginx.certref", "ssl_certificate in matched vhost", F.WARNING,
                F.SCOPE_SERVER,
                ["the matched server block has no ssl_certificate directive"],
                recommendation="Check include files or a parent http{} certificate, "
                               "or TLS being terminated elsewhere.",
                target=self.cfg.host))
            return out
        cert_path = cert_paths[0]
        key_path = key_paths[0] if key_paths else ""
        out.append(self._chainfile_finding(cert_path))
        # deep cert + key verification (also populates last_remote_cert_sha256)
        out.extend(self.scan_cert(cert_path, key_path))
        self.nginx_cert_path, self.nginx_key_path = cert_path, key_path
        return out

    def _chainfile_finding(self, cert_path: str) -> F.Finding:
        """Linkage of the ssl_certificate file: leaf first, each issued by the next.

        Reads only the public certificate file (never the key).
        """
        from . import certs
        title = "Chain completeness of ssl_certificate file"
        rc, so, se, fatal = self.run(f"cat {shlex.quote(cert_path)} 2>&1")
        blocks = certs.extract_pem_blocks(so.encode()) if not fatal else []
        if not blocks:
            return F.Finding(
                "nginx.chainfile", title, F.FAIL, F.SCOPE_SERVER,
                [f"{cert_path}: no PEM certificates readable",
                 (fatal or so.strip() or se.strip())[:200]],
                recommendation="Check the path and read permissions.", target=cert_path)
        try:
            chain = [certs.decode_pem(b) for b in blocks]
        except Exception as exc:  # noqa: BLE001
            return F.Finding("nginx.chainfile", title, F.FAIL, F.SCOPE_SERVER,
                             [f"{cert_path}: unparseable certificate: {exc}"],
                             target=cert_path)
        a = certs.assess_chain(chain)
        ev = [f"{cert_path}: {len(chain)} certificate(s) in file", *a.evidence]
        if a.status == "complete":
            return F.Finding("nginx.chainfile", title, F.PASS, F.SCOPE_SERVER, ev,
                             target=cert_path)
        rec = ("Order the file as: leaf first, then the intermediate(s) that issued it; "
               "replace any intermediate that did not issue the certificate above it."
               if a.status == "broken" else
               "Append the issuing intermediate certificate(s) after the leaf in the "
               "ssl_certificate file and reload nginx - clients without a cached "
               "intermediate fail otherwise.")
        return F.Finding("nginx.chainfile", title, F.WARNING, F.SCOPE_SERVER, ev,
                         recommendation=rec, target=cert_path)

    def compare_configured_vs_presented(self, presented_sha256: str) -> F.Finding:
        """Compare network-presented cert fingerprint with the configured file."""
        if (err := self._need_conn()):
            return err
        if not self.last_remote_cert_sha256:
            return F.Finding(
                "srv.compare", "Configured vs presented certificate", F.NOT_TESTED,
                F.SCOPE_SERVER,
                ["no server certificate scanned yet - run /server cert <path> first"])
        if not presented_sha256:
            return F.Finding(
                "srv.compare", "Configured vs presented certificate", F.NOT_TESTED,
                F.SCOPE_SERVER,
                ["no network TLS check has run yet - run /tls <host> [port] first"])
        same = self.last_remote_cert_sha256 == presented_sha256.lower().replace(":", "")
        return F.Finding(
            "srv.compare", "Configured vs presented certificate",
            F.PASS if same else F.FAIL, F.SCOPE_SERVER,
            ([f"the certificate file on the server matches what clients receive",
              f"sha256: {self.last_remote_cert_sha256}"]
             if same else
             [f"configured file sha256: {self.last_remote_cert_sha256}",
              f"network-presented sha256: {presented_sha256}",
              "the server is NOT serving the certificate found in its configuration"]),
            recommendation="" if same else
            "Possible causes: the service was not reloaded after a cert change, a "
            "different vhost/SNI answers, or a load balancer terminates TLS elsewhere.",
            target=self.cfg.host)


# ---------------------------------------------------------------- local session

class LocalSession(ServerSession):
    """Runs the same read-only server checks on *this* host, without SSH.

    Used by server-role scan agents installed on the nginx machine. The
    commands are the fixed, read-only ones defined in ServerSession; nothing
    from the network is ever executed.
    """

    def __init__(self, tls_host: str = "", tls_port: int = 443,
                 command_timeout: float = 20.0) -> None:
        import getpass
        super().__init__(SSHConfig(host="localhost", username=getpass.getuser(),
                                   tls_host=tls_host, tls_port=tls_port,
                                   command_timeout=command_timeout))
        self.connected = True

    def run(self, remote_cmd: str) -> Tuple[int, str, str, str]:
        try:
            proc = subprocess.run(["/bin/sh", "-c", remote_cmd], capture_output=True,
                                  text=True, timeout=self.cfg.command_timeout,
                                  stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            return 124, "", "", \
                f"command timed out after {self.cfg.command_timeout:.0f}s"
        return proc.returncode, proc.stdout, proc.stderr, ""
