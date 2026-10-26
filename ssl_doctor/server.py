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

import base64
import binascii
import os
import posixpath
import re
import shlex
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from . import certpolicy, certs, chainval, services
from . import findings as F
from . import nginx_discovery

STATE_DIR = os.path.expanduser("~/.ssl-doctor")
# Set in the environment of ssh when a frozen Windows build is its own
# SSH_ASKPASS helper: the executable then prints the password and exits.
ASKPASS_MODE_ENV = "SSL_DOCTOR_ASKPASS"


def password_problem(password: str) -> Optional[str]:
    """Why `password` cannot be used, or None.

    Empty and whitespace-only values are refused: an empty answer is almost
    always a slip, and ssh would send it as a real login attempt. Line breaks
    and NUL cannot pass through the one-line askpass reply.
    """
    if not password or not password.strip():
        return "the password cannot be empty"
    if any(c in password for c in "\r\n\0"):
        return "the password cannot contain line breaks or NUL characters"
    return None


def _describe_os_error(exc: OSError) -> str:
    where = exc.filename or ""
    reason = exc.strerror or str(exc)
    return f"{where}: {reason}" if where else reason


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


def _listen_address(arg: str) -> str:
    """Explicit address of a listen value ('' for '443', '*:443', '[::]:443')."""
    if ":" not in arg or arg.startswith("unix:"):
        return ""
    host = arg.rsplit(":", 1)[0].strip("[]")
    return "" if host in ("*", "", "::", "0.0.0.0") else host


def _match_nginx_server(blocks: List[Dict[str, List[List[str]]]], domain: str,
                        port: int = 443, addresses: Tuple[str, ...] = ()):
    """Server block nginx selects for `domain` on `port`.

    Mirrors nginx: only blocks listening on the port - and, when the target's
    `addresses` are known, only the blocks of the listen socket the connection
    reaches (an explicit `addr:port` socket takes it over `*:port`); exact name
    (first wins), longest leading wildcard, longest trailing wildcard, first
    matching regex; else that socket's default_server, else its first block.
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

    def socket_addrs(dirs) -> set:
        return {_listen_address(a[0]) for a in dirs.get("listen", [])
                if a and a[0].rsplit(":", 1)[-1].strip("[]").split("/")[0] == str(port)}

    wanted = {a for a in addresses if a}
    specific = [(d, p) for d, p in on_port if socket_addrs(d) & wanted]
    if specific:
        on_port = specific
        hit = sorted(set().union(*(socket_addrs(d) for d, _p in specific)) & wanted)
        notes.append(f"listen address {', '.join(hit)}:{port} has its own socket: only "
                     "its server blocks can answer")
    elif wanted and any(socket_addrs(d) - {""} for d, _p in on_port):
        wildcard = [(d, p) for d, p in on_port if "" in socket_addrs(d)]
        if wildcard:
            on_port = wildcard
            notes.append(f"no listen socket for {', '.join(sorted(wanted))}:{port}; "
                         f"the *:{port} server blocks answer")
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

# ssh-keyscan offers OpenSSH's compiled-in default KEX list unfiltered, so a
# build without sntrup761x25519 (the first default) fails against a server that
# picks it, while ssh itself only offers what the binary implements.
_KEX_FAILURES = ("unsupported KEX method", "no matching key exchange")
# one probe per host key family; RSA keys are stored as ssh-rsa whichever
# signature algorithm negotiated them
_PROBE_HOST_KEY_ALGS = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
                        "ecdsa-sha2-nistp521", "rsa-sha2-512,rsa-sha2-256,ssh-rsa")


def _scan_host_keys(host: str, port: int, timeout: float,
                    username: str = "") -> Tuple[List[str], str]:
    """Return ('host keytype base64' lines, error)."""
    if not shutil.which("ssh-keyscan"):
        return _scan_host_keys_ssh(host, port, timeout, username, "ssh-keyscan not available")
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
        reason = err[-1] if err else "no host keys retrieved (SSH service reachable?)"
        if any(marker in proc.stderr for marker in _KEX_FAILURES):
            return _scan_host_keys_ssh(host, port, timeout, username, reason)
        return [], reason
    return lines, ""


def _scan_host_keys_ssh(host: str, port: int, timeout: float, username: str,
                        keyscan_error: str) -> Tuple[List[str], str]:
    """Read the host keys through ssh, which negotiates like the real session.

    Each probe accepts the presented key into a scratch known_hosts file and then
    stops: every authentication method is off, so it can never log in. Lines
    come back in ssh-keyscan's form (`host keytype base64`, `[host]:port` off
    port 22) whatever HashKnownHosts says.
    """
    if not shutil.which("ssh"):
        return [], f"{keyscan_error}; ssh client not found"
    name = host if port == 22 else f"[{host}]:{port}"
    lines: List[str] = []
    seen = set()
    last_error = ""
    scratch = os.path.join(_ensure_state_dir(), ".probe_known_hosts")
    for algs in _PROBE_HOST_KEY_ALGS:
        if os.path.exists(scratch):
            os.unlink(scratch)
        argv = ["ssh", "-p", str(port), "-T",
                "-o", f"ConnectTimeout={int(timeout)}",
                "-o", f"UserKnownHostsFile={scratch}",
                "-o", "GlobalKnownHostsFile=/dev/null",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "HashKnownHosts=no",
                "-o", f"HostKeyAlgorithms={algs}",
                "-o", "BatchMode=yes",
                "-o", "PubkeyAuthentication=no",
                "-o", "PasswordAuthentication=no",
                "-o", "KbdInteractiveAuthentication=no",
                "-o", "GSSAPIAuthentication=no",
                "-o", "HostbasedAuthentication=no",
                "-o", "ControlPath=none",
                "-o", "LogLevel=ERROR"]
        if username:
            argv += ["-l", username]
        argv += [host, "--", "true"]
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=timeout + 5,
                                  text=True, stdin=subprocess.DEVNULL,
                                  start_new_session=True)
        except subprocess.TimeoutExpired:
            last_error = f"host key probe timed out after {timeout:.0f}s"
            continue
        except FileNotFoundError:
            return [], f"{keyscan_error}; ssh client not found"
        if os.path.exists(scratch):
            with open(scratch) as fh:
                for row in fh:
                    parts = row.split()
                    if len(parts) >= 3 and (parts[1], parts[2]) not in seen:
                        seen.add((parts[1], parts[2]))
                        lines.append(f"{name} {parts[1]} {parts[2]}")
            os.unlink(scratch)
        err = proc.stderr.strip().splitlines()
        if err:
            last_error = err[-1]
    if lines:
        return lines, ""
    return [], f"{keyscan_error}; ssh: {last_error or 'no host keys retrieved'}"


_SHA256 = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")


def sha256_fingerprints(lines: List[str]) -> List[str]:
    """The `SHA256:` fingerprints in `ssh-keygen -l` output lines, in order."""
    found: List[str] = []
    for line in lines:
        for fp in _SHA256.findall(line):
            if fp not in found:
                found.append(fp)
    return found


def host_key_status(host: str, port: int, timeout: float = 8.0,
                    username: str = "") -> HostKeyInfo:
    """Compare the presented host keys with the trust store.

    A trust store that cannot be used or a missing `ssh-keygen` is reported as
    `unreachable` with the reason, never raised: the caller must stop before
    authenticating either way.
    """
    try:
        return _host_key_status(host, port, timeout, username)
    except FileNotFoundError as exc:
        if exc.filename in (None, "ssh-keygen") or "ssh-keygen" in str(exc):
            return HostKeyInfo("unreachable", [],
                               "ssh-keygen not found: install the OpenSSH client tools")
        return HostKeyInfo("unreachable", [],
                           f"host-key trust store unusable: {_describe_os_error(exc)}")
    except OSError as exc:
        return HostKeyInfo("unreachable", [],
                           f"host-key trust store unusable: {_describe_os_error(exc)}")
    except subprocess.TimeoutExpired:
        return HostKeyInfo("unreachable", [], "ssh-keygen did not answer in time")


def _host_key_status(host: str, port: int, timeout: float,
                     username: str) -> HostKeyInfo:
    kh_path = os.path.join(_ensure_state_dir(), "known_hosts")
    if not os.path.exists(kh_path):
        open(kh_path, "a").close()
        os.chmod(kh_path, 0o600)

    scan, err = _scan_host_keys(host, port, timeout, username)
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
        try:
            os.unlink(tmp)
        except OSError:
            pass                           # a leftover scratch file holds public keys only

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


def store_host_key(host: str, port: int, timeout: float = 8.0,
                   username: str = "") -> Tuple[bool, str]:
    """Persist the currently presented host key. Requires prior user consent."""
    try:
        kh_path = os.path.join(_ensure_state_dir(), "known_hosts")
        scan, err = _scan_host_keys(host, port, timeout, username)
        if not scan:
            return False, err
        with open(kh_path, "a") as fh:
            fh.write("\n".join(scan) + "\n")
    except OSError as exc:
        return False, f"could not store the host key: {_describe_os_error(exc)}"
    return True, "host key stored in " + kh_path


def askpass_reply() -> Optional[int]:
    """Act as the SSH_ASKPASS helper when ssh started this executable for it.

    Returns None when the process was not started as the helper. Otherwise
    prints the password from the environment (UTF-8, one line) and returns
    0 -- or prints nothing and returns 1 when there is no usable password, so
    ssh gives up instead of sending an empty one.
    """
    if os.environ.get(ASKPASS_MODE_ENV) != "1":
        return None
    secret = os.environ.get("SSL_DOCTOR_PW", "")
    if password_problem(secret):
        return 1
    stream = getattr(sys.stdout, "buffer", None)
    if stream is not None:
        stream.write(secret.encode("utf-8") + b"\n")
    else:
        sys.stdout.write(secret + "\n")
    sys.stdout.flush()
    return 0


# ---------------------------------------------------------------- SSH session

@dataclass
class NginxSettings:
    """Per-server nginx settings in force for a session (see /server config).

    `mode` "manual" means the saved certificate/key paths are validated
    instead of the automatically resolved ones; `conf` / `prefix` steer
    discovery in either mode. `origin` says where they came from.
    """
    mode: str = "auto"
    cert: str = ""
    key: str = ""
    conf: str = ""
    prefix: str = ""
    origin: str = ""

    @property
    def manual(self) -> bool:
        return self.mode == "manual"

    @property
    def is_default(self) -> bool:
        return not (self.manual or self.conf or self.prefix)


# SHA-256 of no input: what a digest pipeline prints when its producer failed
_EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

_PATH_STATE_LABELS = {
    "readable": "exists and is readable",
    "denied": "exists but is not readable by this account",
    "notfile": "exists but is not a regular file",
    "missing": "missing (no such file)",
    "unreachable": "not reachable: a parent directory is not searchable by this account",
    "unsupported": "not checked: unsupported characters in the path",
}


_FILE_STATE_LABELS = {
    "missing": "missing", "denied": "not readable", "nomatch": "matched no file",
    "toolarge": "too large, not read", "unsupported": "unsupported, not read",
    "limit": "not read (limit reached)",
}


def _nginx_conf_finding(d: "nginx_discovery.Discovery", username: str) -> F.Finding:
    """`nginx.conf`: what was found, how it relates to the running nginx, what is missing."""
    nd = nginx_discovery
    title = "Nginx TLS configuration"
    ev: List[str] = [f"evidence level: {d.level}"
                     + ("" if d.level == nd.LEVEL_NONE else
                        (", configuration graph complete" if d.complete
                         else ", configuration graph INCOMPLETE"))]
    ev += d.facts
    if d.main_path:
        ev.append(f"main configuration: {d.main_path} ({d.main_how})")
    if d.via_dump:
        ev.append(f"read with: {d.via_dump} (output used in memory only)")
    read = d.read_files
    if read:
        ev.append(f"files read: {len(read)} - " + ", ".join(f.path for f in read[:8])
                  + (" ..." if len(read) > 8 else ""))
    for f in [f for f in d.files if f.state != nd.READ][:12]:
        label = _FILE_STATE_LABELS.get(f.state, f.state)
        ev.append(f"{f.path}: {label}" + (f" ({f.note})" if f.note else ""))
    if d.roots:
        ev.append("searched: " + ", ".join(f"{root} ({state})" for root, state in d.roots))
    ev += [f"limitation: {item}" for item in d.limitations]
    if d.level == nd.LEVEL_NONE:
        return F.Finding(
            "nginx.conf", title, F.NOT_TESTED, F.SCOPE_SERVER,
            [f"no nginx configuration could be read by account '{username}'", *ev],
            recommendation="Re-run with an account allowed to read the nginx "
                           "configuration (and /proc/<pid> of the master), or use "
                           "/server cert <path> [key] with the certificate paths directly.",
            uncertainty=list(d.uncertainty))
    if d.conclusive:
        return F.Finding("nginx.conf", title, F.PASS, F.SCOPE_SERVER, ev,
                         uncertainty=list(d.uncertainty))
    return F.Finding(
        "nginx.conf", title, F.WARNING, F.SCOPE_SERVER, ev,
        detail="Conclusions about server blocks below are limited to the analysed files.",
        recommendation="Confirm which configuration the running nginx uses (its -p/-c "
                       "arguments) before changing anything; an account that can read "
                       "/proc/<pid> of the master and the configuration gives a "
                       "complete view.",
        uncertainty=list(d.uncertainty))


# ------------------------------------------------------- nginx discovery probe

_FRAME = "@@SSLDOCTOR"


class _SshNginxProbe:
    """Read-only remote primitives for `nginx_discovery.discover()` over SSH.

    Every command is a fixed template; paths and unit names were validated by
    the caller (`nginx_discovery.SAFE_*`) and are quoted here as well, except
    include patterns, which the shell must expand and which therefore carry
    only safe characters. Any failure returns "unavailable", never raises.
    """

    def __init__(self, session: "ServerSession") -> None:
        self.session = session

    def _run(self, command: str) -> Tuple[int, str]:
        rc, out, _err, fatal = self.session.run(command)
        return (rc if not fatal else 255), ("" if fatal else out)

    def processes(self):
        rc, out = self._run(
            "command -v ps >/dev/null 2>&1 || echo '@@SSLDOCTOR NOPS'; "
            "ps -eo pid=,ppid=,user=,etimes=,args= 2>/dev/null | head -c 65536; echo; "
            "echo \"@@SSLDOCTOR NOW $(date +%s)\"")
        if rc == 255:
            return None, None, "the account could not run the process listing"
        # markers count only as whole lines: ps lists this very command line too
        if "@@SSLDOCTOR NOPS" in out.splitlines():
            return None, None, "ps is not installed"
        now = None
        lines = []
        for line in out.splitlines():
            if line.startswith("@@SSLDOCTOR NOW "):
                value = line.split()[-1]
                now = int(value) if value.isdigit() else None
            else:
                lines.append(line)
        return "\n".join(lines), now, ""

    def proc_details(self, pid: int):
        pid = int(pid)
        rc, out = self._run(
            f"for k in exe cwd; do v=$(readlink /proc/{pid}/$k 2>/dev/null); "
            "if [ -n \"$v\" ]; then echo \"@@SSLDOCTOR $k ok $v\"; "
            "else echo \"@@SSLDOCTOR $k denied\"; fi; done; "
            f"echo '@@SSLDOCTOR cgroup'; head -c 4096 /proc/{pid}/cgroup 2>/dev/null")
        info: Dict = {"denied": []}
        cgroup = []
        in_cgroup = False
        for line in out.splitlines():
            if line.startswith("@@SSLDOCTOR cgroup"):
                in_cgroup = True
            elif line.startswith(_FRAME + " ") and not in_cgroup:
                parts = line.split(None, 3)
                if len(parts) == 4 and parts[2] == "ok":
                    info[parts[1]] = parts[3]
                elif len(parts) >= 3:
                    info["denied"].append(f"/proc/{pid}/{parts[1]} is not readable")
            elif in_cgroup:
                cgroup.append(line)
        info["cgroup"] = "\n".join(cgroup)
        if rc == 255:
            info["denied"].append(f"/proc/{pid} could not be inspected")
        return info

    def systemd_show(self, unit: str):
        rc, out = self._run(f"systemctl show {shlex.quote(unit)} -p Id -p LoadState "
                            "-p MainPID -p ExecStart -p FragmentPath --no-pager 2>/dev/null "
                            "| head -c 16384")
        # systemctl prints default properties for units that do not exist
        return out if rc == 0 and "LoadState=loaded" in out.splitlines() else None

    def systemd_units(self):
        rc, out = self._run("command -v systemctl >/dev/null 2>&1 || exit 3; "
                            "systemctl list-units --type=service --all --no-legend "
                            "--plain '*nginx*' 2>/dev/null | head -n 20")
        if rc not in (0, 1):
            return None
        return [line.split()[0] for line in out.splitlines() if line.split()]

    def exe_stat(self, path: str):
        rc, out = self._run(f"stat -Lc '%u %a %F' {shlex.quote(path)} 2>/dev/null")
        parts = out.strip().split(None, 2)
        if rc != 0 or len(parts) != 3 or not parts[0].isdigit():
            return None
        try:
            return int(parts[0]), int(parts[1], 8), parts[2]
        except ValueError:
            return None

    def build_info(self, exe: str):
        rc, out = self._run(f"{shlex.quote(exe)} -V 2>&1 | head -c 8192")
        return out if "nginx version" in out else None

    def _dump(self, command: str):
        _rc, out = self._run(f"{command} -T 2>/dev/null | head -c 4194304")
        return out if "# configuration file " in out else ""

    def dump(self, exe: str, prefix: str, conf: str):
        args = [shlex.quote(exe)]
        if prefix:
            args += ["-p", shlex.quote(prefix)]
        if conf:
            args += ["-c", shlex.quote(conf)]
        command = " ".join(args)
        return self._dump(command), command + " -T"

    def path_dump(self, override: str):
        # an operator-set SSLDOCTOR_NGINX_CMD may carry its own arguments
        command = override or "nginx"
        return self._dump(command), command + " -T"

    def mtimes(self, paths):
        safe = [p for p in paths if nginx_discovery.SAFE_PATH.match(p)]
        if not safe:
            return {}
        rc, out = self._run("stat -c '%Y %n' -- "
                            + " ".join(shlex.quote(p) for p in safe) + " 2>/dev/null")
        found = {}
        for line in out.splitlines():
            value, _, path = line.partition(" ")
            if value.isdigit():
                found[path] = int(value)
        return found

    def read(self, patterns):
        nd = nginx_discovery
        quoted = " ".join(shlex.quote(p) for p in patterns)
        rc, out = self._run(
            "command -v base64 >/dev/null 2>&1 || { echo '@@SSLDOCTOR NOBASE64'; exit 0; }; "
            f"L={nd.MAX_FILE_BYTES}; T={nd.MAX_TOTAL_BYTES}; t=0; "
            f"for pat in {quoted}; do n=0; "
            "for f in $pat; do "                       # unquoted: the shell expands globs
            "[ -f \"$f\" ] || continue; n=1; "
            "if [ ! -r \"$f\" ]; then echo \"@@SSLDOCTOR denied 0 0 $pat $f\"; continue; fi; "
            "s=$(wc -c < \"$f\" 2>/dev/null); s=$((s+0)); "
            "m=$(stat -c %Y \"$f\" 2>/dev/null); m=$((m+0)); "
            "if [ $s -gt $L ]; then echo \"@@SSLDOCTOR toolarge $m $s $pat $f\"; continue; fi; "
            "t=$((t+s)); if [ $t -gt $T ]; then echo \"@@SSLDOCTOR limit $m $s $pat $f\"; "
            "continue; fi; "
            "echo \"@@SSLDOCTOR read $m $s $pat $f\"; base64 < \"$f\" | tr -d '\\n'; echo; "
            "done; "
            "if [ $n = 0 ]; then d=$(dirname \"$pat\"); "
            "if [ -d \"$d\" ] && { [ ! -x \"$d\" ] || [ ! -r \"$d\" ]; }; "
            "then echo \"@@SSLDOCTOR denied 0 0 $pat $pat\"; "
            "else echo \"@@SSLDOCTOR none 0 0 $pat $pat\"; fi; fi; done")
        if rc == 255 or "@@SSLDOCTOR NOBASE64" in out.splitlines()[:1]:
            note = ("base64 is not available on the server" if rc != 255
                    else "the account could not read files")
            return [nd.FileRecord(p, p, nd.UNSUPPORTED, note=note) for p in patterns]
        import base64
        records = []
        lines = out.splitlines()
        i = 0
        states = {"read": nd.READ, "denied": nd.DENIED, "toolarge": nd.TOOLARGE,
                  "limit": nd.LIMIT}
        while i < len(lines):
            parts = lines[i].split(" ", 5)
            i += 1
            if len(parts) != 6 or parts[0] != _FRAME:
                continue
            _, state, mtime, size, pattern, path = parts
            if state == "none":
                state = nd.NOMATCH if nd.is_glob(pattern) else nd.MISSING
            else:
                state = states.get(state, nd.UNSUPPORTED)
            content = ""
            if state == nd.READ:
                payload = lines[i] if i < len(lines) else ""
                i += 1
                try:
                    content = base64.b64decode(payload).decode("utf-8", "replace")
                except ValueError:
                    state = nd.UNSUPPORTED
            records.append(nd.FileRecord(pattern, path, state,
                                         int(mtime) if mtime.isdigit() else 0,
                                         int(size) if size.isdigit() else 0, content))
        return records

    def file_states(self, paths):
        """Per path: readable, denied, notfile, missing, unreachable or unsupported."""
        states = {p: "unsupported" for p in paths if not nginx_discovery.SAFE_PATH.match(p)}
        safe = [p for p in paths if p not in states]
        if safe:
            # walk up to the nearest existing ancestor: a missing file below a
            # directory the account may not search is "unreachable", not missing
            _rc, out = self._run(
                "for p in " + " ".join(shlex.quote(p) for p in safe) + "; do "
                "if [ -f \"$p\" ] && [ -r \"$p\" ]; then s=readable; "
                "elif [ -e \"$p\" ] && [ ! -f \"$p\" ]; then s=notfile; "
                "elif [ -e \"$p\" ]; then s=denied; "
                "else d=$(dirname \"$p\"); "
                "while [ \"$d\" != / ] && [ ! -e \"$d\" ]; do d=$(dirname \"$d\"); done; "
                "if [ -d \"$d\" ] && [ ! -x \"$d\" ]; then s=unreachable; else s=missing; fi; "
                "fi; echo \"@@SSLDOCTOR $s $p\"; done")
            for line in out.splitlines():
                parts = line.split(" ", 2)
                if len(parts) == 3 and parts[0] == _FRAME and parts[2] in safe:
                    states[parts[2]] = parts[1]
            for p in safe:
                states.setdefault(p, "missing" if _rc == 0 else "unsupported")
        return states

    def root_states(self, roots):
        rc, out = self._run(
            "for r in " + " ".join(shlex.quote(r) for r in roots) + "; do "
            "if [ ! -e \"$r\" ]; then echo \"missing $r\"; "
            "elif [ ! -r \"$r\" ] || [ ! -x \"$r\" ]; then echo \"denied $r\"; "
            "else echo \"ok $r\"; fi; done")
        states = []
        for line in out.splitlines():
            state, _, root = line.partition(" ")
            if root in roots:
                states.append((root, state))
        return states or [(r, "unknown") for r in roots]

    def find_main(self, roots):
        rc, out = self._run("find " + " ".join(shlex.quote(r) for r in roots)
                            + " -xdev -maxdepth 4 -type f -name nginx.conf 2>/dev/null "
                            "| head -n 20")
        return [line.strip() for line in out.splitlines()
                if nginx_discovery.SAFE_PATH.match(line.strip())]

    # -- service runtime (listeners, config test, journal, renewal) --------
    def listeners(self, port: int):
        """`ss -ltnp` (or `netstat -ltnp`) output; None when neither exists."""
        rc, out = self._run(
            "if command -v ss >/dev/null 2>&1; then ss -H -ltnp 2>/dev/null; "
            "elif command -v netstat >/dev/null 2>&1; then netstat -ltnp 2>/dev/null; "
            "else echo '@@SSLDOCTOR NONE'; fi | head -c 65536")
        if rc == 255 or "@@SSLDOCTOR NONE" in out.splitlines():
            return None
        return out

    def config_test(self, argv: List[str]):
        """(exit status, output) of a service's own configuration test.

        Only test modes (`-t`, `-c`) are passed by the caller; the output is
        bounded and the real exit status kept.
        """
        command = " ".join(shlex.quote(a) for a in argv)
        rc, out = self._run(f"out=$({command} 2>&1); rc=$?; printf '%s\\n' \"$out\" "
                            "| head -c 16384; echo \"@@SSLDOCTOR rc=$rc\"")
        status = None
        lines = []
        for line in out.splitlines():
            if line.startswith("@@SSLDOCTOR rc="):
                value = line.split("=", 1)[1]
                status = int(value) if value.isdigit() else None
            else:
                lines.append(line)
        return status, "\n".join(lines)

    def journal(self, unit: str):
        if not unit or not nginx_discovery.SAFE_UNIT.match(unit):
            return []
        _rc, out = self._run(f"journalctl -u {shlex.quote(unit)} -n 200 --no-pager -q "
                             "2>/dev/null | tail -n 200")
        return out.splitlines()

    _RENEWAL_SCRIPT = (
        'echo "@@SSLDOCTOR tools"; for t in certbot acme.sh lego; do command -v "$t" '
        '2>/dev/null; done; for d in /root/.acme.sh "$HOME/.acme.sh"; do '
        '[ -x "$d/acme.sh" ] && echo "$d/acme.sh"; done; '
        'echo "@@SSLDOCTOR certbot"; grep -HE "^(cert|fullchain|privkey|chain) *=" '
        '/etc/letsencrypt/renewal/*.conf 2>/dev/null | head -n 200; '
        'echo "@@SSLDOCTOR acme.sh"; grep -HE "^Le_Real(Cert|FullChain|Key)Path=" '
        '/root/.acme.sh/*/*.conf "$HOME"/.acme.sh/*/*.conf 2>/dev/null | head -n 200; '
        'echo "@@SSLDOCTOR timers"; systemctl list-timers --all --no-pager --no-legend '
        '2>/dev/null | grep -iE "certbot|acme|lego" | head -n 10; '
        # cron: file names only - a cron line may carry API credentials
        'echo "@@SSLDOCTOR cron"; grep -liE "certbot|acme\\.sh|lego" /etc/crontab '
        '/etc/cron.d/* /etc/cron.daily/* /var/spool/cron/crontabs/* /var/spool/cron/* '
        '2>/dev/null | head -n 10')

    def renewal(self):
        _rc, out = self._run(self._RENEWAL_SCRIPT)
        return out

    def realpaths(self, paths):
        safe = [p for p in paths if nginx_discovery.SAFE_PATH.match(p)]
        if not safe:
            return {}
        _rc, out = self._run("for p in " + " ".join(shlex.quote(p) for p in safe)
                             + "; do printf '%s\\t%s\\n' \"$p\" "
                               "\"$(readlink -f -- \"$p\" 2>/dev/null)\"; done")
        found = {}
        for line in out.splitlines():
            path, _, real = line.partition("\t")
            if path in safe and real:
                found[path] = real
        return found

    def list_conf(self, dirs):
        safe = [d for d in dirs if nginx_discovery.SAFE_PATH.match(d)]
        if not safe:
            return []
        rc, out = self._run("for d in " + " ".join(shlex.quote(d) for d in safe) + "; do "
                            "[ -d \"$d\" ] && [ -r \"$d\" ] && "
                            "find \"$d\" -maxdepth 1 -type f -name '*.conf' 2>/dev/null; "
                            "done | head -n 50")
        return sorted(line.strip() for line in out.splitlines() if line.strip())


class ServerSession:
    """A thin, stateful wrapper around the system ssh client."""

    def __init__(self, cfg: SSHConfig, password: str = "") -> None:
        self.cfg = cfg
        self._password = password  # kept in memory only; never logged/printed
        self._askpass_path: Optional[str] = None
        self.connected = False
        # populated by cert scans
        self.last_remote_cert_sha256: str = ""
        self.last_configured_chain: List = []      # certificates of the last chain file read
        # facts.certificates entries ("configured:<path>") of the chain files read
        self.chain_facts: Dict[str, Dict] = {}
        # what this scan read, so a comparison never uses an earlier command's file
        self.scan_context: Dict = {"configured": [], "conclusive": True}
        self.nginx_cert_path: str = ""
        self.nginx_key_path: str = ""
        # nginx invocation for config dumps; override for non-default installs,
        # e.g. SSLDOCTOR_NGINX_CMD="/usr/local/nginx/sbin/nginx -p /usr/local/nginx"
        self.nginx_cmd: str = os.environ.get("SSLDOCTOR_NGINX_CMD", "nginx")
        self._nginx_discovery: Optional[nginx_discovery.Discovery] = None
        self.nginx_settings = NginxSettings()

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

    def _write_askpass(self, windows: bool, frozen: bool) -> str:
        """The SSH_ASKPASS helper: it reads the password from the environment.

        Win32-OpenSSH starts the helper with CreateProcessW, which runs an .exe
        or a .cmd but not a shell script. A frozen build is its own helper (see
        :func:`askpass_reply`); otherwise a .cmd runs this interpreter. The
        secret is never written into the helper, so cmd.exe cannot expand or
        split it.
        """
        if windows and frozen:
            return sys.executable
        if windows:
            path = os.path.join(_ensure_state_dir(), "askpass.cmd")
            code = ("import os,sys;p=os.environ.get('SSL_DOCTOR_PW','');"
                    "p.strip() or sys.exit(1);"
                    "sys.stdout.buffer.write(p.encode('utf-8')+b'\\n')")
            with open(path, "w", newline="") as fh:   # CRLF exactly once
                fh.write(f'@echo off\r\n@"{sys.executable}" -I -c "{code}"\r\n')
        else:
            path = os.path.join(_ensure_state_dir(), "askpass.sh")
            with open(path, "w") as fh:
                # an empty or blank password: fail, so ssh never sends it
                fh.write("#!/bin/sh\n"
                         "case \"$SSL_DOCTOR_PW\" in *[![:space:]]*) ;; *) exit 1 ;; esac\n"
                         "printf '%s\\n' \"$SSL_DOCTOR_PW\"\n")
        os.chmod(path, stat.S_IRWXU)
        self._askpass_path = path
        return path

    def _spawn_env(self, windows: Optional[bool] = None,
                   frozen: Optional[bool] = None) -> Dict[str, str]:
        env = dict(os.environ)
        if self.cfg.auth == "password" and self._password:
            windows = os.name == "nt" if windows is None else windows
            frozen = bool(getattr(sys, "frozen", False)) if frozen is None else frozen
            askpass = self._write_askpass(windows, frozen)
            if windows and frozen:
                env[ASKPASS_MODE_ENV] = "1"
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
        try:
            cmd = self._base_argv() + ["--", remote_cmd]
            env = self._spawn_env()
        except OSError as exc:
            return 126, "", "", ("cannot prepare the ssh call (askpass helper / state "
                                 f"directory): {_describe_os_error(exc)}")
        try:
            proc = subprocess.run(
                cmd, capture_output=True, timeout=self.cfg.command_timeout,
                text=True, env=env, stdin=subprocess.DEVNULL,
                start_new_session=True)
        except FileNotFoundError:
            return 127, "", "", "ssh client not found on this machine"
        except OSError as exc:
            return 126, "", "", f"ssh could not be started: {_describe_os_error(exc)}"
        except subprocess.TimeoutExpired:
            return 124, "", "", \
                f"command timed out after {self.cfg.command_timeout:.0f}s"
        return proc.returncode, proc.stdout, proc.stderr, ""

    # -- lifecycle ---------------------------------------------------------
    def connect(self) -> List[F.Finding]:
        out: List[F.Finding] = []
        target = f"{self.cfg.host}:{self.cfg.port}"
        self._nginx_discovery = None
        if self.cfg.auth == "password" and (problem := password_problem(self._password)):
            return [F.Finding("ssh.auth", "SSH authentication", F.FAIL, F.SCOPE_SERVER,
                              [f"not attempted: {problem}"], target=target)]
        key = host_key_status(self.cfg.host, self.cfg.port,
                              self.cfg.connect_timeout, self.cfg.username)
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
        self._nginx_discovery = None
        self._password = ""
        if self._askpass_path and os.path.exists(self._askpass_path):
            try:
                os.unlink(self._askpass_path)
            except OSError:
                pass
            self._askpass_path = None

    # -- nginx discovery ---------------------------------------------------
    def nginx_probe(self):
        return _SshNginxProbe(self)

    def set_nginx_settings(self, settings: "NginxSettings") -> None:
        """Settings changed (connect, /server config): discovery must run again."""
        self.nginx_settings = settings
        self._nginx_discovery = None

    def discover_nginx(self) -> nginx_discovery.Discovery:
        """Discovery for this session (stages A-E), computed once per connection."""
        if self._nginx_discovery is None:
            override = os.environ.get("SSLDOCTOR_NGINX_CMD", "")
            self._nginx_discovery = nginx_discovery.discover(
                self.nginx_probe(), override, conf_override=self.nginx_settings.conf,
                prefix_override=self.nginx_settings.prefix)
        return self._nginx_discovery

    # -- diagnostics -------------------------------------------------------
    def _need_conn(self) -> Optional[F.Finding]:
        if not self.connected:
            return F.Finding("ssh.state", "SSH session state", F.NOT_TESTED,
                             F.SCOPE_SERVER, ["not connected; run /server connect first"])
        return None

    def overview(self, emit: Optional[Callable[[F.Finding], None]] = None) -> List[F.Finding]:
        if (err := self._need_conn()):
            if emit is not None:
                emit(err)
            return [err]
        rc, so, se, fatal = self.run(
            "uname -a; echo ---; cat /etc/os-release 2>/dev/null | head -n 3; echo ---; id")
        if fatal or rc != 0:
            _f = F.Finding("srv.os", "Server OS and identity", F.FAIL, F.SCOPE_SERVER,
                           [fatal or (se.strip() or f"rc={rc}")])
            if emit is not None:
                emit(_f)
            return [_f]
        _f = F.Finding("srv.os", "Server OS and identity", F.PASS, F.SCOPE_SERVER,
                       [ln.rstrip() for ln in so.splitlines() if ln.strip()])
        if emit is not None:
            emit(_f)
        return [_f]

    def webserver_detection(self, emit: Optional[Callable[[F.Finding], None]] = None) -> List[F.Finding]:
        if (err := self._need_conn()):
            if emit is not None:
                emit(err)
            return [err]
        rc, so, se, fatal = self.run(
            "for b in nginx apache2 httpd; do "
            "if command -v $b >/dev/null 2>&1; then "
            "echo \"$b -> $(command -v $b)\"; $($b -v 2>&1 | head -n1); fi; "
            "done; "
            "command -v openssl >/dev/null 2>&1 && echo \"openssl: $(openssl version)\"")
        if fatal:
            _f = F.Finding("srv.web", "Web server detection", F.FAIL, F.SCOPE_SERVER,
                           [fatal])
            if emit is not None:
                emit(_f)
            return [_f]
        lines = [ln.strip() for ln in (so + se).splitlines() if ln.strip()]
        # the running instance, which need not be the nginx on this account's PATH
        discovery = self.discover_nginx()
        for m in discovery.masters[:nginx_discovery.MAX_MASTERS]:
            lines.append(f"running nginx master pid {m.pid}: {m.executable or m.exe or '?'}"
                         + (f" -p {m.prefix}" if m.prefix else "")
                         + (f" -c {m.conf}" if m.conf else ""))
        if not lines:
            _f = F.Finding(
                "srv.web", "Web server detection", F.WARNING, F.SCOPE_SERVER,
                ["no nginx/apache binaries found in the PATH of this account, and no "
                 "running nginx master is visible"],
                recommendation="Confirm which service terminates TLS (load balancer? "
                               "IIS? another host?) and re-target the checks.")
            if emit is not None:
                emit(_f)
            return [_f]
        _f = F.Finding("srv.web", "Web server detection", F.PASS, F.SCOPE_SERVER,
                       lines)
        if emit is not None:
            emit(_f)
        return [_f]

    # Classifies a key on the server from its structure; prints one token and
    # never the key.  asn1parse output (which shows key numbers for a plain DER
    # key) stays inside the pipeline: only grep's verdict leaves the shell.
    _KEY_STATE_SCRIPT = (
        'k={path}; '
        'if [ ! -e "$k" ]; then s=missing; '
        'elif [ ! -r "$k" ]; then s=unreadable; '
        'elif head -c 4096 "$k" | grep -q -e "BEGIN ENCRYPTED PRIVATE KEY" '
        '-e "Proc-Type: 4,ENCRYPTED"; then s=encrypted; '
        'elif ! command -v openssl >/dev/null 2>&1; then s=noverifier; '
        'elif openssl asn1parse -inform DER -in "$k" 2>/dev/null | head -n 4 '
        '| grep -q -i -e ":PBES2" -e ":pbeWith" -e ":pkcs7-data"; then s=encrypted; '
        'elif openssl pkey -in "$k" -passin pass: -noout >/dev/null 2>&1 '
        '|| openssl pkey -inform DER -in "$k" -passin pass: -noout >/dev/null 2>&1; '
        'then s=readable; '
        'else s=unsupported; fi; echo "@@SSLDOCTOR keystate=$s"')

    def key_state(self, key_path: str) -> Tuple[str, str]:
        """(state, reason) of a key file on the server; state "" = undetermined.

        States follow `certs.key_state`; "noverifier" means openssl is missing,
        so a plain key could not be told from an unsupported one.
        """
        rc, out, err, fatal = self.run(
            self._KEY_STATE_SCRIPT.format(path=shlex.quote(key_path)))
        for line in out.splitlines():
            if line.startswith("@@SSLDOCTOR keystate="):
                return line.split("=", 1)[1].strip(), ""
        return "", (fatal or err.strip()[:200] or f"key-state probe exited {rc}")

    @staticmethod
    def _judge_configured_cert(openssl_out: str, domain: str) -> Tuple[str, List[str], str]:
        """(status, evidence, recommendation) from `openssl x509` output: the
        validity window, and the subjectAltName against `domain` when given."""
        info = certs.CertInfo()
        for ln in openssl_out.splitlines():
            ln = ln.strip()
            if ln.startswith("notBefore="):
                info.not_before = certs._parse_time(ln.split("=", 1)[1])
            elif ln.startswith("notAfter="):
                info.not_after = certs._parse_time(ln.split("=", 1)[1])
            elif ln.startswith(("DNS:", "IP Address:")):
                for entry in (e.strip() for e in ln.split(",")):
                    kind, _, value = entry.partition(":")
                    if kind == "DNS":
                        info.san_dns.append(value)
                    elif kind == "IP Address":
                        info.san_ip.append(value)
        status, line, rec = certpolicy.leaf_validity(info)
        evidence = [line]
        if domain:
            ok, entry = info.hostname_match(domain)
            if ok:
                evidence.append(f"covers '{domain}' (subjectAltName entry '{entry}')")
            else:
                evidence.append(f"does not cover '{domain}': subjectAltName "
                                f"{', '.join(info.san_dns + info.san_ip) or '(none)'}")
                if status != F.FAIL:
                    rec = ("Install a certificate whose subjectAltName includes this "
                           "domain.")
                status = F.FAIL
        return status, evidence, rec

    def scan_cert(self, cert_path: str, key_path: str = "",
                  emit: Optional[Callable[[F.Finding], None]] = None,
                  states: Optional[Dict[str, str]] = None,
                  domain: Optional[str] = None) -> List[F.Finding]:
        """Inspect a certificate (and optionally key pairing) ON the server.

        File access is checked first: a missing or unreadable file is NOT
        TESTED with its state, never reported as an invalid certificate.
        """
        if (err := self._need_conn()):
            if emit is not None:
                emit(err)
            return [err]
        domain = self.cfg.tls_host if domain is None else domain
        if states is None:
            states = self.nginx_probe().file_states([p for p in (cert_path, key_path) if p])
        cert_state = states.get(cert_path, "unsupported")
        if cert_state != "readable":
            label = ("file not found" if cert_state == "missing"
                     else _PATH_STATE_LABELS.get(cert_state, cert_state))
            _f = F.Finding("srv.cert", f"Server certificate {cert_path}", F.NOT_TESTED,
                           F.SCOPE_SERVER, [f"{cert_path}: {label}"],
                           recommendation="Check the path, or the read permission of this "
                                          "account.", target=cert_path)
            if emit is not None:
                emit(_f)
            return [_f]
        key_state = states.get(key_path, "unsupported") if key_path else ""
        out: List[F.Finding] = []

        def _add(f: F.Finding) -> F.Finding:
            list.append(out, f)
            if emit is not None:
                emit(f)
            return f

        q = shlex.quote
        rc, so, se, fatal = self.run(
            f"openssl x509 -noout -subject -issuer -dates -serial -fingerprint -sha256 "
            f"-ext subjectAltName -in {q(cert_path)} 2>&1; echo rc=$?")
        if fatal:
            _f = F.Finding("srv.cert", f"Server certificate {cert_path}", F.FAIL,
                           F.SCOPE_SERVER, [fatal], target=cert_path)
            if emit is not None:
                emit(_f)
            return [_f]
        if "rc=0" not in so:
            _add(F.Finding(
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
        self._record_configured(cert_path, fp, [])
        if key_path:
            self.scan_context.setdefault("keys", []).append(key_path)
        status, verdict, rec = self._judge_configured_cert(so, domain)
        _add(F.Finding(
            "srv.cert", f"Server certificate {cert_path}", status, F.SCOPE_SERVER,
            ev + ([f"sha256: {fp}"] if fp else []) + verdict,
            recommendation=rec, target=cert_path))

        if key_path and key_state != "readable":
            label = ("file not found" if key_state == "missing"
                     else _PATH_STATE_LABELS.get(key_state, key_state))
            _add(F.Finding(
                "srv.keymatch", "Certificate/key pairing on server", F.NOT_TESTED,
                F.SCOPE_SERVER, [f"private key {key_path}: {label}",
                                 "the pairing could not be tested"],
                target=cert_path))
        elif key_path:
            state, why = self.key_state(key_path)
            if state != certs.KEY_READABLE:
                _add(self._pairing_not_tested(cert_path, key_path, state, why))
                if state == certs.KEY_ENCRYPTED:
                    _add(self._keystartup_finding(key_path))
                return out
            cert_h, key_h, failed = self._pairing_digests(cert_path, key_path)
            if failed:
                _add(F.Finding(
                    "srv.keymatch", "Certificate/key pairing on server", F.NOT_TESTED,
                    F.SCOPE_SERVER,
                    [f"could not derive the {failed}",
                     "the pairing could not be tested; this is not a mismatch"],
                    target=cert_path, failure_kind="command-failed"))
            elif cert_h == key_h:
                _add(F.Finding(
                    "srv.keymatch", "Certificate/key pairing on server", F.PASS,
                    F.SCOPE_SERVER,
                    ["configured certificate and private key match",
                     f"public-key sha256: {cert_h}"],
                    target=cert_path))
            else:
                _add(F.Finding(
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

    def _keystartup_finding(self, key_path: str) -> F.Finding:
        """`srv.keystartup`: can the service unlock this encrypted key at startup?

        Only the presence and access state of the passphrase file are checked;
        its content is never read.
        """
        title = "Encrypted private key and service startup"
        directive = getattr(self, "_password_file", None)
        if directive is None:
            return F.Finding("srv.keystartup", title, F.NOT_TESTED, F.SCOPE_SERVER,
                             [f"{key_path} is encrypted; the service configuration that "
                              "uses it was not analysed in this command"],
                             recommendation="Run /server nginx to check ssl_password_file.",
                             target=key_path, failure_kind="key-encrypted")
        if not directive:
            return F.Finding("srv.keystartup", title, F.FAIL, F.SCOPE_SERVER,
                             [f"{key_path} is encrypted",
                              "nginx cannot load this encrypted key without "
                              "ssl_password_file (nginx would ask for the passphrase on "
                              "a terminal it does not have, and fail to start)"],
                             recommendation="Add ssl_password_file to the server block, or "
                                            "deploy an unencrypted key readable only by "
                                            "root.", target=key_path)
        value, resolved = directive
        state = self.nginx_probe().file_states([resolved]).get(resolved, "unsupported") \
            if resolved else "unsupported"
        label = _PATH_STATE_LABELS.get(state, state)
        if state == "readable" or state == "denied":
            # root-only passphrase files are normal: nginx's master reads it as root
            return F.Finding("srv.keystartup", title, F.PASS, F.SCOPE_SERVER,
                             [f"{key_path} is encrypted",
                              f"ssl_password_file {value} -> {resolved}: {label} "
                              "(passphrase file configured; its content is not read)"],
                             target=key_path)
        return F.Finding("srv.keystartup", title, F.FAIL, F.SCOPE_SERVER,
                         [f"{key_path} is encrypted",
                          f"ssl_password_file {value} -> {resolved or '?'}: {label}"],
                         recommendation="Point ssl_password_file at the passphrase file "
                                        "nginx should use.", target=key_path)

    _PAIRING_NOT_TESTED = {
        "encrypted": ("key-encrypted",
                      "the private key is passphrase-encrypted; it was not read"),
        "unreadable": ("key-unreadable", "the private key cannot be read by this account"),
        "missing": ("", "the private key file does not exist"),
        "unsupported": ("", "the file is not a private key openssl can load"),
        "noverifier": ("verifier-unavailable", "openssl is not available on the server"),
    }

    def _pairing_not_tested(self, cert_path: str, key_path: str, state: str,
                            why: str) -> F.Finding:
        kind, reason = self._PAIRING_NOT_TESTED.get(
            state, ("command-failed", f"the key could not be classified ({why})"))
        return F.Finding(
            "srv.keymatch", "Certificate/key pairing on server", F.NOT_TESTED,
            F.SCOPE_SERVER,
            [f"private key {key_path}: {reason}",
             "the pairing could not be tested; this is not a mismatch"],
            target=cert_path, failure_kind=kind)

    # Each step that fails prints its own marker to fd 3 (the script's stdout),
    # so a failure is never hidden behind the digest of an empty pipe.
    _PAIRING_SCRIPT = (
        'exec 3>&1; '
        'c=$( { openssl x509 -noout -pubkey -in {cert} 2>/dev/null '
        '|| echo "@@SSLDOCTOR fail=certificate public key" >&3; } '
        '| { openssl pkey -pubin -outform DER 2>/dev/null '
        '|| echo "@@SSLDOCTOR fail=certificate public key" >&3; } '
        '| sha256sum | cut -d" " -f1 ); '
        'k=$( { openssl pkey -in {key} -passin pass: -pubout -outform DER 2>/dev/null '
        '|| openssl pkey -inform DER -in {key} -passin pass: -pubout -outform DER '
        '2>/dev/null || echo "@@SSLDOCTOR fail=public key of the private key" >&3; } '
        '| sha256sum | cut -d" " -f1 ); '
        'echo "@@SSLDOCTOR cert=$c"; echo "@@SSLDOCTOR key=$k"')

    def _pairing_digests(self, cert_path: str, key_path: str) -> Tuple[str, str, str]:
        """(certificate digest, key digest, failed step); digests are SPKI SHA-256."""
        q = shlex.quote
        rc, out, err, fatal = self.run(
            self._PAIRING_SCRIPT.replace("{cert}", q(cert_path)).replace("{key}", q(key_path)))
        if fatal:
            return "", "", f"public keys ({fatal})"
        found: Dict[str, str] = {}
        for line in out.splitlines():
            if line.startswith("@@SSLDOCTOR "):
                name, _, value = line[len("@@SSLDOCTOR "):].partition("=")
                found.setdefault(name, value.strip())
        if "fail" in found:
            return "", "", found["fail"]
        cert_h, key_h = found.get("cert", ""), found.get("key", "")
        for label, digest in (("certificate public key", cert_h),
                              ("public key of the private key", key_h)):
            if not re.fullmatch(r"[0-9a-f]{64}", digest) or digest == _EMPTY_SHA256:
                return "", "", label
        return cert_h, key_h, ""

    def file_permissions(self, paths: List[str]) -> List[F.Finding]:
        """Permissions of `/server cert` arguments: the certificate, then its key."""
        return self.permissions([(p, "certificate" if i == 0 else "key")
                                 for i, p in enumerate(paths)])

    def permissions(self, entries: List[Tuple[str, str]],
                    reader: str = "") -> List[F.Finding]:
        """`srv.perms` per (path, role): owner, group, mode - never the content.

        The role comes from the directive, not the file name.  `reader` is the
        account that loads the files (nginx's master); "" or root = not judged.
        """
        if (err := self._need_conn()):
            return [err]
        q = shlex.quote
        groups: List[str] = []
        if reader and reader != "root":
            _rc, so, _se, fatal = self.run(f"id -Gn {q(reader)} 2>/dev/null")
            groups = so.split() if not fatal else []
        out: List[F.Finding] = []
        for path, role in entries:
            name = os.path.basename(path)
            rc, so, se, fatal = self.run(f"stat -c '%U %G %a %F' -- {q(path)} 2>&1 "
                                         "|| echo MISSING")
            line = so.strip().splitlines()[0] if so.strip() else ""
            if fatal or not line or "MISSING" in so or rc != 0:
                out.append(F.Finding(
                    "srv.perms", f"Permissions on {name}", F.NOT_TESTED, F.SCOPE_SERVER,
                    [f"{path}: {line or se.strip() or fatal or 'unreadable / missing'}"],
                    target=path, failure_kind="command-failed"))
                continue
            user, group, mode = (line.split(" ", 3) + ["", "", ""])[:3]
            try:
                bits = int(mode, 8)
            except ValueError:
                bits = None
            ev = [f"{path} ({role}): owner={user} group={group} mode={mode}"]
            if bits is None:
                out.append(F.Finding("srv.perms", f"Permissions on {name}", F.NOT_TESTED,
                                     F.SCOPE_SERVER, ev + ["mode could not be read"],
                                     target=path))
                continue
            problems, warnings = [], []
            if role == "key" and bits & 0o004:
                warnings.append("private key readable by other users")
            if reader and reader != "root":
                readable = ((user == reader and bits & 0o400)
                            or (group in groups and bits & 0o040) or bits & 0o004)
                if not readable:
                    problems.append(f"service account {reader} cannot read {path}")
                else:
                    ev.append(f"readable by the service account {reader}")
            status = F.FAIL if problems else F.WARNING if warnings else F.PASS
            out.append(F.Finding(
                "srv.perms", f"Permissions on {name}", status, F.SCOPE_SERVER,
                ev + problems + warnings,
                recommendation=("Make the file readable by the account the service runs "
                                "as (owner or group), without opening it to others."
                                if problems else
                                "Restrict private keys: chmod 600/640 root:<service group>."
                                if warnings else ""),
                target=path))
        return out

    def tls_config_scan(self, emit: Optional[Callable[[F.Finding], None]] = None) -> List[F.Finding]:
        """Find configured certs/vhosts. Read-only; degrades without privileges."""
        if (err := self._need_conn()):
            if emit is not None:
                emit(err)
            return [err]
        # nginx: the discovered configuration of the running instance, not fixed dirs
        discovery = self.discover_nginx()
        lines: List[str] = []
        if discovery.source:
            lines.append(f"nginx configuration {discovery.main_path} "
                         f"(evidence level {discovery.level}"
                         + ("" if discovery.complete else ", incomplete") + "):")
            wanted = re.compile(r"^\s*(server_name|listen|ssl_certificate(_key)?)\b")
            lines += [ln.strip()[:200] for ln in discovery.source.splitlines()
                      if wanted.match(ln)][:40]
        rc, so, se, fatal = self.run(
            "apache2ctl -S 2>/dev/null | head -n 30; "
            "grep -rniE 'SSLCertificate' /etc/apache2/sites-enabled /etc/httpd/conf.d "
            "2>/dev/null | head -n 30")
        lines += [ln.rstrip()[:200] for ln in so.splitlines() if ln.strip()]
        if fatal:
            _f = F.Finding("srv.tlsconf", "TLS virtual host configuration", F.FAIL,
                           F.SCOPE_SERVER, [fatal])
            if emit is not None:
                emit(_f)
            return [_f]
        if not lines:
            _f = F.Finding(
                "srv.tlsconf", "TLS virtual host configuration", F.NOT_TESTED,
                F.SCOPE_SERVER,
                ["no readable TLS configuration found for this account"],
                recommendation="Re-run with an account that can read the web server "
                               "configuration, or supply cert/key paths directly with "
                               "/server cert <cert> [key].")
            if emit is not None:
                emit(_f)
            return [_f]
        finding = F.Finding("srv.tlsconf", "TLS virtual host configuration", F.PASS,
                            F.SCOPE_SERVER, lines)
        if emit is not None:
            emit(finding)
        return [finding]

    def log_scan(self, emit: Optional[Callable[[F.Finding], None]] = None) -> List[F.Finding]:
        if (err := self._need_conn()):
            if emit is not None:
                emit(err)
            return [err]
        rc, so, se, fatal = self.run(
            "for f in /var/log/nginx/error.log /var/log/apache2/error.log "
            "/var/log/httpd/ssl_error_log; do "
            "if [ -r $f ]; then echo \"== $f\"; "
            "grep -iE 'ssl|certificate' $f 2>/dev/null | tail -n 8; fi; done")
        lines = [ln.rstrip()[:200] for ln in so.splitlines() if ln.strip()]
        if fatal:
            _f = F.Finding("srv.logs", "TLS-related service log entries", F.FAIL,
                           F.SCOPE_SERVER, [fatal])
            if emit is not None:
                emit(_f)
            return [_f]
        if not lines:
            _f = F.Finding("srv.logs", "TLS-related service log entries",
                           F.NOT_TESTED, F.SCOPE_SERVER,
                           ["no readable TLS log entries found for this account"],
                           recommendation="Re-run with an account that can read the "
                                          "web server error logs.")
            if emit is not None:
                emit(_f)
            return [_f]
        _f = F.Finding("srv.logs", "TLS-related service log entries", F.WARNING,
                       F.SCOPE_SERVER, lines)
        if emit is not None:
            emit(_f)
        return [_f]

    def nginx_scan(self, domain: str, port: int = 443,
                   emit: Optional[Callable[[F.Finding], None]] = None,
                   addresses: Tuple[str, ...] = ()) -> List[F.Finding]:
        """nginx configuration analysis for `domain:port`; `addresses` (what the
        domain resolves to) select the listen socket, as nginx does."""
        if (err := self._need_conn()):
            if emit is not None:
                emit(err)
            return [err]
        self._nginx_domain = domain
        self._service_cas = None      # CA certificates of the block's CA files
        self._password_file = None    # (value, resolved) | "" none configured | None unknown
        self._service_user = ""
        self.begin_scan()
        out: List[F.Finding] = []
        sources = ""

        def _add(f: F.Finding) -> F.Finding:
            list.append(out, f)
            if emit is not None:
                emit(f)
            return f
        d = self.discover_nginx()
        # a mismatch is FAIL only against the running instance's configuration
        # (or paths the operator saved); otherwise it is a qualified WARNING
        self.scan_context["conclusive"] = bool(d.conclusive or self.nginx_settings.manual)
        # nginx's master loads certificates and keys; non-root, its workers share it
        self._service_user = d.master.user if d.master else ""
        conf = _nginx_conf_finding(d, self.cfg.username)
        _add(conf)
        if d.level == nginx_discovery.LEVEL_NONE:
            return self._certificate_checks(d, None, out, _add, emit)
        sources = d.source
        scope = (f"scope: {'complete' if d.complete else 'INCOMPLETE'} configuration graph "
                 f"of {d.main_path} ({len(d.read_files)} file(s)), evidence level {d.level}")

        nodes = _parse_nginx_nodes(sources)
        raw_blocks = _collect_server_blocks(nodes)
        blocks = [_block_directives(b) for b in raw_blocks]
        ssl_blocks = []
        for dirs in blocks:
            listens = dirs.get("listen", [])
            if any("ssl" in a for a in listens) or "443" in _listen_ports(listens):
                ssl_blocks.append(dirs)
        _add(F.Finding(
            "nginx.blocks", "Nginx server blocks", F.PASS, F.SCOPE_SERVER,
            [f"server blocks total: {len(blocks)}, TLS-enabled: {len(ssl_blocks)}",
             scope,
             *[f"listen {' / '.join(' '.join(a) for a in b.get('listen', ['-']))} · "
               f"server_name {' '.join(n for a in b.get('server_name', []) for n in a) or '(none)'}"
               for b in ssl_blocks[:8]],
             *[f"not part of the configuration graph (not analysed): {path}"
               for path in d.discovered_only[:8]]],
            uncertainty=list(d.uncertainty) if not d.conclusive else []))

        match, how, notes = _match_nginx_server(blocks, domain, port, tuple(addresses))
        if not match:
            if d.conclusive:
                _add(F.Finding(
                    "nginx.domain", f"Nginx vhost for '{domain}'", F.WARNING,
                    F.SCOPE_SERVER, [f"no server block found: {how}", scope],
                    recommendation="TLS may be terminated elsewhere (load balancer, "
                                   "another process). Verify what answers on 443.",
                    target=self.cfg.host))
            else:
                _add(F.Finding(
                    "nginx.domain", f"Nginx vhost for '{domain}'", F.NOT_TESTED,
                    F.SCOPE_SERVER,
                    [f"no server block found in the analysed files: {how}", scope],
                    detail="An absence can only be concluded from the complete "
                           "configuration of the running nginx.",
                    uncertainty=[f"the analysed configuration is "
                                 f"{'a candidate' if d.level == nginx_discovery.LEVEL_CANDIDATE else 'incomplete'}"
                                 f", so it is not established that the running nginx has "
                                 f"no server block for port {port}", *d.uncertainty],
                    target=self.cfg.host))
            return self._certificate_checks(d, None, out, _add, emit)
        matched_dirs = match[0]
        self._inventory_blocks(d, blocks, ssl_blocks, nodes, matched_dirs, domain)
        names = [n for a in matched_dirs.get("server_name", []) for n in a]
        # wildcard/regex matches are normal; only fallbacks and conflicts warn
        status = F.WARNING if "fallback" in how or notes else F.PASS
        ev = [f"selected by: {how}",
              f"configuration evidence level: {d.level}"
              + ("" if d.complete else " (graph incomplete)"),
              f"matched server_name entry: {match[2]}",
              f"server block names: {', '.join(names) or '(none)'}",
              f"listen: {' / '.join(' '.join(a) for a in matched_dirs.get('listen', ['-']))}",
              *notes]
        if "fallback" in how:
            ev.append("nginx answered with a FALLBACK server block - the domain has "
                      "no dedicated vhost; clients may receive the wrong certificate")
        _add(F.Finding(
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
            _add(F.Finding(
                "nginx.protocols", "Nginx ssl_protocols", st, F.SCOPE_SERVER,
                [f"ssl_protocols {' '.join(prots)}"] +
                ([f"deprecated: {', '.join(legacy)}"] if legacy else
                 ["modern protocol set"]),
                recommendation="Restrict to 'TLSv1.2 TLSv1.3' unless legacy clients "
                               "must be supported." if legacy else "",
                target=self.cfg.host))
        else:
            _add(F.Finding(
                "nginx.protocols", "Nginx ssl_protocols", F.WARNING, F.SCOPE_SERVER,
                ["no ssl_protocols directive in the matched block - nginx/OS defaults "
                 "apply and vary between builds"],
                detail="Explicitly configuring 'ssl_protocols TLSv1.2 TLSv1.3;' avoids "
                       "surprises after upgrades.",
                target=self.cfg.host))
        ciphers = matched_dirs.get("ssl_ciphers", [])
        _add(F.Finding(
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
            _add(F.Finding(
                "nginx.certref", "ssl_certificate in matched vhost", F.PASS,
                F.SCOPE_SERVER,
                [f"ssl_certificate {cert_paths[0]}"
                 + (" (inherited from http{})" if "ssl_certificate" in inherited else ""),
                 f"ssl_certificate_key {key_paths[0] if key_paths else '(none)'}"
                 + (" (inherited from http{})" if "ssl_certificate_key" in inherited
                    else "")]
                + [f"ssl_certificate {c} / ssl_certificate_key {k or '(none)'}"
                   for c, k in list(zip(cert_paths, key_paths + [""] * len(cert_paths)))[1:]],
                target=self.cfg.host))
        if not cert_paths:
            _add(F.Finding(
                "nginx.certref", "ssl_certificate in matched vhost", F.WARNING,
                F.SCOPE_SERVER,
                ["the matched server block has no ssl_certificate directive"],
                recommendation="Check include files or a parent http{} certificate, "
                               "or TLS being terminated elsewhere.",
                target=self.cfg.host))
            self._ca_file_checks(d, matched_dirs, http_dirs, _add)
            return self._certificate_checks(d, None, out, _add, emit)
        cert_inh, key_inh = "ssl_certificate" in inherited, "ssl_certificate_key" in inherited
        pairs = [{"certificate": (c, cert_inh),
                  "key": (key_paths[i], key_inh) if i < len(key_paths) else None}
                 for i, c in enumerate(cert_paths)]
        mismatch = ""
        if len(cert_paths) != len(key_paths) and max(len(cert_paths), len(key_paths)) > 1:
            mismatch = (f"{len(cert_paths)} certificate{'s' if len(cert_paths) != 1 else ''} "
                        f"but {len(key_paths)} key{'s' if len(key_paths) != 1 else ''} "
                        "configured")
        self._ca_file_checks(d, matched_dirs, http_dirs, _add)
        pw = matched_dirs.get("ssl_password_file") or http_dirs.get("ssl_password_file")
        if pw and pw[-1]:
            resolved, _method, _problem = nginx_discovery.resolve_cert_path(
                pw[-1][0], nginx_discovery.conf_prefix(d))
            self._password_file = (pw[-1][0], resolved)
        else:
            self._password_file = ""
        return self._certificate_checks(d, pairs[0], out, _add, emit,
                                        extra_pairs=pairs[1:], mismatch=mismatch)

    _INVENTORY_LIMIT = 20

    def _inventory_blocks(self, d, blocks, ssl_blocks, nodes, selected, domain) -> None:
        """Every TLS block's first certificate into scan_context["inventory"]."""
        nd = nginx_discovery
        http_dirs = _http_level_directives(nodes)
        entries = []
        for dirs in ssl_blocks[:self._INVENTORY_LIMIT]:
            values = dirs.get("ssl_certificate") or http_dirs.get("ssl_certificate") or []
            if not values or not values[0]:
                continue
            resolved, _m, _p = nd.resolve_cert_path(values[0][0], nd.conf_prefix(d))
            entry = {"names": [n for a in dirs.get("server_name", []) for n in a],
                     "listen": [" ".join(a) for a in dirs.get("listen", [])],
                     "path": resolved or values[0][0], "selected": dirs is selected,
                     "sha256": "", "subject": "", "covers": None}
            data = None
            if resolved and self.nginx_probe().file_states([resolved]).get(resolved) == "readable":
                data, _why = self.read_public_file(resolved)
            parsed = certs.parse_cert_bytes(data) if data else None
            if parsed and parsed.certs:
                leaf = parsed.certs[0]
                entry.update(sha256=leaf.sha256, subject=leaf.subject,
                             covers=leaf.hostname_match(domain)[0])
            entries.append(entry)
        self.scan_context["inventory"] = entries
        self.scan_context["inventory_domain"] = domain
        self.scan_context["inventory_truncated"] = len(ssl_blocks) > self._INVENTORY_LIMIT

    def inventory_finding(self, presented_sha256: str = "") -> F.Finding:
        """`srv.inventory`: every configured certificate, the served one flagged."""
        title = "Certificates configured for the TLS service"
        entries = self.scan_context.get("inventory")
        if not entries:
            return F.Finding("srv.inventory", title, F.NOT_TESTED, F.SCOPE_SERVER,
                             ["no TLS server block certificates were read in this scan"],
                             target=self.cfg.host)
        domain = self.scan_context.get("inventory_domain", "")
        presented = presented_sha256.lower().replace(":", "")
        ev, warnings = [], []
        for e in entries:
            flags = [f for f, on in (("selected", e["selected"]),
                                     ("served", presented and e["sha256"] == presented),
                                     (f"covers {domain}", e["covers"])) if on]
            ev.append(f"server_name {' '.join(e['names']) or '(none)'} · listen "
                      f"{' / '.join(e['listen']) or '-'} · {e['path']}"
                      + (f" · {e['subject']} · sha256 {e['sha256'][:16]}…" if e["sha256"]
                         else " · certificate not read")
                      + (f" [{', '.join(flags)}]" if flags else ""))
            if e["covers"] and not e["selected"] and not (presented and
                                                          e["sha256"] == presented):
                warnings.append(f"another server block ({' '.join(e['names']) or 'unnamed'}) "
                                f"has a certificate covering {domain}: a different listener "
                                "or SNI order could serve it")
            if presented and e["sha256"] == presented and not e["selected"]:
                warnings.append(f"the presented certificate belongs to server block "
                                f"'{' '.join(e['names']) or '(none)'}', not the one selected "
                                f"for {domain}")
        if self.scan_context.get("inventory_truncated"):
            ev.append(f"first {self._INVENTORY_LIMIT} TLS server blocks listed")
        status = F.WARNING if warnings else F.PASS
        return F.Finding("srv.inventory", title, status, F.SCOPE_SERVER, ev + warnings,
                         recommendation="Check which server block should answer for this "
                                        "name; remove or align the others."
                         if warnings else "", target=self.cfg.host)

    _CA_DIRECTIVES = ("ssl_trusted_certificate", "ssl_client_certificate")

    def _ca_file_checks(self, d, matched_dirs, http_dirs, _add) -> None:
        """`cert.cafile` for each CA file the selected block uses (or inherits)."""
        nd = nginx_discovery
        for name in self._CA_DIRECTIVES:
            values = matched_dirs.get(name) or http_dirs.get(name) or []
            for args in values[:1]:
                if not args:
                    continue
                inherited = not matched_dirs.get(name)
                source = nd.directive_source(d, name, args[0], inherited)
                resolved, _method, problem = nd.resolve_cert_path(args[0], nd.conf_prefix(d))
                if not resolved:
                    _add(F.Finding("cert.cafile", "Root / CA bundle file", F.NOT_TESTED,
                                   F.SCOPE_SERVER, [f"{name} {args[0]} [{source}]",
                                                    f"not resolved: {problem}"],
                                   target=self.cfg.host))
                    continue
                state = self.nginx_probe().file_states([resolved]).get(resolved, "unsupported")
                data = None
                if state == "readable":
                    data, why = self.read_public_file(resolved)
                if data is None:
                    label = _PATH_STATE_LABELS.get(state, state)
                    _add(F.Finding("cert.cafile", "Root / CA bundle file", F.NOT_TESTED,
                                   F.SCOPE_SERVER, [f"{name} {resolved} [{source}]: {label}"],
                                   target=resolved))
                    continue
                parsed = certs.parse_cert_bytes(data)
                _add(chainval.ca_file_finding(parsed, resolved, F.SCOPE_SERVER,
                                              chainval.CA_SERVICE,
                                              source=f"{name}, {source}"))
                if parsed.ok and getattr(self, "_service_cas", None) is None:
                    self._service_cas = (parsed.certs, f"{name} {resolved}")

    def _resolve_values(self, d, values) -> Dict[str, Dict]:
        """Automatic resolution of one {"certificate"/"key": (value, inherited)} pair."""
        nd = nginx_discovery
        directive = {"certificate": "ssl_certificate", "key": "ssl_certificate_key"}
        cprefix = nd.conf_prefix(d)
        auto: Dict[str, Dict] = {}
        for kind, entry in (values or {}).items():
            if not entry:
                continue
            value, inherited = entry
            resolved, method, problem = nd.resolve_cert_path(value, cprefix)
            alt = ""
            if (resolved and not value.strip("'\"").startswith("/") and d.prefix
                    and d.prefix.rstrip("/") + "/" != cprefix):
                alt = posixpath.normpath(posixpath.join(d.prefix, value.strip("'\"")))
            auto[kind] = {"value": value, "resolved": resolved, "method": method,
                          "problem": problem, "alt": alt, "origin": "automatic discovery",
                          "source": nd.directive_source(d, directive[kind], value, inherited)}
        return auto

    def _certificate_checks(self, d, values, out, _add, emit, extra_pairs=(),
                            mismatch: str = "") -> List[F.Finding]:
        """nginx.path_resolution, then validation of the files that could be opened.

        `values` maps "certificate"/"key" to (configured value, inherited) from
        the selected block, or is None when discovery gave none. In manual mode
        the saved paths are validated and the automatic ones only compared.
        `extra_pairs` are further certificate/key pairs of the same block (an
        RSA + ECDSA configuration); `mismatch` says the counts differ.
        """
        settings = self.nginx_settings
        auto = self._resolve_values(d, values)
        chosen: Dict[str, Dict] = {}
        for kind, saved in (("certificate", settings.cert), ("key", settings.key)):
            if settings.manual and saved:
                chosen[kind] = {"value": saved, "resolved": saved, "problem": "",
                                "method": "saved manual setting", "alt": "",
                                "origin": "saved manual setting",
                                "source": settings.origin or "saved manual setting"}
            elif kind in auto:
                chosen[kind] = auto[kind]
        pairs = [(chosen, auto)] + [(a, a) for a in
                                    (self._resolve_values(d, v) for v in extra_pairs) if a]
        if not chosen and len(pairs) == 1:
            return out
        paths = set()
        for c, a in pairs:
            for r in list(c.values()) + list(a.values()):
                paths |= {x for x in (r["resolved"], r["alt"]) if x}
        states = self.nginx_probe().file_states(sorted(paths)) if paths else {}
        if len(pairs) == 1 and not mismatch:
            _add(self._path_resolution_finding(d, chosen, auto, states))
            return self._validate_pair(chosen, states, out, _add, emit)
        _add(self._pairs_finding(d, pairs, states, mismatch))
        for i, (c, _a) in enumerate(pairs, 1):
            label = (f"certificate pair {i} of {len(pairs)}: "
                     f"{(c.get('certificate') or {}).get('resolved') or '?'} + "
                     f"{(c.get('key') or {}).get('resolved') or '(no key)'}")

            def labelled(f, _label=label):
                f.evidence.insert(0, _label)
                _add(f)
            self._validate_pair(c, states, out, labelled, None)
        return out

    def _pairs_finding(self, d, pairs, states, mismatch: str) -> F.Finding:
        """One nginx.path_resolution listing every certificate/key pair."""
        parts = [self._path_resolution_finding(d, c, a, states) for c, a in pairs]
        rank = {F.PASS: 0, F.NOT_TESTED: 1, F.WARNING: 2, F.FAIL: 3}
        worst = max(parts, key=lambda f: rank[f.status])
        status = F.FAIL if mismatch else worst.status
        ev = [mismatch] if mismatch else []
        for i, f in enumerate(parts, 1):
            ev.append(f"pair {i}:")
            ev += [f"  {e}" for e in f.evidence]
        return F.Finding("nginx.path_resolution", "Certificate and key file paths", status,
                         F.SCOPE_SERVER, ev,
                         recommendation=("Configure one ssl_certificate_key for every "
                                         "ssl_certificate, in the same order."
                                         if mismatch else worst.recommendation),
                         uncertainty=[u for f in parts for u in f.uncertainty],
                         target=self.cfg.host)

    def _validate_pair(self, chosen, states, out, _add, emit) -> List[F.Finding]:
        """Validate one resolved certificate/key pair whose files could be opened."""
        cert, key = chosen.get("certificate"), chosen.get("key")
        cert_state = states.get(cert["resolved"], "") if cert and cert["resolved"] else ""
        key_state = states.get(key["resolved"], "") if key and key["resolved"] else ""
        if cert and cert_state == "readable":
            cert_path = cert["resolved"]
            key_path = key["resolved"] if key else ""
            self.last_configured_chain = []
            _add(self._chainfile_finding(cert_path))
            configured = self.last_configured_chain
            if configured:
                self._record_configured(cert_path, "", [c.sha256 for c in configured])
                _add(chainval.usage_finding(configured, F.SCOPE_SERVER, cert_path))
                validity = certpolicy.chain_validity_finding(configured, F.SCOPE_SERVER,
                                                             cert_path)
                if validity is not None:
                    _add(validity)
                _add(certpolicy.policy_finding(configured, F.SCOPE_SERVER, cert_path,
                                               certpolicy.anchor_ids(configured)))
                _add(chainval.trust_finding(configured, F.SCOPE_SERVER, cert_path,
                                            certs.load_root_anchors(),
                                            private=getattr(self, "_service_cas", None)))
                self.chain_facts[f"configured:{cert_path}"] = chainval.certificates_fact(
                    configured, "configured", certs.load_root_anchors(), cert_path,
                    private=getattr(self, "_service_cas", None))
            for f in self.scan_cert(cert_path, key_path, emit=None,
                                    domain=getattr(self, "_nginx_domain", None),
                                    states={cert_path: cert_state,
                                            **({key_path: key_state} if key_path else {})}):
                _add(f)
            reader = getattr(self, "_service_user", "")
            for f in self.permissions([(cert_path, "certificate")]
                                      + ([(key_path, "key")] if key_path else []), reader):
                _add(f)
            self.nginx_cert_path, self.nginx_key_path = cert_path, key_path
            return out
        reason = ("certificate file could not be opened: "
                  + (_PATH_STATE_LABELS.get(cert_state, cert_state) if cert_state else
                     (cert["problem"] if cert else "no ssl_certificate to check")))
        target = cert["resolved"] if cert and cert["resolved"] else self.cfg.host
        _add(F.Finding("nginx.chainfile", "Chain completeness of ssl_certificate file",
                       F.NOT_TESTED, F.SCOPE_SERVER, [reason], target=target))
        _add(F.Finding("srv.cert", "Server certificate", F.NOT_TESTED, F.SCOPE_SERVER,
                       [reason], target=target))
        if cert and cert["resolved"]:
            self.nginx_cert_path = cert["resolved"]
            self.nginx_key_path = key["resolved"] if key else ""
        return out

    def _path_resolution_finding(self, d, chosen, auto, states) -> F.Finding:
        nd = nginx_discovery
        ev: List[str] = []
        uncertainty: List[str] = []
        missing = unreadable_cert = unresolvable = disagree = False
        for kind in ("certificate", "key"):
            ref = chosen.get(kind)
            if ref is None:
                if kind == "key":
                    ev.append("key: no ssl_certificate_key configured")
                continue
            ev.append(f"{kind}: {ref['value']}  [{ref['source']}]")
            if ref["problem"]:
                ev.append(f"  not resolved: {ref['problem']}")
                unresolvable = unresolvable or kind == "certificate"
                continue
            state = states.get(ref["resolved"], "unsupported")
            ev.append(f"  resolved: {ref['resolved']}  ({ref['method']})")
            ev.append(f"  {_PATH_STATE_LABELS.get(state, state)}")
            if state in ("missing", "notfile"):
                missing = True
                alt = ref.get("alt")
                if alt and states.get(alt) in ("readable", "denied"):
                    ev.append(f"  {alt} exists, but nginx resolves {ref['value']} against "
                              f"the configuration prefix {nd.conf_prefix(d)}, so it would "
                              "not open this file")
            elif state in ("denied", "unreachable", "unsupported"):
                if kind == "certificate":
                    unreadable_cert = True
                else:
                    ev.append("  the key pairing is not tested (the file cannot be read "
                              "by this account; normal for root-only keys)")
            other = auto.get(kind)
            if (ref["origin"] == "saved manual setting" and other and other["resolved"]
                    and other["resolved"] != ref["resolved"]):
                disagree = True
                ev.append(f"  automatic discovery resolves {other['value']} to "
                          f"{other['resolved']} ({_PATH_STATE_LABELS.get(states.get(other['resolved'], ''), '?')}); "
                          "the saved path is the one validated")
        manual = any(r["origin"] == "saved manual setting" for r in chosen.values())
        ev.append("origin: " + ("saved manual setting" + (f" ({self.nginx_settings.origin})"
                                                          if self.nginx_settings.origin else "")
                                if manual else
                                f"automatic discovery (configuration evidence level {d.level})"))
        if unresolvable or unreadable_cert:
            status = F.NOT_TESTED
        elif missing:
            status = F.FAIL if (d.conclusive and not manual) else F.WARNING
            if not manual and not d.conclusive:
                uncertainty.append("the configuration these paths come from is not "
                                   "confirmed as the running nginx's, so a missing file "
                                   "does not prove a broken server")
        elif disagree:
            status = F.WARNING
        else:
            status = F.PASS
        if manual:
            rec = ("" if status == F.PASS else
                   "Correct the saved paths (/server config set) or return to automatic "
                   "discovery (/server config clear).")
        else:
            rec = ("" if status == F.PASS else
                   "If this server uses a custom layout, save its paths: /server config set "
                   "--cert <path> --key <path>")
        return F.Finding("nginx.path_resolution", "Certificate and key file paths", status,
                         F.SCOPE_SERVER, ev, recommendation=rec, uncertainty=uncertainty,
                         target=self.cfg.host)

    _CERT_FILE_LIMIT = 1 << 20

    def read_public_file(self, path: str) -> Tuple[Optional[bytes], str]:
        """Exact bytes of a (public) file on the server, or (None, reason).

        Read as base64 so binary content survives the text channel; `cat` is
        the fallback for hosts without `base64`.  Never used for key files.
        """
        q = shlex.quote(path)
        rc, out, err, fatal = self.run(
            f"head -c {self._CERT_FILE_LIMIT} -- {q} | base64; echo \"@@SSLDOCTOR rc=$?\"")
        if not fatal and "@@SSLDOCTOR rc=0" in out:
            body = "".join(ln.strip() for ln in out.splitlines()
                           if ln.strip() and not ln.startswith("@@SSLDOCTOR"))
            try:
                return base64.b64decode(body, validate=True), ""
            except (ValueError, binascii.Error):
                pass
        rc, out, err, fatal = self.run(f"cat {q} 2>&1")
        if fatal or rc != 0:
            return None, (fatal or err.strip() or out.strip())[:200]
        return out.encode("utf-8", "replace"), ""

    def _chainfile_finding(self, cert_path: str) -> F.Finding:
        """Linkage of the ssl_certificate file: leaf first, each issued by the next.

        Reads only the public certificate file (never the key).  The file is
        parsed strictly: a truncated or corrupt block fails the file even when
        other blocks decode.
        """
        title = "Chain completeness of ssl_certificate file"
        data, why = self.read_public_file(cert_path)
        if data is None:
            return F.Finding("nginx.chainfile", title, F.FAIL, F.SCOPE_SERVER,
                             [f"{cert_path}: certificate file could not be read", why],
                             recommendation="Point ssl_certificate at a PEM file that "
                                            "holds the certificate (and its "
                                            "intermediates).", target=cert_path)
        parsed = certs.parse_cert_bytes(data)
        notes = ([f"{cert_path}: a private-key block is present and was not read"]
                 if parsed.key_blocks else [])
        if parsed.problems:
            return F.Finding(
                "nginx.chainfile", title, F.FAIL, F.SCOPE_SERVER,
                [f"{cert_path}: {p}" for p in parsed.problems]
                + [f"{len(parsed.certs)} certificate block(s) decoded; the file is not "
                   "usable as it is"] + notes,
                recommendation="Re-create the file from the certificates your CA issued: "
                               "the leaf, then the intermediate(s), each a complete "
                               "-----BEGIN/END CERTIFICATE----- block.",
                target=cert_path)
        if not parsed.certs or parsed.format == certs.FMT_DER:
            # the caller checked the file is readable: this is bad content, not a
            # missing intermediate and not a path problem
            if parsed.format == certs.FMT_DER:
                ev = [f"{cert_path}: the certificate is DER-encoded; nginx loads only PEM"]
                rec = (f"Convert it: openssl x509 -inform DER -in {cert_path} "
                       "-out <file>.pem, then point ssl_certificate at the PEM file.")
            elif parsed.format in (certs.FMT_UNKNOWN, certs.FMT_EMPTY):
                ev = [f"{cert_path}: no PEM certificate in the file",
                      "the content does not contain a -----BEGIN CERTIFICATE----- block"]
                rec = ("Point ssl_certificate at a PEM file that holds the certificate "
                       "(and its intermediates).")
            else:
                ev = [f"{cert_path}: no PEM certificate in the file",
                      f"detected format: {parsed.format}", parsed.error() or ""]
                rec = ("Point ssl_certificate at a PEM file that holds the certificate "
                       "(and its intermediates).")
            return F.Finding("nginx.chainfile", title, F.FAIL, F.SCOPE_SERVER,
                             [e for e in ev + notes if e], recommendation=rec,
                             target=cert_path)
        chain = parsed.certs
        self.last_configured_chain = chain
        roles, wrong_leaf, structure = chainval.file_structure(chain)
        a = certs.assess_chain(chain, certs.load_root_anchors())
        ev = [f"{cert_path}: {len(chain)} certificate(s) in file",
              *chainval.inventory_lines(chain, roles), *a.evidence, *wrong_leaf,
              *structure, *notes]
        if wrong_leaf:
            return F.Finding("nginx.chainfile", title, F.FAIL, F.SCOPE_SERVER, ev,
                             recommendation="nginx serves the first certificate of the "
                                            "file: put the server (leaf) certificate "
                                            "first, then its intermediate(s).",
                             target=cert_path, failure_kind=chainval.FAIL_WRONG_LEAF)
        status, kind, uncertainty = chainval.chain_verdict(a)
        if status == F.PASS and structure:
            status, kind = F.WARNING, chainval.FAIL_HYGIENE
        rec = {
            chainval.FAIL_SIGNATURE:
                "A certificate in the file did not sign the one before it, or may not "
                "issue certificates: replace the intermediate(s) with the ones your CA "
                "issued for this certificate, leaf first.",
            chainval.FAIL_MISORDERED:
                "Order the file as: leaf first, then the intermediate(s) that issued it; "
                "replace any intermediate that did not issue the certificate above it.",
            chainval.FAIL_INCOMPLETE:
                "Append the issuing intermediate certificate(s) after the leaf in the "
                "ssl_certificate file and reload nginx - clients without a cached "
                "intermediate fail otherwise.",
            chainval.FAIL_HYGIENE:
                "Remove repeated and unrelated certificates: the file should hold the "
                "leaf, then the intermediate(s) that issued it, once each.",
        }.get(kind, "")
        return F.Finding("nginx.chainfile", title, status, F.SCOPE_SERVER, ev,
                         recommendation=rec, target=cert_path, failure_kind=kind,
                         uncertainty=uncertainty)

    # ---------------------------------------------------------------- services
    def service_scan(self, domain: str, port: int = 443,
                     emit: Optional[Callable[[F.Finding], None]] = None) -> List[F.Finding]:
        """Which process serves TLS on `port`, its configuration test, reload
        state and renewal tooling; Apache/HAProxy certificate paths.  Read-only:
        test modes only, never a reload, restart or signal."""
        if (err := self._need_conn()):
            if emit is not None:
                emit(err)
            return [err]
        out: List[F.Finding] = []

        def _add(f: F.Finding) -> F.Finding:
            out.append(f)
            if emit is not None:
                emit(f)
            return f

        probe = self.nginx_probe()
        d = self.discover_nginx()
        ps_text, now, _why = probe.processes()
        procs = services.parse_ps(ps_text or "")
        others = services.detect_services(procs)
        _add(self._listener_finding(probe.listeners(port), port, d, others))
        sites: List[Tuple[services.Service, services.TlsSite]] = []
        if d.master is not None:
            _add(self._nginx_configtest(probe, d))
        for svc in others:
            _add(self._other_configtest(probe, svc))
            site = self._other_site(probe, svc, domain, port, _add)
            if site is not None:
                sites.append((svc, site))
        cert_paths = [e["path"] for e in self.scan_context["configured"]]
        key_paths = list(self.scan_context.get("keys", []))
        if d.master is not None and cert_paths:
            _add(self._reload_finding(probe, "nginx", now,
                                      services.children_elapsed(procs, d.master.pid),
                                      cert_paths + key_paths, d.master.unit or ""))
        for svc, site in sites:
            _add(self._reload_finding(probe, svc.kind, now, svc.children,
                                      [p for p in (site.cert, site.key, site.chain) if p],
                                      ""))
        all_certs = cert_paths + [site.cert for _s, site in sites if site.cert]
        _add(self._renewal_finding(probe, all_certs))
        return out

    def _listener_finding(self, text, port, d, others) -> F.Finding:
        title = "Process that terminates TLS on the target port"
        state, owners = services.parse_listeners(text, port)
        binaries = ([f"nginx master pid {m.pid}" for m in d.masters[:3]]
                    + [f"{s.kind} pid {s.pid}" for s in others[:3]])
        if state == services.LISTENER_UNAVAILABLE:
            return F.Finding("srv.service", title, F.NOT_TESTED, F.SCOPE_SERVER,
                             ["neither ss nor netstat is available"] + binaries,
                             target=self.cfg.host)
        if state == services.LISTENER_NONE:
            return F.Finding("srv.service", title, F.WARNING, F.SCOPE_SERVER,
                             [f"no local listener on :{port}; TLS may be terminated "
                              "elsewhere"] + binaries,
                             recommendation="Find the load balancer, proxy or other host "
                                            "that answers on this port.",
                             target=self.cfg.host, observation="no-local-listener")
        if state == services.LISTENER_HIDDEN:
            return F.Finding("srv.service", title, F.NOT_TESTED, F.SCOPE_SERVER,
                             [f"something listens on :{port}, but the listener owner is not "
                              "visible to this account"] + binaries,
                             target=self.cfg.host, failure_kind="permission-denied")
        kinds = sorted({services.kind_of(name) for name, _pid in owners})
        names = ", ".join(f"{n} (pid {pid})" for n, pid in owners)
        if all(kinds) and kinds:
            return F.Finding("srv.service", title, F.PASS, F.SCOPE_SERVER,
                             [f"{names} listens on :{port}"], target=self.cfg.host)
        unknown = sorted({n for n, _pid in owners if not services.kind_of(n)})
        return F.Finding("srv.service", title, F.WARNING, F.SCOPE_SERVER,
                         [f"TLS on :{port} is served by {', '.join(unknown)}, which SSL "
                          "Doctor does not analyse", f"listeners: {names}"],
                         recommendation="Check that service's own TLS configuration; the "
                                        "nginx/Apache/HAProxy results do not describe this "
                                        "endpoint.",
                         target=self.cfg.host, observation="listener-unsupported")

    def _configtest_finding(self, service: str, argv: List[str], rc, output) -> F.Finding:
        title = "Native configuration test of the TLS service"
        verdict, lines = services.classify_config_test(rc, output)
        command = " ".join(argv)
        if verdict == "pass":
            return F.Finding("srv.configtest", title, F.PASS, F.SCOPE_SERVER,
                             [f"{command}: exit status 0", *lines], target=self.cfg.host)
        if verdict == "permission":
            return F.Finding("srv.configtest", title, F.NOT_TESTED, F.SCOPE_SERVER,
                             [f"{command}: exit status {rc}", "configuration test needs read "
                              "access to files this account cannot open", *lines],
                             target=self.cfg.host, failure_kind="permission-denied")
        if verdict == "unknown":
            return F.Finding("srv.configtest", title, F.NOT_TESTED, F.SCOPE_SERVER,
                             [f"{command}: no exit status", *lines],
                             target=self.cfg.host, failure_kind="command-failed")
        if verdict == "inconclusive":
            return F.Finding("srv.configtest", title, F.NOT_TESTED, F.SCOPE_SERVER,
                             [f"{command}: exit status {rc} without a recognised error "
                              "message", *lines],
                             target=self.cfg.host, failure_kind="command-failed")
        return F.Finding("srv.configtest", title, F.FAIL, F.SCOPE_SERVER,
                         [f"{command}: exit status {rc}", *lines],
                         recommendation=f"Fix the {service} configuration error shown; the "
                                        "running service keeps its old configuration until "
                                        "a reload succeeds.", target=self.cfg.host)

    def _nginx_configtest(self, probe, d) -> F.Finding:
        title = "Native configuration test of the TLS service"
        if not d.executable or not d.executable_trusted:
            reason = next((lim for lim in d.limitations if "executable" in lim),
                          "the nginx executable is not known")
            return F.Finding("srv.configtest", title, F.NOT_TESTED, F.SCOPE_SERVER,
                             [f"nginx -t not run: {reason}"], target=self.cfg.host)
        argv = [d.executable]
        if d.master.prefix:
            argv += ["-p", d.master.prefix]
        if d.master.conf:
            argv += ["-c", d.master.conf]
        argv.append("-t")
        rc, output = probe.config_test(argv)
        return self._configtest_finding("nginx", argv, rc, output)

    def _trusted(self, probe, exe: str) -> Tuple[bool, str]:
        if not exe.startswith("/") or not nginx_discovery.SAFE_PATH.match(exe):
            return False, f"executable {exe!r} is not an absolute, safe path"
        st = probe.exe_stat(exe)
        if st is None:
            return False, f"executable {exe} could not be inspected"
        uid, mode, kind = st
        if uid != 0 or mode & 0o022 or kind != "regular file":
            return False, (f"executable {exe} is not trusted (owner uid {uid}, mode "
                           f"{mode:o}, {kind}); it is not run")
        return True, ""

    def _other_configtest(self, probe, svc) -> F.Finding:
        title = "Native configuration test of the TLS service"
        exe = svc.exe
        if svc.kind == "apache" and posixpath.basename(exe) == "apache2":
            # Debian's apache2 needs the environment apache2ctl sets up
            exe = posixpath.join(posixpath.dirname(exe), "apache2ctl")
        ok, why = self._trusted(probe, exe)
        if not ok:
            return F.Finding("srv.configtest", title, F.NOT_TESTED, F.SCOPE_SERVER,
                             [f"{svc.kind} configuration test not run: {why}"],
                             target=self.cfg.host)
        if svc.kind == "apache":
            argv = [exe, "-t"] + (["-f", svc.configs[0]] if svc.configs and
                                  posixpath.basename(exe) != "apache2ctl" else [])
        else:
            argv = [exe, "-c"] + [a for c in svc.configs for a in ("-f", c)]
        rc, output = probe.config_test(argv)
        return self._configtest_finding(svc.kind, argv, rc, output)

    _APACHE_DEFAULTS = {"apache2": ("/etc/apache2", "/etc/apache2/apache2.conf"),
                        "httpd": ("/etc/httpd", "/etc/httpd/conf/httpd.conf")}

    def _other_site(self, probe, svc, domain, port, _add):
        """The Apache vhost / HAProxy bind answering domain:port, reported with
        its paths; certificate checks run on the files that can be opened."""
        title = "TLS virtual host configuration"
        if svc.kind == "apache":
            root, main = self._APACHE_DEFAULTS.get(posixpath.basename(svc.exe),
                                                   self._APACHE_DEFAULTS["httpd"])
            main = svc.configs[0] if svc.configs else main
            files = self._read_tree(probe, main, root)
            sites, globals_ = services.parse_apache(files)
        else:
            files = self._read_tree(probe, None, "", svc.configs or
                                    ["/etc/haproxy/haproxy.cfg"])
            sites, globals_ = services.parse_haproxy(files), {}
        site = services.select_site(sites, domain, port)
        if site is None:
            _add(F.Finding("srv.tlsconf", title, F.NOT_TESTED, F.SCOPE_SERVER,
                           [f"{svc.kind}: no TLS site for {domain}:{port} in "
                            f"{', '.join(files) or 'the readable configuration'}"],
                           uncertainty=["the configuration was read without full include "
                                        "semantics; a site may be defined elsewhere"],
                           target=self.cfg.host))
            return None
        paths = [p for p in (site.cert, site.key, site.chain) if p]
        states = probe.file_states(paths)
        ev = [f"{svc.kind} site {site.addr}:{site.port} "
              f"{' '.join(site.names) or '(no name)'} [{site.source}]"]
        labels = {"certificate": site.cert, "key": site.key, "chain": site.chain}
        for role, path in labels.items():
            if path:
                ev.append(f"{role}: {path} ({_PATH_STATE_LABELS.get(states.get(path), states.get(path))})")
        if svc.kind == "apache" and "sslpassphrasedialog" in globals_:
            ev.append(f"SSLPassPhraseDialog {globals_['sslpassphrasedialog']}")
        missing = [p for p in paths if states.get(p) in ("missing", "notfile")]
        _add(F.Finding("srv.tlsconf", title, F.WARNING if missing else F.PASS,
                       F.SCOPE_SERVER, ev,
                       uncertainty=["the configuration was read without full include "
                                    "semantics (candidate evidence)"],
                       recommendation="Correct the certificate/key path in the "
                                      f"{svc.kind} configuration." if missing else "",
                       target=self.cfg.host))
        if site.cert and states.get(site.cert) == "readable":
            for f in self.scan_cert(site.cert, site.key or "", domain=domain,
                                    states={p: states.get(p, "") for p in paths}):
                _add(f)
            for f in self.permissions([(site.cert, "certificate")]
                                      + ([(site.key, "key")] if site.key else []),
                                      svc.user):
                _add(f)
        return site

    def _read_tree(self, probe, main, root, mains=None) -> Dict[str, str]:
        """Main configuration file(s) plus Include/IncludeOptional, bounded."""
        files: Dict[str, str] = {}
        queue = list(mains or [main])
        rounds = 0
        while queue and rounds < 3 and len(files) < 60:
            rounds += 1
            records = probe.read([q for q in queue if q])
            queue = []
            for rec in records:
                if rec.state != nginx_discovery.READ or rec.path in files:
                    continue
                files[rec.path] = rec.content
                for inc in services.apache_includes(rec.content):
                    base = services.apache_server_root(rec.content, root) or root
                    pattern = inc if inc.startswith("/") else posixpath.join(base, inc)
                    if nginx_discovery.safe_pattern(pattern):
                        queue.append(pattern)
        return files

    def _reload_finding(self, probe, service, now, workers, paths, unit) -> F.Finding:
        title = "Reload state of the service after certificate changes"
        mtimes = probe.mtimes(paths) if paths else {}
        state, ev = services.reload_state(now, workers, mtimes)
        errors = services.reload_errors(probe.journal(unit)) if unit else []
        ev = [f"{service}: {e}" for e in ev] + [f"journal ({unit}): {e}" for e in errors]
        if state == "stale":
            return F.Finding("srv.reload", title, F.WARNING, F.SCOPE_SERVER,
                             ev + [f"certificate changed after the running workers "
                                   f"started; a reload is needed for {service} to serve it"],
                             recommendation=f"Reload {service} (SSL Doctor never does it) "
                                            "after checking its configuration test passes.",
                             target=self.cfg.host)
        if state == "unknown":
            return F.Finding("srv.reload", title, F.NOT_TESTED, F.SCOPE_SERVER,
                             ["reload state unknown"] + ev, target=self.cfg.host)
        if errors:
            return F.Finding("srv.reload", title, F.WARNING, F.SCOPE_SERVER, ev,
                             recommendation="Read the reload errors above; the service may "
                                            "still run an older configuration.",
                             target=self.cfg.host)
        return F.Finding("srv.reload", title, F.PASS, F.SCOPE_SERVER, ev,
                         target=self.cfg.host)

    def _renewal_finding(self, probe, cert_paths) -> F.Finding:
        title = "Renewal tooling that manages the configured certificate"
        r = services.parse_renewal(probe.renewal())
        state, ev = services.renewal_for(r, cert_paths, probe.realpaths(cert_paths))
        if state == "managed":
            return F.Finding("srv.renewal", title, F.PASS, F.SCOPE_SERVER, ev,
                             target=self.cfg.host)
        if state in ("unscheduled", "unlinked"):
            return F.Finding("srv.renewal", title, F.WARNING, F.SCOPE_SERVER, ev,
                             recommendation="Make sure something renews this certificate "
                                            "before it expires, and reloads the service.",
                             target=self.cfg.host)
        return F.Finding("srv.renewal", title, F.NOT_TESTED, F.SCOPE_SERVER,
                         ["no renewal tooling found"] + ev, target=self.cfg.host)

    def begin_scan(self, conclusive: bool = True) -> None:
        """Start a new comparison context: only certificates read from now on count.

        `conclusive` says the configuration being read is the running instance's,
        which a FAIL comparison needs.
        """
        self.scan_context = {"configured": [], "conclusive": conclusive, "inventory": [],
                             "keys": []}
        self.last_remote_cert_sha256 = ""
        self.chain_facts = {}
        self._password_file = None        # unknown until a configuration is analysed

    def _record_configured(self, path: str, leaf: str, chain: List[str]) -> None:
        for entry in self.scan_context["configured"]:
            if entry["path"] == path:
                entry["leaf"] = leaf or entry["leaf"]
                entry["chain"] = chain or entry["chain"]
                return
        self.scan_context["configured"].append({"path": path, "leaf": leaf, "chain": chain})

    def compare_configured_vs_presented(self, presented_sha256: str,
                                        emit: Optional[Callable[[F.Finding], None]] = None,
                                        presented_chain: Optional[List[str]] = None,
                                        presented_from: str = "") -> F.Finding:
        """Compare the presented leaf (and chain) with every configured certificate
        read in this scan; a fingerprint from an earlier command never counts."""
        def done(f: F.Finding) -> F.Finding:
            if emit is not None:
                emit(f)
            return f
        title = "Configured vs presented certificate"
        if (err := self._need_conn()):
            return done(err)
        configured = [e for e in self.scan_context["configured"] if e["leaf"]]
        if not configured:
            return done(F.Finding(
                "srv.compare", title, F.NOT_TESTED, F.SCOPE_SERVER,
                ["configured certificate not read in this scan - run /server cert "
                 "<path> or /server nginx first"]))
        if not presented_sha256:
            return done(F.Finding(
                "srv.compare", title, F.NOT_TESTED, F.SCOPE_SERVER,
                ["no network TLS check has run yet - run /tls <host> [port] first"]))
        presented = presented_sha256.lower().replace(":", "")
        vantage = [f"presented chain captured from {presented_from}"] if presented_from else []
        match = next((e for e in configured if e["leaf"] == presented), None)
        if match:
            ev = [f"the server presents the certificate of {match['path']}",
                  f"sha256: {presented}", *vantage]
            if len(configured) > 1:
                ev.append(f"{len(configured)} certificates are configured for this block; "
                          "clients that negotiate another key type get another one")
            diff = _chain_difference(match["chain"], presented_chain or [])
            if diff:
                return done(F.Finding(
                    "srv.compare", title, F.WARNING, F.SCOPE_SERVER, ev + [diff],
                    recommendation="The running service sends a different chain than the "
                                   "configured file: reload it after changing the file, "
                                   "or check what terminates TLS in front of it.",
                    target=self.cfg.host))
            return done(F.Finding("srv.compare", title, F.PASS, F.SCOPE_SERVER, ev,
                                  target=self.cfg.host))
        ev = [f"configured: {e['path']} sha256 {e['leaf']}" for e in configured]
        ev += [f"network-presented sha256: {presented}", *vantage,
               "the server is NOT serving any certificate found in its configuration"]
        rec = ("Possible causes: the service was not reloaded after a cert change, a "
               "different vhost/SNI answers, or a load balancer terminates TLS elsewhere.")
        if self.scan_context.get("conclusive", True):
            return done(F.Finding("srv.compare", title, F.FAIL, F.SCOPE_SERVER, ev,
                                  recommendation=rec, target=self.cfg.host))
        return done(F.Finding(
            "srv.compare", title, F.WARNING, F.SCOPE_SERVER, ev, recommendation=rec,
            uncertainty=["the configuration read is not confirmed as the running "
                         "instance's, so the mismatch may come from another configuration"],
            target=self.cfg.host))


def _chain_difference(configured: List[str], presented: List[str]) -> str:
    """First difference between the configured file's and the presented chain's
    fingerprints, as an evidence line ('' when equal or unknown)."""
    if not configured or not presented:
        return ""
    for i in range(max(len(configured), len(presented))):
        c = configured[i] if i < len(configured) else ""
        p = presented[i] if i < len(presented) else ""
        if c == p:
            continue
        pos = i + 1
        if not p:
            return (f"position {pos} differs: configured {c[:16]}… is not presented "
                    "(missing)")
        if not c:
            return (f"position {pos} differs: presented {p[:16]}… is not in the "
                    "configured file (added)")
        return f"position {pos} differs: configured {c[:16]}…, presented {p[:16]}… (replaced)"
    return ""


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
