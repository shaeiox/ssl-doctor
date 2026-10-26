"""Which service terminates TLS, and what its runtime says - read-only.

Pure functions over probe output: the listening socket table, process
titles (nginx, Apache httpd, HAProxy), Apache and HAProxy configuration,
the native configuration test's exit status, reload evidence (certificate
mtimes vs worker start) and renewal tooling.  Nothing here runs a command;
`server.ServerSession.service_scan` feeds it from the probe.  Nothing ever
reloads, restarts or signals a service.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

SUPPORTED = ("nginx", "apache", "haproxy")
_KIND_OF_BINARY = {"nginx": "nginx", "apache2": "apache", "httpd": "apache",
                   "haproxy": "haproxy"}

LISTENER_OWNED = "owned"
LISTENER_HIDDEN = "not-visible"     # sockets listed, owners not shown to this account
LISTENER_NONE = "none"
LISTENER_UNAVAILABLE = "unavailable"


# ---------------------------------------------------------------- processes

@dataclass
class Proc:
    pid: int
    ppid: int
    user: str
    elapsed: Optional[int]
    args: List[str]

    @property
    def name(self) -> str:
        first = self.args[0] if self.args else ""
        if first.startswith("nginx:"):
            return "nginx"
        return posixpath.basename(first.rstrip(":"))


def parse_ps(text: str) -> List[Proc]:
    """`ps -eo pid=,ppid=,user=,etimes=,args=` lines."""
    out = []
    for line in (text or "").splitlines():
        parts = line.split(None, 4)
        if len(parts) < 5 or not (parts[0].isdigit() and parts[1].isdigit()):
            continue
        try:
            args = shlex.split(parts[4])
        except ValueError:
            args = parts[4].split()
        out.append(Proc(int(parts[0]), int(parts[1]), parts[2],
                        int(parts[3]) if parts[3].isdigit() else None, args))
    return out


@dataclass
class Service:
    kind: str                       # nginx | apache | haproxy
    pid: int
    user: str
    exe: str
    configs: List[str] = field(default_factory=list)
    elapsed: Optional[int] = None
    children: List[int] = field(default_factory=list)     # child etimes (seconds)


def detect_services(procs: List[Proc]) -> List[Service]:
    """Apache httpd and HAProxy master processes (nginx has its own discovery)."""
    by_pid = {p.pid: p for p in procs}
    found = []
    for p in procs:
        kind = _KIND_OF_BINARY.get(p.name)
        if kind not in ("apache", "haproxy"):
            continue
        parent = by_pid.get(p.ppid)
        if parent is not None and _KIND_OF_BINARY.get(parent.name) == kind:
            continue                                     # a worker, not the master
        configs = [p.args[i + 1] for i, a in enumerate(p.args[:-1]) if a == "-f"]
        found.append(Service(kind, p.pid, p.user, p.args[0] if p.args else "", configs,
                             p.elapsed,
                             [c.elapsed for c in procs
                              if c.ppid == p.pid and c.elapsed is not None]))
    return found


def children_elapsed(procs: List[Proc], pid: int) -> List[int]:
    return [c.elapsed for c in procs if c.ppid == pid and c.elapsed is not None]


# ---------------------------------------------------------------- listeners

_SS_USERS = re.compile(r'\("([^"]+)",pid=(\d+)')
_NETSTAT_OWNER = re.compile(r"\s(\d+)/(\S+)")


def parse_listeners(text: Optional[str], port: int) -> Tuple[str, List[Tuple[str, int]]]:
    """(state, [(process name, pid)]) for TCP listeners on `port`.

    `text` is `ss -H -ltnp` or `netstat -ltnp` output; None when neither ran.
    """
    if text is None:
        return LISTENER_UNAVAILABLE, []
    rows = []
    for line in text.splitlines():
        fields = line.split()
        local = next((f for f in fields if re.search(r":\d+$", f)), "")
        if not local or local.rsplit(":", 1)[1] != str(port):
            continue
        if "LISTEN" not in line and not line.startswith("tcp"):
            continue
        rows.append(line)
    if not rows:
        return LISTENER_NONE, []
    owners: List[Tuple[str, int]] = []
    for line in rows:
        owners += [(name, int(pid)) for name, pid in _SS_USERS.findall(line)]
        m = _NETSTAT_OWNER.search(line)
        if m:
            owners.append((m.group(2).split(":")[0], int(m.group(1))))
    seen, unique = set(), []
    for o in owners:
        if o not in seen:
            seen.add(o)
            unique.append(o)
    return (LISTENER_OWNED, unique) if unique else (LISTENER_HIDDEN, [])


def kind_of(process_name: str) -> str:
    return _KIND_OF_BINARY.get(process_name, "")


# ---------------------------------------------------------------- Apache

@dataclass
class TlsSite:
    """One TLS endpoint configuration: an Apache vhost or a HAProxy bind."""
    service: str
    addr: str
    port: str
    names: List[str]
    cert: str = ""
    key: str = ""
    chain: str = ""
    source: str = ""                # file:line of the block / bind


_APACHE_DIRECTIVE = re.compile(r"^\s*(\w+)\s+(.*?)\s*$")


def apache_includes(text: str) -> List[str]:
    return [m.group(2).strip().strip('"\'') for m in
            (_APACHE_DIRECTIVE.match(ln) for ln in text.splitlines())
            if m and m.group(1).lower() in ("include", "includeoptional")]


def apache_server_root(text: str, default: str) -> str:
    for ln in text.splitlines():
        m = _APACHE_DIRECTIVE.match(ln)
        if m and m.group(1).lower() == "serverroot":
            return m.group(2).strip().strip('"\'')
    return default


def parse_apache(files: Dict[str, str]) -> Tuple[List[TlsSite], Dict[str, str]]:
    """TLS virtual hosts and global SSL directives from Apache files (in order)."""
    sites: List[TlsSite] = []
    globals_: Dict[str, str] = {}
    for path, text in files.items():
        current: Optional[TlsSite] = None
        for no, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            low = stripped.lower()
            if low.startswith("<virtualhost"):
                addrs = stripped[len("<virtualhost"):].rstrip(">").split()
                addr, _, port = (addrs[0] if addrs else "*:80").rpartition(":")
                current = TlsSite("apache", addr or "*", port or "80", [],
                                  source=f"{path}:{no}")
                continue
            if low.startswith("</virtualhost"):
                if current and current.cert:
                    sites.append(current)
                current = None
                continue
            m = _APACHE_DIRECTIVE.match(stripped)
            if not m:
                continue
            name, value = m.group(1).lower(), m.group(2).strip().strip('"\'')
            if current is None:
                if name in ("sslpassphrasedialog", "sslcertificatefile",
                            "sslcertificatekeyfile"):
                    globals_[name] = value
                continue
            if name in ("servername", "serveralias"):
                current.names += value.split()
            elif name == "sslcertificatefile":
                current.cert = value
            elif name == "sslcertificatekeyfile":
                current.key = value
            elif name == "sslcertificatechainfile":
                current.chain = value
    return sites, globals_


# ---------------------------------------------------------------- HAProxy

def parse_haproxy(files: Dict[str, str]) -> List[TlsSite]:
    """`bind ... ssl crt <file|dir> ...` lines, with `crt-base` applied."""
    sites = []
    for path, text in files.items():
        crt_base = ""
        for no, line in enumerate(text.splitlines(), 1):
            words = line.split("#", 1)[0].split()
            if not words:
                continue
            if words[0] == "crt-base" and len(words) > 1:
                crt_base = words[1]
            if words[0] != "bind" or "ssl" not in words:
                continue
            addr, _, port = words[1].rpartition(":") if len(words) > 1 else ("", "", "")
            crts = [words[i + 1] for i, w in enumerate(words[:-1]) if w == "crt"]
            for crt in crts:
                full = crt if crt.startswith("/") or not crt_base else \
                    posixpath.join(crt_base, crt)
                sites.append(TlsSite("haproxy", addr or "*", port, [], cert=full,
                                     key=full, source=f"{path}:{no}"))
    return sites


def select_site(sites: List[TlsSite], domain: str, port: int) -> Optional[TlsSite]:
    """The site answering `domain:port`: a name match, else the first on the port."""
    on_port = [s for s in sites if s.port == str(port)]
    d = domain.lower()
    for s in on_port:
        for n in s.names:
            n = n.lower()
            if n == d or (n.startswith("*.") and d.endswith(n[1:])
                          and d.count(".") == n.count(".")):
                return s
    return on_port[0] if on_port else None


# ---------------------------------------------------------------- config test

_PERMISSION = re.compile(r"permission denied|\(13:|must be root|operation not permitted",
                         re.IGNORECASE)
# Error-level lines of nginx, Apache httpd and HAProxy configuration tests.
_ERROR_LINE = re.compile(r"\[(emerg|alert|crit)\]|^AH\d{5}:|syntax error|\[(ALERT|ERROR)\]",
                         re.IGNORECASE)
# What the service prints about the test itself.  "test failed" follows every
# failed nginx test, so it can never decide whether the failure was access-only.
_SUMMARY_LINE = re.compile(r"syntax is ok|test is successful|configuration file .* test failed"
                           r"|^syntax ok$|action '-t' failed|fatal errors found in configuration"
                           r"|error\(s\) found in configuration file", re.IGNORECASE)
_PARSED_OK = re.compile(r"syntax is ok|^syntax ok$", re.IGNORECASE)
_UNOPENED = re.compile(r'open\(\) "([^"]+)"|fopen\(([^,)]+)|certificate(?: key)? "([^"]+)"'
                       r"|from file '([^']+)'")


def classify_config_test(rc: Optional[int], output: str) -> Tuple[str, List[str]]:
    """("pass" | "fail" | "permission" | "inconclusive" | "unknown", summary lines).

    Decided from error-level lines only.  A test that failed only on files this
    account may not open says nothing about the configuration, so it is
    "permission", never "fail"; its lines name those files and keep a reported
    "syntax is ok".
    """
    lines = [ln.strip()[:240] for ln in (output or "").splitlines() if ln.strip()]
    if rc is None:
        return "unknown", lines[-3:]
    if rc == 0:
        return "pass", lines[-3:]
    errors = [ln for ln in lines if _ERROR_LINE.search(ln) and not _SUMMARY_LINE.search(ln)]
    if not errors:
        return "inconclusive", lines[-3:]
    if all(_PERMISSION.search(e) for e in errors):
        paths = list(dict.fromkeys(next(g for g in m.groups() if g).strip()
                                   for e in errors for m in _UNOPENED.finditer(e)))
        parsed = [ln for ln in lines if _PARSED_OK.search(ln)]
        return "permission", ([f"could not open: {', '.join(paths)}"] if paths else []) \
            + parsed[:1] + errors[:5]
    return "fail", [e for e in errors if not _PERMISSION.search(e)][:5] or errors[:5]


# ---------------------------------------------------------------- reload state

_RELOAD_ERROR = re.compile(r"reload failed|failed to reload|cannot load certificate|"
                           r"\[emerg\]|configuration file .* test failed", re.IGNORECASE)


def reload_errors(lines: List[str]) -> List[str]:
    return [ln.strip()[:240] for ln in lines if _RELOAD_ERROR.search(ln)][-3:]


def reload_state(now: Optional[int], worker_elapsed: List[int],
                 mtimes: Dict[str, int]) -> Tuple[str, List[str]]:
    """("reloaded" | "stale" | "unknown", evidence) from file mtimes vs the
    newest worker start (a reload replaces every worker)."""
    if now is None or not worker_elapsed or not mtimes:
        return "unknown", ["process start times or file modification times are not "
                           "available"]
    started = now - min(worker_elapsed)
    stale = sorted(p for p, m in mtimes.items() if m > started)
    ev = [f"workers started at epoch {started} (newest worker)"]
    if stale:
        return "stale", ev + [f"{p} changed after the running workers started"
                              for p in stale]
    return "reloaded", ev + ["every certificate and key is older than the running workers"]


# ---------------------------------------------------------------- renewal

@dataclass
class Renewal:
    tools: List[str] = field(default_factory=list)          # installed binaries
    managed: Dict[str, str] = field(default_factory=dict)   # cert path -> tool:config
    schedules: List[str] = field(default_factory=list)      # timers / cron lines


def parse_renewal(text: str) -> Renewal:
    """Sections of the renewal probe: `@@SSLDOCTOR <section>` then lines."""
    r = Renewal()
    section = ""
    for line in (text or "").splitlines():
        if line.startswith("@@SSLDOCTOR "):
            section = line.split(None, 1)[1].strip()
            continue
        line = line.strip()
        if not line:
            continue
        if section == "tools":
            r.tools.append(posixpath.basename(line))
        elif section == "certbot":
            # /etc/letsencrypt/renewal/x.conf:fullchain = /etc/letsencrypt/live/x/fullchain.pem
            conf, _, rest = line.partition(":")
            key, _, value = rest.partition("=")
            if key.strip() in ("cert", "fullchain", "privkey", "chain") and value.strip():
                r.managed[value.strip()] = f"certbot:{conf}"
        elif section == "acme.sh":
            conf, _, rest = line.partition(":")
            key, _, value = rest.partition("=")
            value = value.strip().strip("'\"")
            if key.startswith("Le_Real") and value:
                r.managed[value] = f"acme.sh:{conf}"
        elif section in ("timers", "cron"):
            r.schedules.append(line[:200])
    return r


def renewal_for(r: Renewal, paths: List[str], realpaths: Dict[str, str]
                ) -> Tuple[str, List[str]]:
    """("managed" | "unscheduled" | "unlinked" | "none", evidence)."""
    linked = []
    for path in paths:
        candidates = {path, realpaths.get(path, path)}
        for managed, origin in r.managed.items():
            if managed in candidates or realpaths.get(managed) in candidates:
                linked.append((path, origin))
                break
    tool_names = sorted({o.split(":", 1)[0] for _p, o in linked} | set(r.tools))
    if linked:
        ev = [f"{p} is managed by {o.split(':', 1)[0]} ({o.split(':', 1)[1]})"
              for p, o in linked]
        relevant = [s for s in r.schedules
                    if any(t in s for t in tool_names)] or r.schedules
        if relevant:
            return "managed", ev + [f"schedule: {s}" for s in relevant[:3]]
        return "unscheduled", ev + ["no systemd timer or cron entry for it was found"]
    if r.tools:
        return "unlinked", [f"{', '.join(sorted(set(r.tools)))} installed, but no renewal "
                            f"configuration names {', '.join(paths) or 'the certificate'}"]
    return "none", ["no certbot, acme.sh or lego installation or renewal configuration "
                    "was found"]
