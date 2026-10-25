"""An in-memory Linux host for nginx discovery tests (no SSH, no real files).

`NginxHost` implements the probe interface `nginx_discovery.discover()` uses:
processes, /proc links, systemd units, executables (owner, mode, `-V`, `-T`)
and a filesystem with per-file mtime and readability. Every call is recorded
in `calls`, so tests can assert what would have been executed remotely.
`HostSession` is a connected `ServerSession` whose nginx probe is the host.
"""

from __future__ import annotations

import fnmatch
import posixpath
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ssl_doctor import nginx_discovery as nd
from ssl_doctor import server


@dataclass
class File:
    content: str
    mtime: int = 1_000
    readable: bool = True


@dataclass
class Exe:
    uid: int = 0
    mode: int = 0o755
    kind: str = "regular file"
    version_output: str = ""
    dump: Optional[str] = None          # what `<exe> -T` prints, None = fails


@dataclass
class NginxHost:
    files: Dict[str, File] = field(default_factory=dict)
    ps: Optional[str] = ""              # None = ps unavailable
    now: int = 10_000
    proc: Dict[int, Dict] = field(default_factory=dict)       # pid -> exe/cwd/cgroup/denied
    units: Dict[str, str] = field(default_factory=dict)       # name -> `systemctl show` text
    systemd: bool = True
    executables: Dict[str, Exe] = field(default_factory=dict)
    path_nginx_dump: Optional[str] = None                     # `nginx -T` from PATH
    denied_dirs: List[str] = field(default_factory=list)
    calls: List[Tuple] = field(default_factory=list)

    # -- stage A
    def processes(self):
        self.calls.append(("ps",))
        if self.ps is None:
            return None, None, "ps is not available"
        return self.ps, self.now, ""

    def proc_details(self, pid):
        self.calls.append(("proc", pid))
        info = dict(self.proc.get(pid, {}))
        info.setdefault("denied", [])
        return info

    # -- stage B
    def systemd_show(self, unit):
        self.calls.append(("systemctl show", unit))
        return self.units.get(unit) if self.systemd else None

    def systemd_units(self):
        self.calls.append(("systemctl list-units",))
        if not self.systemd:
            return None
        return sorted(u for u in self.units if "nginx" in u)

    # -- stage C
    def exe_stat(self, path):
        self.calls.append(("stat", path))
        exe = self.executables.get(path)
        return (exe.uid, exe.mode, exe.kind) if exe else None

    def build_info(self, exe):
        self.calls.append(("-V", exe))
        return self.executables[exe].version_output

    def dump(self, exe, prefix, conf):
        self.calls.append(("-T", exe, prefix, conf))
        out = self.executables[exe].dump
        return (out or ""), f"{exe} -T"

    def path_dump(self, override):
        self.calls.append(("PATH -T", override))
        return (self.path_nginx_dump or ""), (override or "nginx") + " -T"

    # -- files
    def _exists(self, path):
        return path in self.files

    def read(self, patterns):
        self.calls.append(("read", tuple(patterns)))
        out = []
        for pattern in patterns:
            if nd.is_glob(pattern):
                hits = sorted(p for p in self.files if fnmatch.fnmatchcase(p, pattern)
                              and posixpath.dirname(p) == posixpath.dirname(pattern))
                if not hits:
                    out.append(nd.FileRecord(pattern, pattern, nd.NOMATCH))
                for path in hits:
                    out.append(self._record(pattern, path))
            elif pattern in self.files:
                out.append(self._record(pattern, pattern))
            elif any(pattern.startswith(d.rstrip("/") + "/") for d in self.denied_dirs):
                out.append(nd.FileRecord(pattern, pattern, nd.DENIED,
                                         note="directory not searchable"))
            else:
                out.append(nd.FileRecord(pattern, pattern, nd.MISSING))
        return out

    def _record(self, pattern, path):
        f = self.files[path]
        size = len(f.content.encode())
        if not f.readable:
            return nd.FileRecord(pattern, path, nd.DENIED, f.mtime)
        if size > nd.MAX_FILE_BYTES:
            return nd.FileRecord(pattern, path, nd.TOOLARGE, f.mtime, size)
        return nd.FileRecord(pattern, path, nd.READ, f.mtime, size, f.content)

    def mtimes(self, paths):
        self.calls.append(("mtimes", tuple(paths)))
        return {p: self.files[p].mtime for p in paths if p in self.files}

    def file_states(self, paths):
        """readable / denied / notfile / missing / unreachable / unsupported."""
        self.calls.append(("file_states", tuple(paths)))
        out = {}
        for path in paths:
            if not nd.SAFE_PATH.match(path):
                out[path] = "unsupported"
            elif path in self.files:
                out[path] = "readable" if self.files[path].readable else "denied"
            elif any(f.startswith(path.rstrip("/") + "/") for f in self.files):
                out[path] = "notfile"
            elif any(path.startswith(d.rstrip("/") + "/") for d in self.denied_dirs):
                out[path] = "unreachable"
            else:
                out[path] = "missing"
        return out

    def root_states(self, roots):
        self.calls.append(("roots", tuple(roots)))
        out = []
        for root in roots:
            if root in self.denied_dirs:
                out.append((root, "denied"))
            elif any(p.startswith(root.rstrip("/") + "/") for p in self.files):
                out.append((root, "ok"))
            else:
                out.append((root, "missing"))
        return out

    def find_main(self, roots):
        self.calls.append(("find", tuple(roots)))
        return [p for p in sorted(self.files) if posixpath.basename(p) == "nginx.conf"
                and any(p.startswith(r.rstrip("/") + "/") for r in roots)
                and p.count("/") - r_depth(p, roots) <= 4][:20]

    def list_conf(self, dirs):
        self.calls.append(("list", tuple(dirs)))
        return sorted(p for p in self.files if p.endswith(".conf")
                      and posixpath.dirname(p) in dirs)

    # -- helpers for tests
    def executed(self):
        """Executables that would have been run (-V / -T)."""
        return [c[1] for c in self.calls if c[0] in ("-V", "-T")]


def r_depth(path, roots):
    return min(r.rstrip("/").count("/") for r in roots if path.startswith(r.rstrip("/") + "/"))


def master_line(pid, argv, user="root", etimes=3600, ppid=1):
    return f"{pid:>6} {ppid:>6} {user} {etimes} nginx: master process {argv}"


def worker_line(pid, master, user="www-data", etimes=3600):
    return f"{pid:>6} {master:>6} {user} {etimes} nginx: worker process"


def version(prefix, conf_path, ver="1.24.0"):
    return (f"nginx version: nginx/{ver}\nbuilt with OpenSSL 3.0.13\n"
            f"configure arguments: --prefix={prefix} --conf-path={conf_path} "
            "--with-http_ssl_module")


class HostSession(server.ServerSession):
    """A connected session whose nginx probe is an in-memory host."""

    def __init__(self, host: NginxHost, tls_host: str = "files.example.com"):
        super().__init__(server.SSHConfig(host="files.example.com", username="eleven",
                                          tls_host=tls_host))
        self.host = host
        self.connected = True
        self.commands: List[str] = []

    def nginx_probe(self):
        return self.host

    def run(self, remote_cmd):
        # downstream checks (certificate files) read through `cat`
        self.commands.append(remote_cmd)
        if remote_cmd.startswith("for f in /etc/nginx/nginx.conf"):
            # the pre-discovery fixed file list, answered as a real host would
            listed = remote_cmd.split("for f in ", 1)[1].split("; do", 1)[0].split()
            out = []
            for pattern in listed:
                for path in sorted(p for p in self.host.files
                                   if fnmatch.fnmatchcase(p, pattern)):
                    if self.host.files[path].readable:
                        out.append(f"--- FILE: {path}\n{self.host.files[path].content}")
            return 0, "\n".join(out), "", ""
        if remote_cmd.startswith("openssl x509 -noout -subject"):
            # answered as openssl would for a readable PEM file
            path = remote_cmd.rsplit(" -in ", 1)[1].split()[0].strip("'")
            f = self.host.files.get(path)
            if f and f.readable and "BEGIN CERTIFICATE" in f.content:
                return 0, ("subject=CN = files.example.com\nissuer=CN = Test CA\n"
                           "notBefore=Jan  1 00:00:00 2026 GMT\n"
                           "notAfter=Jan  1 00:00:00 2027 GMT\n"
                           "sha256 Fingerprint=AB:CD:EF\nrc=0\n"), "", ""
            return 0, "Could not read certificate\nrc=1\n", "", ""
        if remote_cmd.startswith("cat "):
            path = remote_cmd.split()[1].strip("'")
            f = self.host.files.get(path)
            if f and f.readable:
                return 0, f.content, "", ""
            return 1, "", f"cat: {path}: No such file or directory", ""
        return 127, "", "not available in the test host", ""
