"""Which nginx configuration is the running nginx using?

Discovery works from the running instance outwards (openspec change
`fix-nginx-config-discovery`):

A. the running master process: executable, `-p`, `-c`, `-g`;
B. the systemd unit that owns it (supplementary evidence);
C. the build defaults of *that* executable (`-V`), run only when the file is
   trusted (root-owned, not group/world-writable) -- a process title can be
   spoofed by any local user;
D. a bounded search of fixed roots, only when A-C give no main configuration;
E. the include graph of the selected main configuration, with includes
   expanded where they appear, as nginx reads them.

Everything here is pure: remote access goes through a *probe* object (see
`ServerSession.nginx_probe()` for the SSH one), so the logic is tested with
in-memory hosts. The result carries an evidence level -- runtime-verified,
runtime-associated, candidate or none -- that limits what may be concluded
from the configuration.
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
import shlex
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

# evidence levels, weakest first
LEVEL_NONE = "none"
LEVEL_CANDIDATE = "candidate"
LEVEL_ASSOCIATED = "runtime-associated"
LEVEL_VERIFIED = "runtime-verified"

# per-file states
READ, MISSING, DENIED, NOMATCH, TOOLARGE, UNSUPPORTED, LIMIT = (
    "read", "missing", "denied", "nomatch", "toolarge", "unsupported", "limit")
INCOMPLETE_STATES = {MISSING, DENIED, TOOLARGE, UNSUPPORTED, LIMIT}

SEARCH_ROOTS = ("/etc/nginx", "/usr/local/nginx", "/usr/local/etc/nginx", "/opt", "/srv")
NGINX_DEFAULT_PREFIX = "/usr/local/nginx/"
MAX_MASTERS = 4
MAX_DEPTH = 10
MAX_FILES = 200
MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024

# characters a path or include pattern may contain before it reaches a remote
# shell; glob characters are allowed because the shell must expand them
SAFE_PATTERN = re.compile(r"^[A-Za-z0-9_./*?\[\]@%+=:,~-]+$")
SAFE_PATH = re.compile(r"^/[A-Za-z0-9_./@%+=:,~-]+$")
SAFE_UNIT = re.compile(r"^[A-Za-z0-9@._:\\-]+\.service$")
_MASTER_TITLE = "nginx: master process "
_INCLUDE = re.compile(r"(?<![\w$])include\s+([^;\s]+)\s*;")
_DUMP_HEADER = re.compile(r"^# configuration file (.+):\s*$")


# ------------------------------------------------------------------ records

@dataclass
class Master:
    pid: int
    ppid: int
    user: str
    elapsed: Optional[int]          # seconds since start (ps etimes), None if unknown
    argv: List[str]
    exe: str = ""                   # from the title (argv[0])
    prefix: str = ""                # -p
    conf: str = ""                  # -c
    globals: str = ""               # -g
    exe_link: str = ""              # readlink /proc/<pid>/exe
    cwd: str = ""                   # readlink /proc/<pid>/cwd
    unit: str = ""                  # systemd unit from /proc/<pid>/cgroup
    workers: int = 0

    @property
    def executable(self) -> str:
        return self.exe_link or (self.exe if self.exe.startswith("/") else "")


@dataclass
class FileRecord:
    pattern: str
    path: str
    state: str
    mtime: int = 0
    size: int = 0
    content: str = ""
    note: str = ""


@dataclass
class Discovery:
    level: str = LEVEL_NONE
    complete: bool = False
    masters: List[Master] = field(default_factory=list)
    master: Optional[Master] = None
    processes_visible: bool = False
    unit: Dict[str, str] = field(default_factory=dict)
    unit_linked: bool = False
    executable: str = ""
    executable_trusted: bool = False
    build: Dict[str, str] = field(default_factory=dict)
    main_path: str = ""
    main_how: str = ""
    runtime_main: bool = False      # main config derived from the running instance
    via_dump: str = ""              # the -T command used, if any
    files: List[FileRecord] = field(default_factory=list)
    discovered_only: List[str] = field(default_factory=list)
    roots: List[Tuple[str, str]] = field(default_factory=list)
    facts: List[str] = field(default_factory=list)          # observed
    limitations: List[str] = field(default_factory=list)    # what could not be done
    uncertainty: List[str] = field(default_factory=list)    # why conclusions are limited
    source: str = ""                # configuration text, includes expanded

    @property
    def read_files(self) -> List[FileRecord]:
        return [f for f in self.files if f.state == READ]

    @property
    def unread_files(self) -> List[FileRecord]:
        return [f for f in self.files if f.state in INCOMPLETE_STATES]

    @property
    def conclusive(self) -> bool:
        """Whether an absence (no block on a port) may be concluded."""
        return self.complete and self.level in (LEVEL_ASSOCIATED, LEVEL_VERIFIED)


# ------------------------------------------------------------------ parsing

def parse_masters(ps_output: str) -> List[Master]:
    """nginx master processes from `ps -eo pid=,ppid=,user=,etimes=,args=`.

    nginx rewrites its process title to `nginx: master process <command
    line>`, so the original executable and arguments survive in `args`.
    Workers (`nginx: worker process`) are counted against their parent.
    """
    masters: Dict[int, Master] = {}
    workers: List[int] = []
    for line in (ps_output or "").splitlines():
        parts = line.split(None, 4)
        if len(parts) < 5 or not parts[0].isdigit() or not parts[1].isdigit():
            continue
        pid, ppid, user, etimes, args = parts
        if args.startswith(_MASTER_TITLE):
            try:
                argv = shlex.split(args[len(_MASTER_TITLE):])
            except ValueError:
                argv = args[len(_MASTER_TITLE):].split()
            m = Master(pid=int(pid), ppid=int(ppid), user=user,
                       elapsed=int(etimes) if etimes.isdigit() else None, argv=argv)
            if argv:
                m.exe = argv[0]
            i = 1
            while i < len(argv):
                flag = argv[i]
                value = argv[i + 1] if i + 1 < len(argv) else ""
                if flag in ("-p", "-c", "-g") and value:
                    setattr(m, {"-p": "prefix", "-c": "conf", "-g": "globals"}[flag], value)
                    i += 2
                    continue
                if flag[:2] in ("-p", "-c", "-g") and len(flag) > 2:   # -c/path
                    setattr(m, {"-p": "prefix", "-c": "conf", "-g": "globals"}[flag[:2]],
                            flag[2:])
                i += 1
            masters[m.pid] = m
        elif args.startswith("nginx: worker process"):
            workers.append(int(ppid))
    for ppid in workers:
        if ppid in masters:
            masters[ppid].workers += 1
    return sorted(masters.values(), key=lambda m: m.pid)


def parse_build_info(text: str) -> Dict[str, str]:
    """`nginx -V` output -> {"version", "prefix", "conf_path"} (when present)."""
    out: Dict[str, str] = {}
    for line in (text or "").splitlines():
        if line.startswith("nginx version:"):
            out["version"] = line.split(":", 1)[1].strip()
        if line.startswith("configure arguments:"):
            try:
                args = shlex.split(line.split(":", 1)[1])
            except ValueError:
                args = line.split(":", 1)[1].split()
            for arg in args:
                if arg.startswith("--prefix="):
                    out["prefix"] = arg.split("=", 1)[1]
                elif arg.startswith("--conf-path="):
                    out["conf_path"] = arg.split("=", 1)[1]
    return out


def parse_systemd_show(text: str) -> Dict[str, str]:
    """`systemctl show -p …` output -> properties; ExecStart reduced to its argv."""
    props: Dict[str, str] = {}
    for line in (text or "").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            props[key.strip()] = value.strip()
    exec_start = props.get("ExecStart", "")
    match = re.search(r"argv\[\]=([^;]*)", exec_start)
    if match:
        props["ExecStartArgv"] = match.group(1).strip()
    elif exec_start and not exec_start.startswith("{"):
        props["ExecStartArgv"] = exec_start
    return props


def unit_from_cgroup(text: str) -> str:
    units = re.findall(r"/([A-Za-z0-9@._:\\-]+\.service)\b", text or "")
    return units[-1] if units else ""


def args_from_command(command: str) -> Dict[str, str]:
    """-p / -c / -g from a command line such as a unit's ExecStart."""
    try:
        argv = shlex.split(command)
    except ValueError:
        argv = command.split()
    out = {"exe": argv[0] if argv else ""}
    for i, arg in enumerate(argv[1:], 1):
        if arg in ("-p", "-c", "-g") and i + 1 < len(argv):
            out[arg[1]] = argv[i + 1]
    return out


# ------------------------------------------------------------ path semantics

def resolve_main_config(prefix_arg: str, conf_arg: str, build: Dict[str, str],
                        cwd: str = "") -> Tuple[str, str, str]:
    """(main configuration path, how it was chosen, limitation) as nginx does.

    prefix = -p, else the build --prefix, else nginx's compiled default;
    main = -c, else the build --conf-path, else <prefix>conf/nginx.conf; a
    relative -c joins the prefix. A relative -p is relative to the master's
    working directory, which is often unreadable.
    """
    limitation = ""
    prefix = prefix_arg or build.get("prefix", "") or NGINX_DEFAULT_PREFIX
    if prefix_arg and not prefix_arg.startswith("/"):
        if cwd:
            prefix = posixpath.join(cwd, prefix_arg)
        else:
            limitation = (f"-p {prefix_arg} is relative to the master's working directory, "
                          "which is not readable")
            prefix = ""
    if conf_arg:
        how = "-c argument of the running master"
        conf = conf_arg
    elif build.get("conf_path"):
        how = "build default (--conf-path) of the running executable"
        conf = build["conf_path"]
    else:
        how = "nginx's compiled default under the prefix"
        conf = "conf/nginx.conf"
    if not conf.startswith("/"):
        if not prefix:
            return "", how, limitation or "relative configuration path without a usable prefix"
        conf = posixpath.join(prefix, conf)
    return posixpath.normpath(conf), how, limitation


def resolve_include(pattern: str, conf_dir: str) -> str:
    """An include pattern as an absolute, normalised path (nginx conf_prefix rule)."""
    pattern = pattern.strip("'\"")
    if not pattern.startswith("/"):
        pattern = posixpath.join(conf_dir, pattern)
    return posixpath.normpath(pattern)


def is_glob(pattern: str) -> bool:
    return any(c in pattern for c in "*?[")


def safe_pattern(pattern: str) -> bool:
    return bool(SAFE_PATTERN.match(pattern)) and ".." not in pattern.split("/")


def includes_in(text: str) -> List[str]:
    """`include` arguments in configuration text (comments stripped)."""
    from .server import _strip_nginx_comments
    return _INCLUDE.findall(_strip_nginx_comments(text))


# ------------------------------------------------------------- include graph

def build_graph(main: str, read: Callable[[List[str]], List[FileRecord]]
                ) -> Tuple[List[FileRecord], bool, str]:
    """Follow includes from `main`; return (records, complete, expanded source).

    `read(patterns)` returns one record per matched file, or one record with
    state missing / nomatch / denied for a pattern that yields no readable file.
    Files are read once (normalised paths), cycles and duplicates are skipped,
    and depth, file count and size are bounded.
    """
    conf_dir = posixpath.dirname(main)
    records: List[FileRecord] = []
    by_path: Dict[str, FileRecord] = {}
    matches: Dict[str, List[str]] = {}
    total = 0
    level = [main]
    complete = True
    for depth in range(MAX_DEPTH + 1):
        batch = []
        for pattern in level:
            if pattern in matches:
                continue
            if not safe_pattern(pattern):
                matches[pattern] = []
                records.append(FileRecord(pattern, pattern, UNSUPPORTED,
                                          note="characters outside the safe set; not read"))
                complete = False
                continue
            batch.append(pattern)
        if not batch:
            break
        if depth == MAX_DEPTH:
            for pattern in batch:
                records.append(FileRecord(pattern, pattern, LIMIT,
                                          note=f"include depth limit ({MAX_DEPTH})"))
            complete = False
            break
        next_level: List[str] = []
        for rec in read(batch):
            matches.setdefault(rec.pattern, [])
            if rec.state in (MISSING, NOMATCH, DENIED, UNSUPPORTED) and rec.path == rec.pattern:
                records.append(rec)
                if rec.state != NOMATCH:
                    complete = False
                continue
            if rec.path in by_path:                 # duplicate or cycle
                matches[rec.pattern].append(rec.path)
                continue
            if len(by_path) >= MAX_FILES or total + rec.size > MAX_TOTAL_BYTES:
                rec = FileRecord(rec.pattern, rec.path, LIMIT, rec.mtime, rec.size,
                                 note="file-count or size limit reached")
            by_path[rec.path] = rec
            matches[rec.pattern].append(rec.path)
            records.append(rec)
            if rec.state != READ:
                complete = False
                continue
            total += rec.size
            for inc in includes_in(rec.content):
                next_level.append(resolve_include(inc, conf_dir))
        for pattern in batch:
            matches.setdefault(pattern, [])
        level = next_level
    source = expand(main, by_path, matches, conf_dir)
    return records, complete, source


def expand(main: str, files: Dict[str, FileRecord], matches: Dict[str, List[str]],
           conf_dir: str) -> str:
    """The configuration as nginx reads it: each include replaced by its files."""
    def text_of(path: str, stack: Tuple[str, ...]) -> str:
        rec = files.get(path)
        if rec is None or rec.state != READ or path in stack:
            return ""
        def splice(match):
            pattern = resolve_include(match.group(1), conf_dir)
            return "\n".join(text_of(p, stack + (path,)) for p in matches.get(pattern, []))
        from .server import _strip_nginx_comments
        return _INCLUDE.sub(splice, _strip_nginx_comments(rec.content))
    return text_of(main, ())


def graph_from_dump(dump: str, main: str) -> Tuple[List[FileRecord], str]:
    """Records and expanded source from `nginx -T` output (file-by-file)."""
    files: Dict[str, FileRecord] = {}
    order: List[str] = []
    current, lines = None, []
    for line in dump.splitlines():
        header = _DUMP_HEADER.match(line)
        if header:
            if current:
                files[current] = FileRecord(current, current, READ,
                                            content="\n".join(lines))
            current, lines = header.group(1).strip(), []
            order.append(current)
        elif current is not None:
            lines.append(line)
    if current:
        files[current] = FileRecord(current, current, READ, content="\n".join(lines))
    if not files:
        return [], ""
    first = main if main in files else order[0]
    conf_dir = posixpath.dirname(first)
    matches: Dict[str, List[str]] = {}
    for rec in files.values():
        for inc in includes_in(rec.content):
            pattern = resolve_include(inc, conf_dir)
            matches[pattern] = sorted(p for p in files
                                      if fnmatch.fnmatchcase(p, pattern)) \
                if is_glob(pattern) else ([pattern] if pattern in files else [])
    for rec in files.values():
        rec.size = len(rec.content.encode("utf-8", "replace"))
    return [files[p] for p in order if p in files], expand(first, files, matches, conf_dir)


# ------------------------------------------------------------------ discovery

def discover(probe, override_cmd: str = "") -> Discovery:
    """Run stages A-E through `probe`; never raises for remote failures."""
    d = Discovery()
    ps_text, now, why = probe.processes()
    if ps_text is None:
        d.limitations.append(f"process list not available: {why}")
    else:
        d.processes_visible = True
        d.masters = parse_masters(ps_text)
        if not d.masters:
            d.facts.append("no nginx master process is visible to this account")
            d.uncertainty.append("a master run by another user can be hidden from this "
                                 "account (e.g. /proc mounted with hidepid)")
    for m in d.masters[:MAX_MASTERS]:
        details = probe.proc_details(m.pid)
        m.exe_link = details.get("exe", "")
        m.cwd = details.get("cwd", "")
        m.unit = unit_from_cgroup(details.get("cgroup", ""))
        for note in details.get("denied", []):
            d.limitations.append(f"pid {m.pid}: {note}")
    if d.masters:
        d.master = m = d.masters[0]
        d.facts.append(f"running nginx master: pid {m.pid} (user {m.user}, {m.workers} "
                       f"worker(s)) - {' '.join(m.argv) or '(no command line)'}")
        if len(d.masters) > 1:
            d.facts.append(f"{len(d.masters)} nginx masters are running; analysing pid "
                           f"{m.pid} (others: "
                           f"{', '.join(str(x.pid) for x in d.masters[1:])})")
        if m.exe_link and m.exe and m.exe_link != m.exe and m.exe.startswith("/"):
            d.facts.append(f"executable link {m.exe_link} differs from the title {m.exe}")

    _service_stage(d, probe)
    _executable_stage(d, probe)

    # main configuration from the running instance
    if d.master is not None:
        m = d.master
        conf_arg, prefix_arg = m.conf, m.prefix
        if not conf_arg and d.unit_linked:
            unit_args = args_from_command(d.unit.get("ExecStartArgv", ""))
            conf_arg, prefix_arg = unit_args.get("c", ""), prefix_arg or unit_args.get("p", "")
        can_use_defaults = bool(d.build) or bool(conf_arg)
        if can_use_defaults or conf_arg:
            path, how, limitation = resolve_main_config(prefix_arg, conf_arg, d.build, m.cwd)
            if limitation:
                d.limitations.append(limitation)
            if path:
                d.main_path, d.main_how, d.runtime_main = path, how, True
        else:
            d.limitations.append("the running master's configuration path cannot be "
                                 "derived: no -c argument and the executable's build "
                                 "defaults are not available")
            d.uncertainty.append("the running instance may use a configuration outside "
                                 "the locations SSL Doctor can see")

    if d.runtime_main:
        dumped = ""
        if d.executable_trusted:
            dumped, cmd = probe.dump(d.executable, d.master.prefix, d.master.conf)
            if dumped:
                d.via_dump = cmd
        if dumped:
            d.files, d.source = graph_from_dump(dumped, d.main_path)
            d.complete = bool(d.files)
            mtimes = probe.mtimes([f.path for f in d.files]) if d.files else {}
            for f in d.files:
                f.mtime = mtimes.get(f.path, 0) or 0
        else:
            d.files, d.complete, d.source = build_graph(d.main_path, probe.read)
    else:
        _candidate_stage(d, probe, override_cmd)

    _discovered_only(d, probe)
    _evidence_level(d, now)
    return d


def _service_stage(d: Discovery, probe) -> None:
    m = d.master
    unit = m.unit if m else ""
    if unit and SAFE_UNIT.match(unit):
        text = probe.systemd_show(unit)
        if text:
            d.unit = parse_systemd_show(text)
            main_pid = d.unit.get("MainPID", "")
            d.unit_linked = main_pid.isdigit() and int(main_pid) == m.pid
            d.facts.append(f"systemd unit {unit}: MainPID {main_pid or '?'}, "
                           f"ExecStart {d.unit.get('ExecStartArgv') or '?'}, "
                           f"unit file {d.unit.get('FragmentPath') or '?'}")
        else:
            d.limitations.append(f"systemd unit {unit} could not be read")
    elif m is None:
        units = probe.systemd_units() or []
        for name in [u for u in units if SAFE_UNIT.match(u)][:5]:
            text = probe.systemd_show(name)
            if not text:
                continue
            props = parse_systemd_show(text)
            if props.get("ExecStartArgv"):
                d.facts.append(f"systemd unit {name} (not running or not visible): "
                               f"ExecStart {props['ExecStartArgv']}")
                if not d.unit:
                    d.unit = props


def _executable_stage(d: Discovery, probe) -> None:
    m = d.master
    if m is None:
        return
    exe = m.executable
    if not exe:
        d.limitations.append("the running executable cannot be determined (relative name "
                             "in the process title and /proc/<pid>/exe not readable)")
        return
    d.executable = exe
    if not SAFE_PATH.match(exe):
        d.limitations.append(f"executable path {exe!r} has unsupported characters; not run")
        return
    st = probe.exe_stat(exe)
    if st is None:
        d.limitations.append(f"executable {exe} could not be inspected; not run")
        return
    uid, mode, kind = st
    if uid != 0 or mode & 0o022 or kind != "regular file":
        d.limitations.append(f"executable {exe} is not trusted (owner uid {uid}, mode "
                             f"{mode:o}, {kind}); it is not run")
        return
    d.executable_trusted = True
    d.build = parse_build_info(probe.build_info(exe) or "")
    if d.build:
        d.facts.append(f"executable {exe}: nginx {d.build.get('version', '?')}, build "
                       f"prefix {d.build.get('prefix', '?')}, build conf-path "
                       f"{d.build.get('conf_path', '?')}")
    else:
        d.limitations.append(f"{exe} -V gave no build information")


def _candidate_stage(d: Discovery, probe, override_cmd: str) -> None:
    unit_args = args_from_command(d.unit.get("ExecStartArgv", "")) if d.unit else {}
    if unit_args.get("c", "").startswith("/"):
        d.main_path = posixpath.normpath(unit_args["c"])
        d.main_how = "configuration argument of a systemd unit not linked to a running master"
    if not d.main_path and d.master is None:
        dumped, cmd = probe.path_dump(override_cmd)
        if dumped:
            d.via_dump = cmd
            d.main_how = f"{cmd} (no running master visible; not linked to one)"
            d.files, d.source = graph_from_dump(dumped, "")
            d.complete = bool(d.files)
            d.main_path = d.files[0].path if d.files else ""
            return
    if not d.main_path:
        d.roots = probe.root_states(SEARCH_ROOTS)
        usable = [root for root, state in d.roots if state == "ok"]
        found = probe.find_main(usable) if usable else []
        if found:
            d.main_path = found[0]
            d.main_how = "bounded search of " + ", ".join(usable)
            d.discovered_only.extend(found[1:])
    if d.main_path:
        d.files, d.complete, d.source = build_graph(d.main_path, probe.read)


def _discovered_only(d: Discovery, probe) -> None:
    """*.conf files next to the graph that the graph does not include."""
    if not d.main_path:
        return
    conf_dir = posixpath.dirname(d.main_path)
    dirs = {conf_dir, posixpath.join(conf_dir, "conf.d"),
            posixpath.normpath(posixpath.join(conf_dir, "..", "conf.d"))}
    in_graph = {f.path for f in d.files}
    for path in probe.list_conf(sorted(dirs)):
        if path not in in_graph and path not in d.discovered_only:
            d.discovered_only.append(path)


def _evidence_level(d: Discovery, now: Optional[int]) -> None:
    if not d.read_files:
        d.level = LEVEL_NONE
    elif not d.runtime_main:
        d.level = LEVEL_CANDIDATE
        d.uncertainty.append(f"{d.main_path} is not linked to a running nginx master: it "
                             "may not be the configuration that serves this endpoint")
    else:
        d.level = LEVEL_ASSOCIATED
        m = d.master
        start = (now - m.elapsed) if (now and m and m.elapsed is not None) else None
        if not d.complete:
            d.uncertainty.append("some files of the configuration graph could not be read")
        elif start is None:
            d.uncertainty.append("the master's start time is unknown, so on-disk files "
                                 "cannot be compared with what it loaded")
        else:
            changed = [f.path for f in d.read_files if not f.mtime or f.mtime >= start]
            if changed:
                d.uncertainty.append("modified after the master started (a reload may or "
                                     "may not have applied it): " + ", ".join(changed[:5]))
            else:
                d.level = LEVEL_VERIFIED
    if d.unread_files:
        d.complete = False
