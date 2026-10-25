# Design

## Context

See `proposal.md` for the defect. Current state, verified in the code:

- `ServerSession.nginx_scan()` (`ssl_doctor/server.py`) tries
  `f"{self.nginx_cmd} -T"` (`nginx_cmd` = `SSLDOCTOR_NGINX_CMD` or `nginx` on
  the account's `PATH`), else `cat`s `/etc/nginx/nginx.conf`,
  `/etc/nginx/conf.d/*.conf`, `/etc/nginx/sites-enabled/*`,
  `/usr/local/nginx/conf/nginx.conf`, `/usr/local/etc/nginx/nginx.conf`. The
  fallback does not follow `include`; whatever text is found becomes
  `nginx.conf` PASS ("readable files under /etc/nginx …").
- Parsing is sound and reused as is: `_parse_nginx_nodes` (tokeniser → tree),
  `_collect_server_blocks`, `_block_directives`, `_listen_ports`,
  `_match_nginx_server` (nginx's selection order) and `_http_level_directives`.
  They work on concatenated text, exactly like `nginx -T` output.
- `tls_config_scan()` greps fixed `/etc/nginx` dirs; `webserver_detection()`
  uses `command -v nginx` on `PATH`.
- `analyze.py`: an `nginx.domain` WARNING without "fallback" in its evidence is
  reported as "Several nginx server blocks claim this domain" — also when the
  warning was "no server block listens on port 443".
- `ServerSession.run()` is the only remote execution path (system `ssh`,
  read-only, timeout, stdout/stderr apart, fatal note). Findings contract 1.5
  already has `Finding.uncertainty` and `Diagnosis.unresolved`.
- Test fixture `tests/fixtures/fake_server.FakeSession` answers any command
  starting with `nginx -T` with a canned config and runs everything else
  locally.

## Goals / Non-Goals

**Goals:** find the configuration of the *running* nginx; analyse only its
include graph; attach an evidence level; let findings and the diagnosis say
exactly what the evidence supports; keep check ids, CLI and contract 1.5.

**Non-Goals:** Apache/other servers; full nginx semantics (variables in
`include`, `map`-driven names, `stream` SNI routing beyond today's block
collection); following configuration generated at runtime by other tools;
containers' internal filesystems (a containerised nginx shows up as a process
whose paths are outside our mount namespace — reported, not entered).

## Decisions

### D1. One new module of pure functions, one orchestrating method
`ssl_doctor/nginx_discovery.py` holds parsing and resolution with no I/O:
`parse_masters(ps_output)`, `parse_build_info(v_output)`,
`parse_systemd_show(text)`, `resolve_main_config(runtime, build)`,
`resolve_include(pattern, conf_dir)`, `build_graph(main, read_batch)` and a
`Discovery` dataclass (masters, unit, executable, main path + how chosen,
files with states, discovered-only files, evidence level, limitations,
source text). `ServerSession.discover_nginx()` runs the remote commands
through `self.run()` and feeds the pure functions; the result is cached on the
session (cleared on connect/disconnect) and shared by `nginx_scan`,
`tls_config_scan` and `webserver_detection`.
*Alternative:* everything inside `server.py` — rejected, the file is already
1100+ lines and the logic needs table-driven tests without SSH.
*Alternative:* an nginx-parser dependency (crossplane) — rejected; the
existing tokeniser already handles the syntax we analyse, and the CLI is
stdlib-only.

### D2. Stage A — process discovery
`ps -eo pid=,ppid=,user=,etimes=,args= 2>&1 | head -c 65536` plus
`date +%s`. A master is a line whose args start with `nginx: master process `
(nginx rewrites its title to that prefix + the original command line), parsed
with `shlex.split` into executable and `-p`/`-c`/`-g`; workers are matched to
masters by PPID. For up to 4 masters: `readlink /proc/<pid>/exe`,
`cat /proc/<pid>/cgroup` (both may be refused for other users' processes —
recorded, not fatal). Start time = `date` − `etimes`. A relative `-p` needs the
master's cwd (`readlink /proc/<pid>/cwd`); unreadable → limitation.
*Why `ps` over walking `/proc`:* one bounded command, available on every
distribution, and it already honours `hidepid` restrictions.

### D3. Stage B — service definitions
From the cgroup path, the owning `*.service`; then
`systemctl show <unit> -p Id -p MainPID -p ExecStart -p FragmentPath
-p Environment --no-pager`. Without a running master:
`systemctl list-units --type=service --all --no-legend --plain '*nginx*'`
(bounded) and `show` for each. A unit is *linked* only when its `MainPID` is a
discovered master; otherwise its `-c`/`-p` give candidates. Unit names are
validated (`^[A-Za-z0-9@._:-]+\.service$`) before use.

### D4. Stage C — trusted executable defaults
Before running anything: `stat -Lc '%u %a %F' <exe>`; run only if uid 0, mode
without group/other write, regular file (D-trust). Then `<exe> -V 2>&1`
(bounded) → `--prefix`, `--conf-path`, version. The executable path must match
`^/[A-Za-z0-9._+/-]+$` and is passed through `shlex.quote`.
*Why the trust check:* any local user can start a process titled
`nginx: master process /tmp/x`; running that path as the SSH account would
execute an attacker's file.

### D5. Path semantics (nginx's own rules)
prefix = `-p` else build `--prefix` (else `/usr/local/nginx/`, nginx's
compiled default); main = `-c` else build `--conf-path` (else
`<prefix>conf/nginx.conf`); relative `-c` joins the prefix; relative `include`
joins the main configuration's directory (nginx's `conf_prefix`). All paths are
normalised (`posixpath.normpath`); `-g` directives are recorded but not merged
(they rarely define servers).

### D6. Stage D — bounded candidate search (fallback only)
Runs only when no main configuration came from A–C. One command: for each root
of `/etc/nginx /usr/local/nginx /usr/local/etc/nginx /opt /srv`, report
missing / not readable / ok, then
`find <ok roots> -xdev -maxdepth 4 -type f -name nginx.conf 2>/dev/null |
head -n 20`, timeout 15 s. With several candidates, the first in the root order
is analysed and the rest are listed as discovered-only. When no master is
visible, `SSLDOCTOR_NGINX_CMD` / `PATH` `nginx -T` is tried first (today's
behaviour), at candidate level.

### D7. Stage E — include graph by levels
Breadth-first from the main file, one SSH round trip per level (depth ≤ 10,
≤ 200 files, ≤ 512 KiB per file, ≤ 4 MiB total). Each level sends a single
script that, per path or glob, prints a framed record:
`@@SSLDOCTOR <state> <mtime> <bytes> <path>` followed by the content (`head -c`)
for readable files; states: `read`, `missing`, `denied`, `nomatch`, `toolarge`.
Patterns must match `^[A-Za-z0-9_./*?\[\]@%+=:,-]+$` (glob characters allowed,
quoting impossible because the shell must expand them); anything else is
`unsupported` and never sent. `include` nodes are found anywhere in each
file's parse tree (reusing `_parse_nginx_nodes`); seen paths are skipped
(cycles, duplicates). The analysed source text is the graph's files
concatenated in visit order — the same shape as `nginx -T`, so the existing
block and inheritance code needs no change.
When the trusted runtime executable is known, `<exe> -T` with the master's own
`-p`/`-c` is tried first; on success its text is the source, its
`# configuration file <path>:` headers give the file list, and the graph is
complete. It is not stored or printed; `stat` still supplies mtimes.

### D8. Evidence level
`none` (nothing read) < `candidate` (not linked to a running master) <
`runtime-associated` (main from the master's `-c`, its executable's defaults,
or its linked unit; graph incomplete or modified after start) <
`runtime-verified` (same source, complete, every file's mtime < master start).
Mapping to the brief's states: per file `read` = *referenced*, discovered-only
= *discovered*, level = *runtime_associated* / *runtime_verified* /
*unconfirmed* (candidate, none).

### D9. Findings (same ids, contract 1.5 unchanged)
- `nginx.conf`: PASS (complete graph at runtime-associated or above) /
  WARNING (candidate or incomplete) / NOT TESTED (none). Evidence: level,
  master (pid, executable, args), unit, main configuration and how it was
  chosen, files read, each file not read with its state, discovered-only files
  (capped). `uncertainty` carries why the association or completeness is not
  established.
- `nginx.blocks`: counts from the graph only, plus "scope: complete graph at
  <level>" / "scope: incomplete …".
- `nginx.domain`: when the graph is a candidate or incomplete and no block
  matches the port → NOT TESTED with `uncertainty`; otherwise unchanged
  (selection and fallback logic untouched). Downstream findings (`protocols`,
  `ciphers`, `certref`, `chainfile`) still run when a block was selected, with
  the level in their evidence.
- `srv.web`: adds the running master(s) and executable when found.
- `/server config` (`srv.tlsconf`): greps the graph files instead of fixed
  directories.
*Alternative:* a new `nginx.discovery` check — rejected for this change: new
check ids require a contract minor version (1.6) and the information fits
`nginx.conf` ("Nginx configuration source").

### D10. Diagnosis
- The `nginx.domain` WARNING rule distinguishes three evidence shapes:
  fallback (existing cause), duplicate-name note (existing "several blocks"
  cause), no block on the port (new cause: "No nginx server block listens on
  port N in the analysed configuration"). No other shape claims a conflict.
- When `tls.handshake` PASS (and `tls.verify` not FAIL) while `nginx.conf` is
  WARNING or NOT TESTED: add `Unresolved(check="nginx.conf", …)` — observed:
  endpoint works; conclusion: the configuration serving it could not be
  established; uncertainty from `nginx.conf`; recommendation: identify the
  active configuration before changing anything. Server causes from
  `nginx.domain`/`nginx.certref` are skipped unless `nginx.conf` is PASS.

### D11. Test strategy
Discovery reaches the server only through a probe object
(`ServerSession.nginx_probe()`; `_SshNginxProbe` over `run()`). Tests drive
`discover()` and `nginx_scan` with an in-memory host implementing the same
interface (`tests/fixtures/nginx_host.py`); the SSH probe's shell scripts are
exercised for real under `/bin/sh` through `LocalSession`. `FakeSession` keeps its API: it reports one root
master `/usr/sbin/nginx` with trusted `stat`, answers `-V` with
`--conf-path=/etc/nginx/nginx.conf` and `<exe> -T …` with its canned config, so
existing nginx, diagnosis and contract tests run unchanged.

## Risks / Trade-offs

- [`ps` hidden by `hidepid`] → candidate search still runs; level stays
  candidate; uncertainty says processes were not visible.
- [`nginx -T` side effects: it tests the configuration, may open/create log
  files and needs read access to keys] → only the trusted runtime executable
  with its own arguments, same as the operator would run; output kept in memory
  only; a failure falls back to D7.
- [mtime heuristic for runtime-verified] → a file changed and reverted after
  start, or a reload with different files, cannot be seen; documented as the
  limit of "verified".
- [Round trips per include level] → bounded depth; typical graphs need 2–3.
- [Wildcards with unusual characters] → reported as unsupported rather than
  risking shell injection.
- [Containerised nginx] → paths are in another mount namespace; the read fails
  as missing and the level is lowered — reported, not misread.

## Migration Plan

No data migration. Behaviour changes are limited to `nginx.conf` /
`nginx.domain` status and evidence and the diagnosis rule; check ids and the
contract are unchanged. Rollback is a revert of the change.
