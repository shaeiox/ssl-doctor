# Tasks

## 1. Test scaffolding

- [ ] 1.1 Add `tests/fixtures/scripted_remote.py`: a `ServerSession` subclass whose `run()` answers from a command-prefix table and serves D7's framed file reads from an in-memory filesystem (path → content, mtime, readable flag), recording every command; verify with a self-test that unknown commands fail loudly and recorded commands can be asserted
- [ ] 1.2 Add a pre-change reproduction test (`tests/test_nginx_discovery.py::Regression`): a custom-install remote (`/opt/pvm/nginx` master, unrelated `/etc/nginx/nginx.conf` with one port-80 block, HTTPS findings PASS) and assert the intended outcome (no `nginx.domain` WARNING, no "Several nginx server blocks" cause); verify it fails on the current code
- [ ] 1.3 Extend `tests/fixtures/fake_server.FakeSession` per D11 (root master `/usr/sbin/nginx`, trusted `stat`, `-V` with `--conf-path=/etc/nginx/nginx.conf`, `<exe> -T` → canned config) without changing its constructor; verify the existing nginx, diagnosis and contract tests still pass

## 2. Pure discovery functions (`ssl_doctor/nginx_discovery.py`)

- [ ] 2.1 `parse_masters()` for `ps -eo pid=,ppid=,user=,etimes=,args=` output (master/worker titles, `-p`/`-c`/`-g`, quoted args, several masters, garbage lines); verify with table tests including `nginx: master process /opt/pvm/nginx/sbin/nginx -p /opt/pvm/nginx/ -c conf/nginx.conf`
- [ ] 2.2 `parse_build_info()` for `nginx -V` (`--prefix`, `--conf-path`, version, missing options) and `parse_systemd_show()` (Id, MainPID, ExecStart with its `argv[]=` form, FragmentPath); verify with captured outputs from Debian/Ubuntu, RHEL and a custom build
- [ ] 2.3 `resolve_main_config()` implementing D5 (explicit `-c`/`-p` over build defaults, relative `-c` under the prefix, relative `-p` needing cwd → limitation, compiled defaults); verify with the "Relative -c with -p" and "No -c argument" scenarios
- [ ] 2.4 Include-pattern handling: `resolve_include()` (absolute, relative to the main config dir, normalisation) and the safe-pattern check (unsafe → `unsupported`); verify with tests for `conf.d/*.conf`, `/etc/nginx/sites-enabled/*`, `../x.conf`, and patterns with `$(`, `;`, spaces
- [ ] 2.5 `build_graph(main, read_batch)`: breadth-first levels, include nodes at any nesting via `_parse_nginx_nodes`, de-duplication, cycle detection, depth/file/size limits, per-file states (`read`, `missing`, `denied`, `nomatch`, `toolarge`, `unsupported`), completeness flag, concatenated source text; verify with the nested-wildcard, cycle, permission-denied and wildcard-matching-nothing scenarios using an in-memory `read_batch`
- [ ] 2.6 Evidence level per D8 (`none` / `candidate` / `runtime-associated` / `runtime-verified` with the mtime-vs-start rule); verify with the "Unchanged since start", "Changed after start", "Linked but incomplete" and "Candidate from the search" scenarios

## 3. Remote discovery stages (`ServerSession.discover_nginx`)

- [ ] 3.1 Stage A: run `ps … | head -c` + `date +%s`, then `readlink /proc/<pid>/exe`, `cat /proc/<pid>/cgroup`, `readlink /proc/<pid>/cwd` for ≤ 4 masters; record refusals; verify with scripted remotes for a visible master, `hidepid` (no processes), refused `/proc` links, and `ps` missing
- [ ] 3.2 Stage B: unit from cgroup → `systemctl show` (validated unit name); without a master `systemctl list-units '*nginx*'`; linked vs candidate per MainPID; verify with "Unit owns the master", "Unrelated unit" and no-systemd scenarios
- [ ] 3.3 Stage C: trust check (`stat -Lc '%u %a %F'`, root-owned regular file, no group/other write) then `<exe> -V`; verify that a spoofed `/tmp/x/nginx` title is never executed (no `-V`, no `-T` in the recorded commands) and that a different `nginx` on `PATH` is never run while a master is visible
- [ ] 3.4 Stage D: bounded candidate search (root states + `find -xdev -maxdepth 4 … | head -n 20`, timeout) only when A–C give no main config; `SSLDOCTOR_NGINX_CMD` / `PATH` `nginx -T` first when no master is visible; verify with "Nothing running, custom tree on disk" and that the search is not run when the master's `-c` is known
- [ ] 3.5 Stage E remote reads: framed per-level script for D7 with `head -c` and `stat` mtimes; `<exe> -T` with the master's own `-p`/`-c` first when trusted (headers → file list, output kept in memory only); verify with scripted remotes that `-T` output never appears in findings and that a `-T` failure falls back to level reads
- [ ] 3.6 Cache the `Discovery` on the session (cleared on connect/disconnect) and add discovery to the `EveryCheckRuns` matrix in `tests/test_server_session_checks.py`; verify no stage raises for success, empty, error and transport replies

## 4. Findings from the discovered graph (`ssl_doctor/server.py`)

- [ ] 4.1 `nginx_scan` uses `discover_nginx()`; `nginx.conf` status/evidence/uncertainty per D9; verify brief Tests 1 (standard), 2 (custom `/opt/pvm/nginx`), 3 (explicit `-c`/`-p`), 7 (missing vs unreadable files) end to end through `nginx_scan`
- [ ] 4.2 `nginx.blocks` counts graph blocks only with the scope line; discovered-only files listed, not counted; verify brief Test 4 (TLS `default.conf` on disk but not included)
- [ ] 4.3 `nginx.domain` NOT TESTED with uncertainty for candidate/incomplete graphs when no block matches the port; unchanged otherwise; verify brief Test 5 (runtime undeterminable) and the "Verified graph without a 443 block" scenario
- [ ] 4.4 `srv.web` reports running masters/executable from discovery; `/server config` (`srv.tlsconf`) greps graph files instead of fixed `/etc/nginx` dirs; verify with a custom-install scripted remote that neither mentions `/etc/nginx` unless it is in the graph
- [ ] 4.5 Contract check: every emitted id is in `contract.CHECK_IDS`, documents validate against findings 1.5, and the agent report renders the new evidence; verify with `tests/test_contract.py` and an agent-report render of the custom-install scan

## 5. Diagnosis (`ssl_doctor/analyze.py`)

- [ ] 5.1 Split the `nginx.domain` WARNING rule into fallback / duplicate-name / no-block-on-port causes, the last limited to the analysed configuration; verify "No block on the port" and "Real duplicate" scenarios and that the existing `test_diagnosis` fallback expectation still holds
- [ ] 5.2 Add the unresolved entry for "HTTPS works, configuration not established" and suppress nginx-derived server causes unless `nginx.conf` is PASS; verify brief Test 6 (HTTPS works, discovery incomplete → unresolved entry, no server cause, no configuration-change recommendation)
- [ ] 5.3 Facts vs hypotheses: suspected non-standard paths appear only in uncertainty / unresolved conclusions; verify the "Suspected custom path" scenario

## 6. Documentation and integration

- [ ] 6.1 Document the discovery stages, evidence levels, trust rule and the read-only command list in README (server-side section), `docs/command-used.md`, `docs/execution-flow.md`, `docs/findings-contract.md` (meaning of `nginx.conf`/`nginx.domain` statuses) and CHANGELOG Unreleased; verify the documented commands match the code
- [ ] 6.2 Run the full suite (`python3 -m unittest discover -s tests`) and verify it passes, with the 1.2 reproduction now passing; record the before/after outcome for the custom-install scenario
- [ ] 6.3 Update the project brain (`server-ssh-nginx` topic, decisions: runtime-first discovery over path lists; mtime rule for runtime-verified; executable trust rule) and verify `brain-check` passes

## Workflow follow-up

- Archive the change with `/openspec-archive-change` after review.
- Merge to `master`, bump the version and push, as for previous changes.
