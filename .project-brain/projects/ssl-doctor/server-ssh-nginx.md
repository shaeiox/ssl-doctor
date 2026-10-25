---
project: ssl-doctor
topic: server-ssh-nginx
tags: [ssh, nginx, apache, vhost, config, hostkeys, permissions]
status: done
trust: human
last_done: 2026-10-25
version: 3
---

**Problem:** Diagnose server-side TLS config via read-only SSH without sudo/config edits.

**Solution (v1):**
- SSH: host keys verified against `~/.ssl-doctor/known_hosts`; unknown requires explicit yes, changed keys refused. Passwords via SSH_ASKPASS (never CLI). Uses system ssh with StrictHostKeyChecking=yes.
- Detection: finds nginx/apache/httpd and openssl versions. Config via `nginx -T` if possible, else readable files under `/etc/nginx/{nginx.conf,conf.d/*.conf,sites-enabled/*}` and common paths. Insufficient rights → NOT TESTED.
- Vhost resolution (nginx): only blocks on target port; exact server_name (first wins, duplicates WARN) → longest leading wildcard → longest trailing wildcard → first regex → default_server on port → first block on port. ssl_certificate/ssl_certificate_key inherited from http{}. Chain linkage checked (leaf-first, each issued by next). 
- Server checks: overview, nginx analysis, cert inspection/key match (digest-only), config inventory, logs, compare configured vs presented fingerprint.
- Apache support via `apache2ctl -S` and config grep.

**Notes:** All read-only; no sudo/service restarts/config edits.

**v2 (field bug, trust: ai-inferred):** `/server connect` → "choose_kex: unsupported KEX method sntrup761x25519-sha512@openssh.com" while plain `ssh` worked. Root cause (OpenSSH 9.5p1 source): `ssh-keyscan.c` uses `KEX_CLIENT` from `myproposal.h` unfiltered (sntrup761 first), `kex.c` only implements it `#ifdef USE_SNTRUP761X25519`; `ssh` filters defaults via `match_filter_allowlist(KEX_CLIENT_KEX, kex_alg_list())` (readconf.c). Fix: `server._scan_host_keys` falls back to `_scan_host_keys_ssh` on a KEX failure or missing keyscan — one `ssh` probe per key family (`HostKeyAlgorithms=`), `StrictHostKeyChecking=accept-new` into `~/.ssl-doctor/.probe_known_hosts`, all auth methods off + BatchMode, lines normalised to `host|[host]:port type blob`. `host_key_status`/`store_host_key` take `username` so the probe uses the real login name. Tests: `tests/test_ssh_hostkey_scan.py` (fake OpenSSH); real probe checked against github.com:22 = same keys as ssh-keyscan. Not yet confirmed on the user's machine.

**v2b (Windows askpass, trust: ai-inferred):** Win32-OpenSSH runs SSH_ASKPASS via `posix_spawnp` → `CreateProcessW(NULL, cmdline)` (contrib/win32/win32compat/w32fd.c), so `askpass.sh` never ran. `ServerSession._write_askpass(windows, frozen)`: POSIX `askpass.sh`; Windows `askpass.cmd` = `@"<sys.executable>" -I -c "<print SSL_DOCTOR_PW utf-8>"` (CRLF, `newline=""`, no secret, no `%`); frozen Windows → `sys.executable` + env `SSL_DOCTOR_ASKPASS=1`, answered by `server.askpass_reply()` first thing in `cli.main()`. Never delete `sys.executable` on disconnect (`_askpass_path` stays None there). Needs OpenSSH ≥ 8.4 (Windows 10's inbox 8.1p1 lacks SSH_ASKPASS_REQUIRE). Tests in `tests/test_ssh_hostkey_scan.py::WindowsAskpass` (the .cmd's command line is actually executed).

**v2c (field bug, v0.8.4):** `/scan` step 3 → `NameError: name 'fatal' is not defined`. The streaming refactor (a024efe) deleted the `self.run("uname -a; …; id")` line from `ServerSession.overview()`. Restored. Guard: `tests/test_server_session_checks.py` drives every ServerSession check on a connected fake against success/empty/error/transport replies — keep it in sync when adding checks.

**v2d (error handling, trust: ai-inferred):** `server.password_problem()` is the one rule (empty/blank, CR/LF/NUL refused) used by the CLI prompt (3 attempts, `tui.read_secret` returns None on cancel), `ServerSession.connect` (FAIL without running ssh), vault puts, and `askpass_reply()` (now returns None | 0 | 1; `cli.main` returns it) + both helper scripts (exit 1). `host_key_status` wraps `_host_key_status`: missing ssh-keygen / unusable trust store → `unreachable` with reason; `store_host_key` → (False, msg); `run()` → fatal note on OSError. `cli._persist()` wraps every profile write. `execute()` phrases OSError as `/cmd: file: reason` and bugs as "internal error in /cmd". Tests: `tests/test_error_handling.py`.

**v3 (nginx config discovery, trust: ai-inferred; openspec `fix-nginx-config-discovery`):** field bug — custom install `/opt/pvm/nginx/sbin/nginx -p … -c …` was analysed from `nginx -T` on PATH or a fixed `/etc/nginx` list → "no server block listens on port 443" → analyze turned every non-fallback `nginx.domain` WARNING into "Several nginx server blocks claim this domain". Now `ssl_doctor/nginx_discovery.py` (pure, probe-driven): A `ps` master titles (`nginx: master process <argv>`) + `/proc/<pid>/exe|cwd|cgroup`; B systemd unit (linked only if MainPID == master; `LoadState=loaded` required — systemctl prints defaults for missing units); C `-V`/`-T` only for root-owned, non-group/world-writable regular files (titles are spoofable); D bounded `find` only without a runtime main; E include graph read in levels (framed `base64` script, glob expanded by the shell, `SAFE_PATTERN` only) and **expanded in place** (block order matters). Levels: none / candidate / runtime-associated / runtime-verified (complete + every mtime < master start). Findings: `nginx.conf` PASS only for complete runtime graph, WARNING candidate/incomplete, NOT TESTED none; `nginx.domain` NOT TESTED (uncertainty) instead of a no-block WARNING unless `Discovery.conclusive`; analyze gates nginx server causes (incl. chainfile) on `nginx.conf` PASS, splits fallback / duplicate / no-block, adds an `unresolved` entry when HTTPS works but the config is unconfirmed. Gotchas: markers must be whole lines (ps lists our own command); `FakeSession` now simulates a root master `/usr/sbin/nginx` whose `-T` returns the canned config. Tests: `tests/test_nginx_discovery.py` (incl. real `/bin/sh` runs of the probe scripts), fixture `tests/fixtures/nginx_host.py`. Contract unchanged (1.5).

