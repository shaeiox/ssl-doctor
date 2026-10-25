---
project: ssl-doctor
topic: server-ssh-nginx
tags: [ssh, nginx, apache, vhost, config, hostkeys, permissions]
status: verified
trust: human
last_done: 2026-10-25
version: 2
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
