---
project: ssl-doctor
topic: remembered-servers
tags: [ssh, profiles, credentials, vault, windows, linux, security, openspec]
status: in-progress
trust: ai-inferred
last_done: 2026-10-25
version: 3
---

**Problem:** every `/server connect` (and `/scan` server step) re-asks host, port, user, auth, TLS target and password.

**Implemented (v2, branch feat/remembered-servers):** `ssl_doctor/profiles.py` (Profile, ProfileStore: load/save/forget/get/closest/recent/match_domain/for_host/expire), `ssl_doctor/vault.py` (SecretVault, NullVault, MemoryVault, WindowsCredentialVault via advapi32 ctypes, SecretServiceVault via secret-tool, open_vault), `cli.py` five-step `_server_connect` (+ `_ConnectSettings`, `remember_enabled`, `/servers`, `/server forget[-password]`, `/scan` profile offer, `_completer` with `completes_arguments` so the shell menu completes profile names). Tests: test_profiles, test_vault (incl. fake advapi32 marshalling + fake secret-tool on PATH), test_remembered_connect, test_server_commands, test_remembered_leaks. Windows real Credential Manager contract runs only on the windows-latest CI job.

**Plan (ADR-001 Accepted):** ADR `docs/decisions/ADR-001-remembered-servers.md` (Proposed) + OpenSpec change `openspec/changes/remembered-servers/` (proposal, specs `server-profiles` + `credential-vault`, design D1–D9, tasks 1–6; `openspec validate --strict` passes).
- Non-secret profiles → `~/.ssl-doctor/profiles.json` (allowlisted schema, atomic write, 0600).
- Passwords only in the OS vault: Windows Credential Manager via ctypes (`CRED_PERSIST_LOCAL_MACHINE`), Linux Secret Service via `secret-tool` (stdin), else `NullVault` (ask every time; never a file fallback).
- Security-critical order: profile → host key trusted → fingerprint matches saved → vault read → askpass → ssh. Auth failure deletes the saved password. Password prompt moves after the host-key check for typed passwords too.
- Commands: `/servers`, `/server connect [name]`, `/server forget <name>|--all`, `/server forget-password <name>`; `/scan` offers a matching profile; `--no-remember`, `SSL_DOCTOR_REMEMBER=off`; never in `-c`, agents, service.

**Defaults (accepted at apply):** pre-selected answer *profile only*; headless Linux = ask every time; saved passwords expire after 90 days unused; macOS out of scope.

**Next:** confirm Windows CI job (real Credential Manager) + manual checks (task 6.2) → archive change → merge/release.

**v3 (scan server choice):** `cli._choose_scan_server(domain)` runs at every interactive `/scan` server step → "current" | Profile | "new" | None; list = current session, then profiles (dedup vs current endpoint, domain matches first by tls_host/host); default = current if it serves the domain, else first match, else current, else most recent. Batch: open session or `_server_connect()`. `_server_connect` now returns bool; `_open_session` keeps the old session until the new one connects (failed attempt → old stays, scan stops). Spec: "Every `/scan` asks which server to use" + "Batch scans never ask" (task 4.6). Tests: `test_server_commands.py::ScanAsksWhichServer`.

