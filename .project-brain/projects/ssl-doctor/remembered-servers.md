---
project: ssl-doctor
topic: remembered-servers
tags: [ssh, profiles, credentials, vault, windows, linux, security, openspec]
status: in-progress
trust: ai-inferred
last_done: 2026-10-25
version: 1
---

**Problem:** every `/server connect` (and `/scan` server step) re-asks host, port, user, auth, TLS target and password.

**Plan (proposed, not implemented):** ADR `docs/decisions/ADR-001-remembered-servers.md` (Proposed) + OpenSpec change `openspec/changes/remembered-servers/` (proposal, specs `server-profiles` + `credential-vault`, design D1–D9, tasks 1–6; `openspec validate --strict` passes).
- Non-secret profiles → `~/.ssl-doctor/profiles.json` (allowlisted schema, atomic write, 0600).
- Passwords only in the OS vault: Windows Credential Manager via ctypes (`CRED_PERSIST_LOCAL_MACHINE`), Linux Secret Service via `secret-tool` (stdin), else `NullVault` (ask every time; never a file fallback).
- Security-critical order: profile → host key trusted → fingerprint matches saved → vault read → askpass → ssh. Auth failure deletes the saved password. Password prompt moves after the host-key check for typed passwords too.
- Commands: `/servers`, `/server connect [name]`, `/server forget <name>|--all`, `/server forget-password <name>`; `/scan` offers a matching profile; `--no-remember`, `SSL_DOCTOR_REMEMBER=off`; never in `-c`, agents, service.

**Defaults written into the specs, owner to confirm before apply:** pre-selected answer *profile only*; headless Linux = ask every time; saved passwords expire after 90 days unused; macOS out of scope.

**Next:** owner reviews artifacts → `/openspec-apply-change remembered-servers` (TDD, new branch).
