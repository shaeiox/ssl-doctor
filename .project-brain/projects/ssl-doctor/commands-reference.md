---
project: ssl-doctor
topic: commands-reference
tags: [commands, openssl, certutil, wevtutil, ssh, docs]
status: verified
trust: human
last_done: 2026-10-25
version: 2
---

**Problem:** Need exact commands the program actually executes (documented and verified).

**Solution (v1):**
- Created `docs/ssl-doctor-actual-commands.md` listing only real subprocess invocations: local (certutil, wevtutil, openssl x509/pkey/s_client fallback) with source files/functions/args; remote via SSH (ssh/ssh-keyscan/ssh-keygen transport, nginx/apache/openssl/stat/grep/cat). 
- Created `docs/ssl-doctor-tls-troubleshooting-commands.md` (and .docx/.pdf) as polished reference covering both sides.
- Created `docs/command-used.md` summarizing CLI usage/verification/build.

**Notes:** All traced to actual code (ssl_doctor/local.py, certs.py, netchecks.py, server.py). No invented commands.

**v2 (2026-10-25, trust: ai-inferred — additions only):** `docs/ssl-doctor-actual-commands.md` and `docs/ssl-doctor-tls-troubleshooting-commands.md` are **git-ignored** (`.gitignore` lines 165–166): local-only, never pushed — keep them current locally, but `docs/command-used.md` is the tracked reference. Commands added since v1: the `ssh` host-key probe fallback (`StrictHostKeyChecking=accept-new`, all auth off), `secret-tool search|store|lookup|clear` (secret on stdin/stdout), Windows Credential Manager via advapi32 (no subprocess).
