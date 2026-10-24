---
project: ssl-doctor
topic: architecture-and-scope
tags: [architecture, cli, tls, nginx, ssh, windows, read-only]
status: verified
trust: human
last_done: 2026-10-24
version: 1
---

**Problem:** Need to understand what SSL Doctor actually does and how it's structured.

**Solution (v1):**
- Entry point: `ssldoctor.py` → CLI in `ssl_doctor/cli.py` (REPL, prompts, colors, spinner, orchestration). 
- Modules: `findings.py` (PASS/FAIL/WARNING/NOT TESTED + session store), `certs.py` (offline parsing + digest-only key matching), `netchecks.py` (target parsing, domain profile, DNS/TCP/TLS/HTTPS), `local.py` (client + Windows certutil/Schannel), `server.py` (SSH transport, host-key trust, nginx config), `analyze.py` (correlation → ranked causes), `report.py` (JSON + HTML).
- Scope: Offline-capable TLS/SSL diagnostics for IT support — identifies whether failure is client, server (nginx/Apache), chain, or network. 
- Security: read-only, no sudo/config edits/service restarts, passwords never on CLI (SSH_ASKPASS), host keys verified/changed keys refused, private keys never printed, Windows checks only on Windows.
- Modes: `/scan` combined/client-only/server-only/--with-server; `/tls`, `/local`, `/cert`, `/server`, `/diagnose`, `/report`.

**Notes:** Python 3.10+, stdlib only + system `openssl`/`ssh` when present. Chain reading via Python APIs or `openssl s_client`. Hostname check uses SAN only (CN ignored).
