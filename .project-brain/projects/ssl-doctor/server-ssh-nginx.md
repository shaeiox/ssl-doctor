---
project: ssl-doctor
topic: server-ssh-nginx
tags: [ssh, nginx, apache, vhost, config, hostkeys, permissions]
status: verified
trust: human
last_done: 2026-10-24
version: 1
---

**Problem:** Diagnose server-side TLS config via read-only SSH without sudo/config edits.

**Solution (v1):**
- SSH: host keys verified against `~/.ssl-doctor/known_hosts`; unknown requires explicit yes, changed keys refused. Passwords via SSH_ASKPASS (never CLI). Uses system ssh with StrictHostKeyChecking=yes.
- Detection: finds nginx/apache/httpd and openssl versions. Config via `nginx -T` if possible, else readable files under `/etc/nginx/{nginx.conf,conf.d/*.conf,sites-enabled/*}` and common paths. Insufficient rights → NOT TESTED.
- Vhost resolution (nginx): only blocks on target port; exact server_name (first wins, duplicates WARN) → longest leading wildcard → longest trailing wildcard → first regex → default_server on port → first block on port. ssl_certificate/ssl_certificate_key inherited from http{}. Chain linkage checked (leaf-first, each issued by next). 
- Server checks: overview, nginx analysis, cert inspection/key match (digest-only), config inventory, logs, compare configured vs presented fingerprint.
- Apache support via `apache2ctl -S` and config grep.

**Notes:** All read-only; no sudo/service restarts/config edits.
