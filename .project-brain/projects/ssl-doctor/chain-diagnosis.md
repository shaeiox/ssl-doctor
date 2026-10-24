---
project: ssl-doctor
topic: chain-diagnosis
tags: [tls, chain, openssl, s_client, verification, windows]
status: verified
trust: human
last_done: 2026-10-24
version: 1
---

**Problem:** Correctly diagnose missing/incorrect intermediate certificates and avoid blaming client for server chain faults.

**Solution (v1):**
- Read presented chain by priority: Python 3.13+ `get_unverified_chain` → Python 3.10-12 `_sslobj.get_unverified_chain` → `openssl s_client -showcerts` (fallback). Close first connection before fallback for single-connection servers.
- `tls.chain`: judges completeness/linkage of chain server actually sends; `complete/incomplete/broken/NOT TESTED`. Never assumes leaf-only.
- `tls.verify` vs `tls.verify.rootonly`: rootonly validates against trusted roots only (no cached intermediates). If verify passes but rootonly fails → missing intermediate cached on this machine.
- Hostname: SAN-only (CN ignored). CN-only fails.
- Windows: `local.rootca` looks up root the chain leads to (path building), reports NOT TESTED if chain incomplete/broken/unread (doesn't blame client). `local.certutil` validates presented leaf with Windows chain engine automatically.
- Fixed in v0.3.0: chain reading on 3.10-12, root-store crash, SAN-only enforcement.

**Notes:** Evidence records which reader was used. All read-only.
