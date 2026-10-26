---
project: ssl-doctor
topic: chain-diagnosis
tags: [tls, chain, openssl, s_client, verification, windows]
status: done
trust: human
last_done: 2026-10-26
version: 2
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

**v2 (2026-10-26, trust: ai-inferred; openspec complete-certificate-diagnostics P2 — v1 above unchanged):**
- Linkage is cryptographic. `certs.assess_chain` wraps `chainval.assess`: adjacency as sent via `verify_link` (openssl verify; name → misordered WARNING; signature / not-a-ca / pathLenConstraint → FAIL).
- Then the top: a verified self-signed top is complete. Otherwise `_paths` does bounded DFS (8 paths, depth 8) over the sent certificates plus anchors, with AKI-first candidate order and a note when same-name roots exist. Otherwise a verified multi-cert chain stays `complete` with `anchored=False` ("anchor unknown"), never "missing intermediates" (client-trust question). A single non-CA leaf is `incomplete`, naming the missing issuer, AKI and AIA.
- Findings carry `failure_kind` chain-signature / misordered / incomplete / unverified / hygiene / wrong-leaf; `analyze` correlates on it (legacy text matching only when the kind is empty).
- `tls.chain` now always receives the trust anchors (previously only for 1-cert chains), and `nginx.chainfile` and `cert.chainfile` do too.
- `chain.usage`: EKU serverAuth, KU vs key type, issuers need keyCertSign; its cause explains a tls.verify "unsuitable purpose".
- Names compare canonically (`CertInfo.subject_canon` / `issuer_canon`: casefold, collapsed whitespace).
- Gotcha: openssl 3.x `verify -CAfile` does not add the default CApath; `-no-CApath` matters for 1.1.1.
