---
project: ssl-doctor
topic: legacy-tls-diagnosis-semantics
tags: [tls, diagnosis, uncertainty, unresolved, endpoint-coverage, contract]
status: done
trust: ai-inferred
last_done: 2026-10-24
version: 1
---

Builds on [[protocol-policy-evidence]] (classification unchanged); supersedes its
remediation text "treat legacy TLS as enabled until proven otherwise".
v1 classification kept. v1 remediation ("treat legacy TLS as enabled until proven
otherwise") is superseded.

**Problem:** google.com scan — classification correct, but remediation presumed
legacy enabled, the open WARNING was only a note + generic "some checks report
warnings/failures", and a 4-of-7 endpoint match did not say it was partial.

**Solution (v2)**
- `facts.probe_policy.default_probe` = raw default-policy state per re-probed
  version (`client-limited` = never sent ≠ `refused`).
- `Finding.uncertainty` (why the evidence cannot settle it), separate from evidence.
- `Diagnosis.unresolved` (`analyze.Unresolved`: observed / conclusion / uncertainty
  / recommendation) replaces the free-text note; rendered in CLI + HTML.
  `_finish` names unexplained severe findings instead of the generic message.
- Unverified-legacy remediation = controlled `openssl s_client -tls1/-tls1_1` test
  with its limitations; server config is authoritative.
- `endpoint_comparison.addresses` + "N of M DNS address(es) were not compared".
- Contract 1.5 (additive), `schemas/findings-1.5.schema.json`.

**Tests:** `tests/test_legacy_tls_semantics.py` (12; 10 fail on pre-change code).
Suite: 152 tests, OK (6 skipped).
