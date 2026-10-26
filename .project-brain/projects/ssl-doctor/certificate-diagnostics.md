---
project: ssl-doctor
topic: certificate-diagnostics
tags: [audit, verdict, keys, chain, openspec, contract-1.7]
status: in-progress
trust: ai-inferred
last_done: 2026-10-26
version: 3
---

**Problem:** The 45-requirement audit (2026-10-26) found false verdicts. An encrypted server key was a *confirmed* mismatch (sha256 of empty `openssl pkey` output). An expired intermediate gave overall PASS and exit 0. A verify timeout was a certificate cause. Chains were linked by names only, the on-disk certificate's dates were never judged, and PEM parsing was lenient. Plan: openspec change `complete-certificate-diagnostics` (P0–P7, 63 tasks, decisions U1–U7 approved with their defaults).

**Solution (v1, P0 done):**
- Verdict: `analyze` rules pass `explains=(check ids)`. Every other FAIL/WARNING goes to `Diagnosis.unexplained` and still counts.
  - `overall` FAIL = confirmed cause, or an unexplained FAIL that is not transport (`contract.TRANSPORT_FAILURE_KINDS`) and not a session check (`ssh.*`, `srv.os/web/tlsconf/logs`; those count as WARNING).
  - "covered by X" branches count only when X raised a cause.
  - `report._diagnosis_from` must restore `unexplained`, or the HTML recomputes a different verdict.
- Keys:
  - `certs.key_state()` classifies from structure: PEM markers; DER via a minimal TLV walk (EncryptedPrivateKeyInfo = SEQUENCE then OCTET STRING; PKCS#12 = INTEGER 3 then pkcs7-data).
  - Server: `ServerSession._KEY_STATE_SCRIPT` prints only a token.
  - `_PAIRING_SCRIPT` puts per-step failure markers on fd 3; `_EMPTY_SHA256` is never compared.
  - Inconclusive → NOT TESTED with `key-encrypted` / `key-unreadable` / `command-failed` / `verifier-unavailable`.
- `tls.verify` / `rootonly`: `_validation_unfinished` → NOT TESTED with the timeout/reset kind (`tls-alert` stays FAIL); both are pinned to `verified_ip`.
- Contract 1.7:
  - new ids and kinds, `facts.certificates` (chain key → {source, status, trust_class, anchor, revocation, certificates[]}), `diagnosis.unexplained`;
  - `validate()` supports `additionalProperties`;
  - check ids are NOT enforced in the schema (forward compatibility); `unregistered_checks()` reports them instead.
- Guard: `tests/baseline/record.py --check` against `baseline.tsv` (708 ids, recorded as root).
- Fixture: `pki.expired_intermediate` (`openssl ca` with explicit dates; `x509 -req` < 3.4 cannot set past dates), TLSServer mode `expired-intermediate`.
- Tests: `test_private_key_states`, `test_key_pairing`, `test_validation_transport`, `test_verdict_semantics`, `test_exit_code`, `test_contract.CertificateEvidenceTests`.

**Notes:**
- Still open (later phases): R4 expired on-disk `srv.cert` PASS → P3 4.5; R6 truncated/corrupt PEM → P1 2.3; signature linkage → P2.
- Spec amendments made during P0: CEM check-id scenario (registry report, not schema rejection); `facts.certificates` shape; DC verdict counts session failures as WARNING.
- Behaviour change: unexplained warnings (e.g. `srv.logs`, expiring `tls.certvalid`) now make the overall result WARNING.

**v2–v3 (P1–P3 internals):** moved verbatim to [[cert-analysis-internals]] (projects/ssl-doctor/cert-analysis-internals.md) to keep this topic short.
