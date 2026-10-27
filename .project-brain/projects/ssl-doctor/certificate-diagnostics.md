---
project: ssl-doctor
topic: certificate-diagnostics
tags: [audit, verdict, keys, chain, openspec, contract-1.7]
status: done
trust: ai-inferred
last_done: 2026-10-27
version: 5
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

**v4 (integration gate, 9.1–9.4, all 63 tasks done):** record in `openspec/changes/complete-certificate-diagnostics/verification.md`.
- 9.1: `record.py --check` → 958 ids (+250), 0 removed, 0 newly skipped, 0 failing; the only new skips are the 2 root-only `test_private_key_states.*.test_unreadable_file`.
- 9.2 `tests/test_secret_exports.py`, 9.3 `tests/test_gate_end_to_end.py` (real TLS endpoint + nginx fixture on the same port, through `cli.main`, exit 1).
- 9.3 interpretation: encrypted key *with* `ssl_password_file` = note + `srv.keystartup` PASS, not a cause (D3).
- 9.4: 45/45 rows Yes/Yes; 140 matrix test ids checked against the run, all ok.
- Gotcha: run the suites with `venv/bin/python` (has `psycopg`); with system python 4 service-importing tests skip and `--check` reports "added, skipped here". Service suite: from `service/tests`, `PYTHONPATH=.:../..:../../tests:..`; its 1 failure (`test_unreadable_nginx_config_is_not_tested_with_reason`) predates the change (root run).
- Next: review, then archive after the two older unarchived changes (tasks.md "Workflow follow-up").

**v5 (2026-10-27): follow-up audit A–H → openspec change `fix-diagnostic-false-positives`, branch `fix/diagnostic-false-positives` (23/23 tasks; U1 `local.*` unexplained FAIL = WARNING, U2 clock reference ≤120 s).** Per-fix details live in its design.md and verification.md, and in the CHANGELOG.
- Gotchas:
  - `datetime.now()` is often earlier than a preceding `time.time()` → round ages, never `int()`.
  - Running the suite as `nobody` breaks the tests that use `nobody` as the service account.
  - In shell `"…"` inside Python strings, `\\.` collapses → use `[.]`.
  - nginx's default listen port is 80.
- Archive order: the two older changes → `complete-certificate-diagnostics` → this change.
