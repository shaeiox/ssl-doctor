---
project: ssl-doctor
topic: certificate-diagnostics
tags: [audit, verdict, keys, chain, openspec, contract-1.7]
status: in-progress
trust: ai-inferred
last_done: 2026-10-26
version: 2
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

**v2 (P1 done + task 3.1 pulled forward, trust: ai-inferred; branch `feat/complete-certificate-diagnostics`):**
- `certs.parse_cert_bytes()` → `ParsedCertificates(format, certs, problems, key_blocks, other_blocks)`.
  - Formats come from content: PEM labels, DER cert, then `_der_format` (PKCS#7 = first element is the OID signedData; PKCS#12 / keys via `key_state`).
  - Strict blocks: every BEGIN needs an END, Base64 is decoded with `validate=True`, ASN.1 is checked through `_test_decode_cert`. Any problem fails the whole file.
  - `load_cert_file` is a compatibility wrapper.
- `CertInfo` gains `position`, `extensions_read`, `key_type/bits/curve`, `basic_constraints`, `is_ca` (None = not read), `path_len`, `key_usage`, `ext_key_usage`, `aia_ca_issuers`, `ocsp_urls`, `crl_urls`, from `_text_extensions()` (indentation-based parser of `openssl x509 -text`).
- `ssl_doctor/chainval.py`:
  - `verify_link` uses `openssl verify -partial_chain -no_check_time -no-CApath [-no-CAstore] -CAfile parent child` and parses every `error N at D depth`: 7 → signature-failed, 2/20/… → name-mismatch, 24/79 → not-a-ca.
  - `self_signed` = names equal AND (AKI absent or == SKI) AND `-check_ss_sig` OK. Gotcha: openssl skips the self-signature check when AKI ≠ SKI.
  - `classify_roles`: unrelated = not connected to cert 1 by any link, either direction.
  - `inventory_lines`, `file_structure` (CA-first, unrelated), `ca_file_finding` (purpose roots | service).
- `certs.dedupe` / `assess_chain` drop duplicates before linkage; positions are file positions.
- Server: `read_public_file` reads via `head -c 1MiB | base64` with a `cat` fallback (`run()` is text-mode, so `cat` of DER bytes was unsafe). `nginx.chainfile` is FAIL for CA-first and for DER (nginx loads only PEM). `_ca_file_checks` covers `ssl_trusted_certificate` / `ssl_client_certificate`.
- Gotcha: openssl 3.x `verify -CAfile` never adds the default CApath (1.1.1 does), so the isolation test cannot fail on 3.x; `test_isolation_flags_are_passed` asserts the argv instead.
- Spec amendment: a service CA file with intermediates is PASS (nginx documents intermediates in `ssl_trusted_certificate`).
- Not verified here: OpenSSL 1.1.1 (only 3.0.13 installed). Apache `SSLCACertificateFile` waits for 7.2.
- Tests: `test_cert_file_inspection`, `test_certificate_records`, `test_chainval`, `test_chain_file_structure`, `test_ca_bundle`; pki `sample(name)` factory.
