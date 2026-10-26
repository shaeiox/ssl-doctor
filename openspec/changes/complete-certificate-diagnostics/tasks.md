# Tasks

## 1. P0: Baseline, contract 1.7 scaffold and correctness hotfixes

- [x] 1.1 Record the baseline: run `HOME=<tmp> venv/bin/python -m unittest discover -s tests -v`, save the test-id and skip lists under `tests/baseline/` (expected 708 run, 24 skipped); verify the file lists every test id
- [x] 1.2 Contract 1.7 (design D9): `SCHEMA_VERSION = "1.7"`, `schemas/findings-1.7.schema.json`, register every new check id (`chain.validity`, `chain.usage`, `chain.trust`, `cert.policy`, `cert.cafile`, `tls.revocation`, `srv.service`, `srv.configtest`, `srv.reload`, `srv.renewal`, `srv.keystartup`, `srv.inventory`), the new failure kinds, optional `facts.certificates` and `diagnosis.unexplained`; verify `tests/test_contract.py` passes, a new scan document validates against 1.7, and stored 1.0–1.6 samples validate against their own schemas
- [x] 1.3 Key-state classification (PKI "key state is classified", #1): local classifier for legacy-PEM, PKCS#8 PEM, DER `EncryptedPrivateKeyInfo` and PKCS#12; remote probe returning only a state token (design D5); verify `test_private_key_states` covers each format locally and through `LocalSession`
- [x] 1.4 Fix remote pairing (R1, PKI "unextractable digest is inconclusive", #5): per-step exit markers, no digest over empty output, encrypted/failed → NOT TESTED with `failure_kind`; verify `test_regression_r1_encrypted_server_key` (encrypted key → `srv.keymatch` NOT TESTED `key-encrypted`, no "does NOT match") and that the mismatch → FAIL and match → PASS tests pass
- [x] 1.5 Fix local pairing (R8, O3): DER-encrypted → NOT TESTED; an underivable certificate digest → NOT TESTED; verify `test_regression_r8_der_encrypted_key` and `test_regression_o3_cert_pubkey_unextractable`
- [x] 1.6 Classify validation-handshake transport failures (TND "validation handshakes classify transport failures", R5) and pin them to the verified address; verify `test_regression_r5_verify_timeout` (silent listener → `tls.verify`/`rootonly` NOT TESTED `negotiation-timeout`, no certificate cause) and that existing `test_handshake_failure_attribution` passes
- [x] 1.7 Verdict algorithm (DC MODIFIED verdict, design D4): explained-check tracking per rule, `unexplained` list, transport-kind downgrade (U7), notes for NOT TESTED; verify table test `test_verdict_semantics` (expired-intermediate findings → FAIL; transport-only unexplained → WARNING; observation-only → not FAIL; NOT TESTED-only → PASS with notes)
- [x] 1.8 Exit-code consistency (DC "exit code follows the overall verdict"): verify `test_exit_code` runs `cli.main(["-c", "/scan … --client-only"])` against the expired-intermediate TLS fixture → 1, and against a full valid chain → 0 (`test_regression_r2_expired_intermediate_exit`)
- [x] 1.9 CHANGELOG and README: verdict tightening, encrypted-key handling, contract 1.7; verify the README example commands run as written

## 2. P1: Strict parsing and certificate records

- [x] 2.1 Fixture factory: extend `tests/fixtures/pki.py` with truncated, corrupt, duplicate, mixed certificate+key, DER-as-.pem, PKCS#7 and PKCS#12 files; verify the fixtures build or skip with a named reason on `openssl` 1.1.1 and 3.x
- [x] 2.2 Content-based format detection (CFI "format is detected from content", #8); verify `test_format_detection` covers each fixture, and that no key bytes appear in the evidence
- [x] 2.3 Strict block accounting (CFI "malformed and truncated input", #9, R6) for `cert.parse` and `nginx.chainfile`; verify `test_regression_r6_truncated_block`, `test_regression_r6_corrupt_middle_block` and a server-side truncated-file test
- [x] 2.4 Extend the certificate record (position, key type/size/curve, signature algorithm, BC/pathLen, KU, EKU, SKI, AKI, AIA, CDP); verify the record unit tests against fixtures with known values
- [x] 2.5 Per-certificate inventory (CFI #10) and duplicate handling (CFI #12, R7) excluded from linkage; verify `test_inventory_three_certs` and `test_regression_r7_duplicate_not_broken`
- [x] 2.6 Mixed certificate+key files parsed for certificates only (CFI "key content is never shown"); verify the evidence states a key block was ignored, and that the security grep finds no key line
- [x] 2.7 Role classification `leaf` / `intermediate` / `root` / `unrelated` from Basic Constraints and signatures, with the CA-first FAIL (CFI "roles classified", #11); depends on 3.1 for signatures, so it lands with group 3 if 3.1 is not done; verify the reversed-file and unrelated-certificate fixtures
- [x] 2.8 Root/CA bundle parsing as `cert.cafile` for supplied files and `ssl_trusted_certificate` / `SSLCACertificateFile` (CFI "root and CA bundle files", #3); verify the root+intermediate bundle → WARNING and the name-only root not classified as root

## 3. P2: Verified chains

- [x] 3.1 `openssl verify` wrapper (design D1) with a one-time flag probe and the `verifier-unavailable` outcome; verify unit tests with `openssl` present and with `PATH` masked
- [x] 3.2 Canonical name comparison and per-link signature verification (CCV #15, #4, #16); verify `test_regression_r3_forged_intermediate` (→ broken/FAIL) and the wrong-intermediate tests unchanged
- [x] 3.3 Basic Constraints and pathLen (CCV #17); verify `test_regression_r3_non_ca_issuer` and a pathLen fixture
- [x] 3.4 KU/EKU for TLS server authentication (CCV #18) as `chain.usage`; verify the clientAuth-only leaf → FAIL and the CA without keyCertSign → FAIL
- [x] 3.5 Verified self-signature (CCV #21); verify `test_regression_r7_name_only_self_signed` and the genuine self-signed PASS
- [x] 3.6 AKI/SKI-guided issuer selection with lazy root SKI and the ambiguity note (CCV #19); verify the two same-name roots fixture
- [x] 3.7 Bounded path enumeration (CCV #20, design D2 limits); verify the cross-signed fixture lists two paths, and a bounded-limit test
- [x] 3.8 Missing-intermediate naming (AIA, AKI) and the anchored-unknown result (CCV #6, #2); verify the e2e `ScanVerdictTable` still passes and the evidence names the missing issuer
- [x] 3.9 `assess_chain` becomes a compatibility wrapper over the builder, and the presented chain from the primary handshake feeds it unchanged (TND "presented chain feeds the verified chain analysis", #26); verify every existing chain test (`test_tls_inspection`, `test_nginx_config.ChainFileTests`, `test_diagnosis`, `test_scan_e2e`) passes unchanged
- [x] 3.10 Update the brain topic `chain-diagnosis` and the README chain section; verify `brain-check` passes, or the index line is updated

## 4. P3: Trust, lifecycle, policy and hostname rules

- [x] 4.1 Trust evaluation naming the store and anchor count, transport-independent (CCV #22, CTC #25) as `chain.trust`; verify the public, private (`ssl_trusted_certificate`), public-looking unknown and verifier-unavailable fixtures
- [x] 4.2 Anchor validity and empty/unreadable store (CTC #42); verify the expired root → WARNING with limitation, and the empty store → NOT TESTED
- [x] 4.3 Client trust-gap rule (CTC "client trust-store gaps are not blamed on the server"); verify the existing `test_complete_chain_untrusted_root_is_not_missing_intermediate` passes
- [x] 4.4 Per-certificate validity as `chain.validity` and leaf ids (CLP #13, #41); verify the expired and not-yet-valid fixtures, live and configured
- [x] 4.5 `srv.cert` judges dates and SAN (CTC #7, R4); verify `test_regression_r4_expired_on_disk_leaf` via `LocalSession`
- [x] 4.6 Configurable expiry threshold `--expiry-warn-days` and agent job parameter, 1–365, evidence names it (CLP #40); verify boundary tests 30/14/0/400
- [x] 4.7 Key and algorithm policy `policy 1` as `cert.policy` (CLP #14, #43, U6); verify the RSA-1024, P-256, Ed25519, SHA-1 intermediate and SHA-1 root fixtures
- [x] 4.8 Single hostname matcher with IDN, IP-SAN, case, trailing dot, wildcard and public-suffix rules (CHC #23, #24); verify the hostname matrix test, and that `tls.hostname`, `cert.hostname`, `tls.sni` and the domain profile use it
- [x] 4.9 Document the policy table and threshold option in README; verify the documented option runs

## 5. P4: Structured facts and diagnosis rules

- [x] 5.1 Populate `facts.certificates` for presented, configured and supplied chains (CEM); verify `facts.chain_status` is `complete` only for verified anchored paths, and the monitoring condition test for a forged chain fires
- [x] 5.2 Validation-reason cause mapping (DC "every validation error has a specific cause"); verify the expired-intermediate, EKU, failed-signature, non-CA, untrusted/expired anchor and hostname scenarios each raise their named cause
- [x] 5.3 Inconclusive validation and pairing rules (DC "inconclusive validation never becomes a certificate cause", "pairing failures need conclusive key evidence"); verify the R1 and R5 regression tests assert no cause
- [x] 5.4 HTML, JSON and agent reports show the new findings and the `unexplained` list; verify `tests/test_agent_report.py` and a report equality test for an unchanged scan
- [x] 5.5 Service monitor reads `chain.validity` / `tls.revocation` additively; verify `service/tests/test_monitoring.py` (with the PostgreSQL fixture) passes

## 6. P5: Server certificate deployment

- [x] 6.1 Per-scan configured-fingerprint context (design D6, O2); verify `test_regression_o2_stale_compare`
- [x] 6.2 Multiple nginx certificate/key pairs (NCP "every pair", SCD #38, O1) and listen-address block selection; verify the dual RSA/ECDSA fixture, the count-mismatch FAIL and the address-specific listen test
- [x] 6.3 `srv.compare` against every configured leaf, plus full-chain comparison (SCD #35, #27); verify the ECDSA-served PASS, the no-match FAIL and the configured-B-vs-presented-A difference
- [x] 6.4 Role-based permissions in `/scan`, the server agent and `/server cert`, with a worker-account readability check (SCD #34, O5); verify the 0644 `.pem` key WARNING, the www-data-unreadable FAIL, the presence in `/scan` and a non-root CI job
- [x] 6.5 `srv.keystartup` (SCD #39); verify the encrypted key with and without `ssl_password_file`, and that passphrase-file content is never read (command audit)
- [x] 6.6 `srv.inventory` (SCD #44); verify the second-block-covers-domain and served-from-default_server fixtures
- [x] 6.7 Path-resolution FAIL reaches the verdict (NCP "path-resolution failures reach the overall verdict", SCD #33); verify the missing certificate in a verified configuration → overall FAIL
- [x] 6.8 Update the brain topic `server-ssh-nginx` and the commands reference; verify the documented commands match the executed commands list

## 7. P6: Service discovery and runtime state

- [x] 7.1 Listener-owner probe with `ss` / `netstat` fallback, mapped to services (TSD #31); verify the fake `ss` output tests for nginx, caddy, owner-not-visible and no-listener
- [x] 7.2 Apache httpd and HAProxy detection and path extraction under the trusted-binary rule (TSD, SCD #32/#33); verify an Apache vhost fixture, a HAProxy `crt` fixture and an untrusted binary not executed
- [x] 7.3 `srv.configtest` keeping the exit status and a redacted stderr summary; permission-only failure → NOT TESTED (TSD #36, design D8); verify `nginx -t` rc=1, rc=0, permission-only and untrusted-binary cases
- [x] 7.4 `srv.reload` from certificate/key mtime vs worker start and journal/error-log lines (TSD #37); verify the newer-certificate, reloaded, journal-error and unknown cases
- [x] 7.5 `srv.renewal` discovery for certbot/acme.sh/lego, timers and cron, linked by path (TSD #45); verify the linked, installed-but-unlinked and nothing-found cases
- [x] 7.6 Command audit test over a full server scan (TSD "never a state change"); verify no executed command matches the forbidden patterns

## 8. P7: Network extras (may run in parallel with 6–7 once 5 is done)

- [x] 8.1 Family-balanced endpoint selection and family labels, plus family-level difference wording (EC #28); verify mocked 5×v4 + 2×v6, v6-only difference, v6-unreachable, and a real `::1` test or a named skip
- [x] 8.2 Request OCSP stapling and capture the stapled response (TND "requests a stapled OCSP response"); verify against an `openssl s_server -status_file` fixture
- [x] 8.3 `tls.revocation` states and response validity checks, stapled by default, `--revocation=online|off` (REV #30, U4); verify good, revoked, stale, unreachable responder (mocked), `unavailable` and `not-checked`
- [x] 8.4 Document the revocation option and its privacy implications in README; verify the documented flags run

## 9. Integration and regression gate

- [x] 9.1 Full-suite comparison against the 1.1 baseline: no test id removed, no unexplained new skip, and `tests/test_sni_observation` (#29, unchanged behaviour) and `tests/test_tls_inspection.PresentedChainTests` (#26) are still green; verify with a diff of the `-v` outputs
- [x] 9.2 Security grep over every export path (stdout, JSON, HTML, agent report, upload payload) for every fixture key and passphrase line; verify zero matches
- [x] 9.3 End-to-end `/scan --with-server` against a `LocalSession` nginx fixture with an expired intermediate, an encrypted key with `ssl_password_file`, and a certificate newer than the workers; verify the diagnosis names all three causes and the exit code is 1
- [x] 9.4 Re-run the audit's 45-row matrix against the implementation and record each row's new status with its test id; verify every row references a passing test

## Workflow follow-up

- Resolve decisions U1–U7 in design.md with the maintainer before starting group 1.
- Coordinate with the unarchived `fix-chain-diagnosis-saas-enterprise` and `fix-tls-handshake-timeout-attribution` changes. Archive those first, or amend `tls-certificate-inspection` per U1, before archiving this change.
- Archive this change after review and verify that the new capabilities land under `openspec/specs/`.
