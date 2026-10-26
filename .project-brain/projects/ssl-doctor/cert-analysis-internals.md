---
project: ssl-doctor
topic: cert-analysis-internals
tags: [certs, chainval, certpolicy, hostnames, parsing, trust, openssl]
status: in-progress
trust: ai-inferred
last_done: 2026-10-26
version: 2
---

**Problem:** How the certificate-analysis core works after complete-certificate-diagnostics P1–P3 (moved from certificate-diagnostics v2/v3, unchanged).

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

**v3 (P3 done, trust: ai-inferred):**
- `ssl_doctor/hostnames.py`: one matcher (`covers`, `why_not`) behind `CertInfo.matches_hostname` / `hostname_match`. Rules: IDN to A-label, IPs only against iPAddress entries, one-label wildcard, no partial or non-left-most wildcard, no wildcard over `*.tld` or an embedded multi-label public-suffix list (not the full PSL).
- `ssl_doctor/certpolicy.py`:
  - `leaf_validity` uses the module-level threshold (`set_warn_days` / `parse_warn_days`, 1–365, default 30). CLI `--expiry-warn-days` exits 2 on a bad value; the agent takes `job.options.expiry_warn_days` and restores the threshold afterwards; the service `next_job` sends the target's `expiry_threshold_days`.
  - `chain_validity_finding` (non-leaf certificates; an intermediate expiring before the leaf → "chain stops validating on").
  - `policy_finding` ("policy 1"; an anchor's own self-signature is not judged).
- `chainval.trust_finding`: public / private / self-signed / unknown, offline. Public needs the anchor in the store (`_in`, matched by sha256 or subject + SKI). Private comes from service CA files (`ServerSession._service_cas`, set in `_ca_file_checks`). An expired anchor warns with uncertainty; an empty store is NOT TESTED. `ChainAssessment.anchor_cert` was added.
- `srv.cert` is judged from its `openssl x509` output (dates + SAN against the scanned domain via `_judge_configured_cert`). `nginx_scan` stores `_nginx_domain`.
- `analyze` causes: chain.validity FAIL (also explains tls.verify "expired"), srv.cert dates/SAN, cert.policy FAIL. Verify and chain causes also explain chain.trust.
- Gotchas:
  - fixtures live 30 days, so a leaf is always within the default threshold (WARNING); threshold tests build their own dates.
  - `openssl x509 -req -sha1` still signs on 3.0.
- Service suite: 77 tests. 1 failure is pre-existing (`test_unreadable_nginx_config_is_not_tested_with_reason`, fails as root, also on 2f70fb0).

**v2 (P4, trust: ai-inferred):**
- `chainval.classify_trust` is the single trust decision, shared by `trust_finding` and `certificates_fact`.
- `facts.certificates` comes from `netchecks.export_facts`: presented from facts["chain"], plus facts["certificate_chains"] (CLI: `/cert inspect` → supplied, server `chain_facts` → configured, merged in `_report_inputs`). Server-agent docs carry `facts: {certificates}` only.
- monitor: `evaluate` gates on `facts.leaf` (both the doc and the prev query), so cert-only docs are ignored. New STATEFUL conditions `chain_certificate_invalid` (remote-net `chain.validity` FAIL) and `revoked`.
- analyze: `chain.trust` private/unknown → `Unresolved` (no cause; this machine's store is not the client's); expired anchor / self-signed → probable causes. Existing `test_wildcard_vhost_is_not_a_cause` caught the first draft blaming configured chains.
- Reports: agent md `### 5.8 Unexplained findings` (top-level sections stay 7); HTML `[UNEXPLAINED · check · status]`; CLI `/diagnose` prints them.
