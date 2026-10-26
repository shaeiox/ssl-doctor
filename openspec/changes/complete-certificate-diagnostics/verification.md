# Verification — complete-certificate-diagnostics (integration gate, group 9)

Run on 2026-10-26, branch `feat/complete-certificate-diagnostics`, Linux, as
root (same conditions as `tests/baseline/baseline.tsv`), with the system
`openssl` present. Nothing in the gate reloads, restarts or signals a service,
and no test reads key or passphrase content into its output.

## 9.1 Full-suite comparison against the baseline

Command: `venv/bin/python tests/baseline/record.py --check`. It compares the
ids and outcomes of the whole `tests/` suite with `baseline.tsv`, recorded at
v0.10.1. Service suite: from `service/tests`, run
`PYTHONPATH=.:../..:../../tests:.. ../../venv/bin/python -m unittest discover -s .`.
Use the project `venv`. Outside it `psycopg` is missing, so 4 tests that import
the service package skip themselves, and `--check` lists them as "added,
skipped here".

| | Baseline | Now |
|---|---|---|
| Test ids | 708 | 958 (+250) |
| Removed ids | — | 0 |
| ok / skipped / fail / error | 684 / 24 / 0 / 0 | 932 / 26 / 0 / 0 |
| Baseline ids that changed outcome | — | 0 |

- **New skips: 2, both new ids, both explained.**
  `test_private_key_states.LocalKeyStates.test_unreadable_file` and
  `test_private_key_states.RemoteKeyStates.test_unreadable_file` need a file
  the test user cannot read, which root can always read. They run as a
  non-root user. The 24 baseline skips are unchanged.
- **#29 (behaviour unchanged):** all 8 `test_sni_observation` tests are ok,
  as in the baseline.
- **#26:** all 5 `test_tls_inspection.PresentedChainTests` tests are ok, as in
  the baseline.
- The service suite (`service/`) has 1 failure that predates this change:
  `test_unreadable_nginx_config_is_not_tested_with_reason`. It also fails at
  `2f70fb0` (before group 1), because a root run can read the "unreadable"
  file. No other service test fails.

## 9.2 No secret in any export path

`tests/test_secret_exports.py` (2 tests, ok). One session meets every secret
the checks can come across:
- a PKCS#8 key encrypted with AES-256, plus an `ssl_password_file`;
- a certificate file that also holds its private key;
- an SSH password.

The test collects every base64 line of both keys, the passphrase and the SSH
password, then greps them against:
- terminal output of `/server nginx`, `/server services`, `/cert inspect`,
  `/cert match`, `/diagnose` and `/findings`;
- the JSON, HTML and agent-Markdown reports written by `/report`;
- the document that `agent.run_server_checks` uploads.

Result: zero matches. The test also asserts that the encrypted key was
actually met (`srv.keystartup` and `cert.keymatch` are present), so a clean
result cannot come from skipped checks.

## 9.3 End-to-end `/scan --with-server`

`tests/test_gate_end_to_end.ScanWithServer.test_scan_names_every_problem_and_exits_one`
(ok). It runs through `cli.main(["--no-tui", "-c", "/scan … --with-server"])`
against a real local TLS endpoint that serves an expired intermediate. The
server side is the nginx fixture, configured with:
- that chain file;
- an encrypted key with an existing `ssl_password_file`;
- workers started 10 minutes ago, while the certificate file is newer.

Outcome:
- **Expired intermediate:** named as a cause ("… outside its validity period").
- **Missing reload:** `srv.reload` is WARNING, and it is named as a cause.
- **Encrypted key:** named in the diagnosis notes ("passphrase-encrypted"), and
  `srv.keystartup` is PASS.
- **Verdict:** overall FAIL, exit code 1.

**Interpretation, recorded here deliberately.** The task asks for "all three
causes". The design (D3, "Encrypted key compatibility") says an encrypted key
*with* an existing `ssl_password_file` starts correctly, so it is not a defect.
Raising it as a cause would contradict the spec. The scan therefore names it in
the notes and passes `srv.keystartup`. The same key without a passphrase file is
a cause:
`test_server_deployment.KeyStartup.test_encrypted_key_without_ssl_password_file`.

## 9.4 The audit's 45-row matrix, re-run

Columns: **Impl** = implemented, **Complete** = complete and correct (the
audit's two Yes/No columns), then the tests that prove the row.

Every test id listed below was checked against the 9.1 run: each is present
and `ok`, and none is skipped. Abbreviations: `M.C.t` = `test_M.C.test_t`; ids
in one cell share a module unless prefixed.

| # | Requirement | Audit | Now | Covering tests | Remaining limitation |
|---|---|---|---|---|---|
| 1 | Encrypted private key detection | Yes / No | Yes / Yes | `private_key_states.LocalKeyStates.every_format_is_classified`, `private_key_states.RemoteKeyStates.every_format_is_classified`, `key_pairing.ServerPairing.regression_r1_encrypted_server_key`, `key_pairing.LocalPairing.regression_r8_der_encrypted_key` | — |
| 2 | Full chain detection in CRT/PEM files | Yes / No | Yes / Yes | `chain_file_structure.Roles.roles_come_from_constraints_and_signatures`, `chain_validation.Signatures.full_chain_says_signatures_verified` | — |
| 3 | Root certificate file completeness | No / No | Yes / Yes | `ca_bundle.SuppliedRootFile.genuine_root_file_passes`, `.SuppliedRootFile.name_only_root_is_not_a_root`, `.ServiceCaFile.leaf_in_a_service_ca_file_warns`, `.ServiceCaFile.intermediates_in_a_service_ca_file_are_normal` | — |
| 4 | Certificate and CA chain matching | Yes / No | Yes / Yes | `chainval.Links.forged_intermediate_with_same_name_and_ski_fails`, `chain_validation.Signatures.regression_r3_forged_intermediate` | — |
| 5 | Private key and certificate matching | Yes / No | Yes / Yes | `key_pairing.LocalPairing.mismatched_pair_fails`, `.ServerPairing.mismatched_pair_fails_with_both_digests`, `.ServerPairing.failed_digest_step_is_not_tested`, `.ServerPairing.an_empty_digest_is_never_compared` | — |
| 6 | Missing intermediate detection | Yes / No | Yes / Yes | `chain_validation.MissingIntermediate.missing_issuer_is_named_with_its_aia_url`, `validation_transport.GenuineVerificationErrors.missing_intermediate_still_fails_rootonly` | — |
| 7 | Domain and trust validation | Yes / No | Yes / Yes | `lifecycle_policy.ConfiguredCertificate.regression_r4_expired_on_disk_leaf`, `.ConfiguredCertificate.configured_certificate_not_covering_the_domain` | — |
| 8 | Certificate file format detection | Yes / No | Yes / Yes | `cert_file_inspection.FormatDetection.format_detection`, `.FormatDetection.pkcs12_without_extension`, `.FormatDetection.pkcs7_names_the_conversion`, `.ConfiguredFileOnServer.der_ssl_certificate_file_fails_because_nginx_needs_pem` | — |
| 9 | Malformed or incomplete file detection | Yes / No | Yes / Yes | `cert_file_inspection.StrictParsing.regression_r6_truncated_block`, `.StrictParsing.regression_r6_corrupt_middle_block`, `.StrictParsing.malformed_asn1_inside_valid_base64` | — |
| 10 | Multiple certificates in one file | Yes / No | Yes / Yes | `chain_file_structure.Inventory.inventory_three_certs`, `.Inventory.server_file_inventory` | — |
| 11 | Incorrect certificate in the CRT file | Yes / No | Yes / Yes | `chain_file_structure.Roles.intermediate_first_fails_on_the_server`, `.Roles.unrelated_certificate_is_named`, `lifecycle_policy.ConfiguredCertificate.configured_certificate_not_covering_the_domain` | — |
| 12 | Duplicate certificate detection | No / No | Yes / Yes | `chain_file_structure.Duplicates.regression_r7_duplicate_not_broken`, `.Duplicates.duplicate_in_presented_chain_order_keeps_positions` | — |
| 13 | Expired or not-yet-valid certificates | Yes / No | Yes / Yes | `lifecycle_policy.EveryCertificate.expired_and_not_yet_valid_intermediates`, `.EveryCertificate.not_yet_valid_leaf`, `.EveryCertificate.problems_do_not_hide_each_other` | — |
| 14 | Key strength and algorithm analysis | No / No | Yes / Yes | `lifecycle_policy.Policy.rsa_1024_fails`, `.Policy.p256_and_ed25519_pass` | Policy table "policy 1" is fixed (design U5) |
| 15 | Issuer and subject relationship | Yes / No | Yes / Yes | `chain_validation.Signatures.equivalent_names_in_another_case_match`, `chainval.Links.wrong_name_is_a_name_mismatch`, `chain_validation.Signatures.wrong_intermediate_is_still_a_misordered_warning` | — |
| 16 | Certificate signature verification | No / No | Yes / Yes | `chainval.Links.genuine_issuer_is_verified`, `chainval.Links.the_system_store_is_never_consulted`, `chain_validation.Signatures.forged_chain_raises_a_signature_cause`, `chain_validation.Signatures.without_openssl_a_chain_is_never_pass` | Needs the system `openssl`; without it the result is NOT TESTED (`verifier-unavailable`) |
| 17 | Basic constraints validation | No / No | Yes / Yes | `chain_validation.CaConstraints.regression_r3_non_ca_issuer`, `.CaConstraints.path_length_exceeded`, `certificate_records.RecordFields.no_basic_constraints_is_not_a_ca` | — |
| 18 | Key usage and extended key usage | No / No | Yes / Yes | `chain_validation.Usage.client_only_leaf_fails`, `.Usage.ca_without_keycertsign_fails`, `.Usage.diagnosis_names_the_usage_cause_not_a_generic_failure` | — |
| 19 | AKI / SKI analysis | Yes / No | Yes / Yes | `certificate_records.RecordFields.intermediate_path_length_and_identifiers`, `certificate_records.RecordFields.root`, `chain_validation.Anchors.two_same_name_roots_pick_the_key_identifier_match` | — |
| 20 | Alternative certificate chain detection | No / No | Yes / Yes | `chain_validation.Anchors.cross_signed_chain_lists_both_paths`, `.Anchors.only_the_legacy_path_validates`, `.Anchors.path_enumeration_is_bounded` | Bounded to 8 paths, depth 8 (design D2) |
| 21 | Self-signed certificate detection | Yes / No | Yes / Yes | `chainval.SelfSigned.name_only_self_signed_is_not_self_signed`, `chain_validation.SelfSigned.regression_r7_name_only_self_signed`, `chain_validation.SelfSigned.genuine_self_signed_leaf_is_verified` | — |
| 22 | Chain validation to a trust anchor | Yes / No | Yes / Yes | `validation_transport.StalledValidation.regression_r5_verify_timeout`, `validation_transport.GenuineVerificationErrors.validation_names_the_pinned_address`, `exit_code.BatchExitCode.regression_r2_expired_intermediate_exit`, `certificate_facts.ValidationCauses.expired_anchor_has_a_named_cause` | — |
| 23 | SAN-to-hostname validation | Yes / No | Yes / Yes | `hostname_coverage.Matrix.hostname_matrix`, `.Matrix.cn_only_certificate_is_not_covered`, `.OneMatcher.every_coverage_check_uses_the_matcher` | — |
| 24 | Wildcard hostname validation | Yes / No | Yes / Yes | `hostname_coverage.Matrix.hostname_matrix` (wildcard and public-suffix rows), `.Matrix.reasons_are_given` | — |
| 25 | Public / private / self-signed trust classification | Yes / No | Yes / Yes | `trust_classification.TrustClass.public_names_store_and_anchor`, `.TrustClass.private_ca_from_ssl_trusted_certificate`, `.TrustClass.self_signed`, `.TrustClass.public_looking_issuer_is_unknown` | — |
| 26 | Live internet server chain inspection | Yes / Yes | Yes / Yes | `tls_inspection.PresentedChainTests.full_chain_is_two_certs`, `.PresentedChainTests.s_client_fallback_reads_same_chain`, `.PresentedChainTests.unreadable_chain_is_not_tested`, `certificate_facts.CertificateFacts.presented_chain_facts` | Unchanged; the audit's optional pin of the `s_client` fallback was not in scope |
| 27 | Local-to-live chain comparison | Yes / No | Yes / Yes | `server_deployment.Compare.served_intermediate_differs_from_the_file`, `.Compare.no_configured_certificate_matches` | — |
| 28 | IPv4 and IPv6 comparison | Yes / No | Yes / Yes | `revocation.AddressFamilies.both_families_are_probed_and_labelled`, `.AddressFamilies.ipv6_only_difference`, `.AddressFamilies.ipv6_unreachable_is_not_a_difference`, `.AddressFamilies.real_ipv6_loopback` | — |
| 29 | SNI validation | Yes / Yes | Yes / Yes | `sni_observation.SniObservationTests.different_default_certificate_is_only_an_observation`, `.SniObservationTests.no_sni_probe_failure_is_inconclusive_not_a_warning`, `.SniObservationTests.observation_corroborates_an_independent_hostname_failure` | Unchanged (behaviour kept on purpose) |
| 30 | OCSP and CRL status checking | No / No | Yes / Yes | `revocation.Stapled.good_and_revoked`, `.Stapled.stale_stapled_response`, `.States.crl_revoked_and_good`, `.States.unreachable_responder_is_inconclusive`, `.InTheScan.revoked_leaf_is_a_confirmed_cause_and_an_alert` | Default is stapled only; `--revocation online` contacts the CA (design U4/D7); the online responder is mocked in tests |
| 31 | Certificate-consuming service detection | Yes / No | Yes / Yes | `service_discovery.Listener.nginx_owns_the_port`, `.Listener.unsupported_terminator`, `.ApacheAndHaproxy.haproxy_crt_with_crt_base` | Terminators other than nginx/Apache/HAProxy are an observation (`listener-unsupported`), not parsed |
| 32 | Actual certificate and key path discovery | Yes / No | Yes / Yes | `server_deployment.MultiplePairs.rsa_and_ecdsa_pairs_are_both_validated`, `service_discovery.ApacheAndHaproxy.apache_vhost_from_a_custom_configuration`, `nginx_cert_paths.Provenance.file_and_line_of_the_directive` | — |
| 33 | Service configuration path validation | Yes / No | Yes / Yes | `server_deployment.PathFailureVerdict.missing_certificate_in_a_verified_configuration`, `verdict_semantics.VerdictTable.path_resolution_failure_reaches_the_verdict`, `nginx_cert_paths.PathResolutionFinding.missing_certificate_is_fail_and_validation_not_tested` | `nginx_cert_paths.FileStatesScript.denied_and_unreachable` is still skipped as root (baseline skip); it runs as a non-root user |
| 34 | Certificate and key file permissions | Yes / No | Yes / Yes | `server_deployment.Permissions.service_account_cannot_read_the_certificate`, `.Permissions.world_readable_key_named_pem_warns`, `.Permissions.permissions_run_in_the_nginx_scan`, `.Permissions.no_content_is_read` | — |
| 35 | On-disk versus active certificate | Yes / No | Yes / Yes | `server_deployment.PerScanContext.regression_o2_stale_compare`, `.Compare.ecdsa_certificate_served_from_a_dual_configuration` | — |
| 36 | Service configuration validation | No / No | Yes / Yes | `service_discovery.ConfigTest.passing_test`, `.ConfigTest.failing_test_keeps_status_and_message`, `.ConfigTest.permission_only_failure_is_not_tested`, `.NeverAStateChange.real_probe_commands_are_read_only` | — |
| 37 | Reload and restart state | Yes / No | Yes / Yes | `service_discovery.Reload.certificate_newer_than_the_workers`, `.Reload.journal_errors`, `.Reload.reloaded_after_renewal`, `gate_end_to_end.ScanWithServer.scan_names_every_problem_and_exits_one` | — |
| 38 | Multiple certificates and virtual hosts | Yes / No | Yes / Yes | `server_deployment.MultiplePairs.listen_address_selects_the_block`, `.MultiplePairs.more_certificates_than_keys_fails`, `service_discovery.ApacheAndHaproxy.apache_vhost_from_a_custom_configuration` | — |
| 39 | Encrypted key and service startup | No / No | Yes / Yes | `server_deployment.KeyStartup.encrypted_key_without_ssl_password_file`, `.KeyStartup.encrypted_key_with_a_passphrase_file_never_reads_it`, `secret_exports.NoSecretInAnyExport.every_cli_export` | — |
| 40 | Certificate expiration warning | Yes / No | Yes / Yes | `lifecycle_policy.Threshold.boundaries`, `.Threshold.cli_sets_the_threshold`, `.Threshold.cli_refuses_an_out_of_range_threshold_and_runs_nothing`, `.Threshold.agent_job_option` | — |
| 41 | Intermediate certificate expiration | No / No | Yes / Yes | `lifecycle_policy.EveryCertificate.live_expired_intermediate_is_named`, `.EveryCertificate.intermediate_expiring_before_the_leaf`, `exit_code.BatchExitCode.regression_r2_expired_intermediate_exit`, `verdict_semantics.VerdictTable.regression_r2_expired_intermediate_is_fail` | — |
| 42 | Root expiration and trust store issues | No / No | Yes / Yes | `trust_classification.AnchorsAndStores.expired_anchor_warns_with_a_limitation`, `.AnchorsAndStores.empty_store_is_not_tested`, `.TrustClass.public_names_store_and_anchor` | — |
| 43 | Deprecated cryptographic algorithms | Yes / No | Yes / Yes | `lifecycle_policy.Policy.sha1_intermediate_fails`, `.Policy.sha1_root_self_signature_is_not_judged`, `.Policy.policy_failure_is_a_cause` | — |
| 44 | Alternative or unexpected certificate | Yes / No | Yes / Yes | `server_deployment.Inventory.served_certificate_from_the_default_server`, `.Inventory.another_block_covering_the_domain_warns` | — |
| 45 | Certificate renewal capability | No / No | Yes / Yes | `service_discovery.Renewal.certbot_manages_the_certificate`, `.Renewal.installed_but_not_linked`, `.Renewal.nothing_found_does_not_claim_manual_renewal` | Discovery is read-only; no renewal is ever run |

**Result: 45 of 45 rows are implemented and complete, each covered by passing
tests.** The audit had 2 complete rows (#26, #29); both still pass unchanged.
The "Remaining limitation" column lists the bounds the design set on purpose.
None of them makes a row incomplete.
