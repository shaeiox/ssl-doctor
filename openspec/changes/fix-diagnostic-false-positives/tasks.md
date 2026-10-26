# Tasks

## 1. Verdict weighting for client-machine checks (H, decision U1)

- [x] 1.1 Confirm decision U1 (recommended: option b) and U2 (120 s window) with the maintainer, and record them in `design.md` and `.project-brain/projects/ssl-doctor/_decisions.md`; verify both lines exist
- [x] 1.2 `Unexplained.decides_verdict` treats `local.*` like the session checks (design D7); verify new `test_verdict_semantics` cases:
  - healthy endpoint + unexplained `local.clockskew` FAIL → WARNING, exit 0, still listed under unexplained;
  - probable certutil client cause → WARNING;
  - a confirmed cause still gives FAIL.
- [x] 1.3 Document the behaviour change (BREAKING for exit-code consumers) in `CHANGELOG.md` and `docs/findings-contract.md`; verify the wording matches the spec scenario "Unexplained client-machine failure"

## 2. `srv.configtest` permission limits (B)

- [ ] 2.1 Fixtures from real output in `tests/test_service_discovery.py`, each a captured multi-line string:
  - non-root `nginx -t` (error-log alert, `syntax is ok`, pid `[emerg]`, `test failed`);
  - unreadable `ssl_certificate_key`;
  - unknown directive with a permission alert;
  - Apache `AH00526` syntax error;
  - HAProxy `[ALERT]`.
  - The existing `test_permission_only_failure_is_not_tested` fixture gains the `test failed` trailer.
  - Verify the new non-root test fails before the fix.
- [ ] 2.2 Error-level classification in `services.classify_config_test` (design D2): summary lines excluded, `syntax is ok` kept as evidence, unreadable paths listed, non-zero exit without error-level lines → NOT TESTED `command-failed`; verify the 2.1 tests:
  - permission → NOT TESTED `permission-denied`, no cause, overall not FAIL;
  - mixed → FAIL;
  - syntax error → FAIL with a confirmed cause.
- [ ] 2.3 Verify `NeverAStateChange` still passes: no sudo, test modes only (spec "never escalates privileges")

## 3. `srv.perms` on the resolved target (F)

- [ ] 3.1 Probe with link type, `readlink -f`, `stat -L` and the ACL marker in one command, with `Permission denied` from `stat -L` → NOT TESTED `permission-denied` (design D4); verify with `FakeSession` on real scratch files in `tests/test_server_deployment.Permissions`:
  - certbot-style `live/` → `archive/` symlink to 0600 → PASS, naming link and target;
  - symlink to 0644 → WARNING naming the target;
  - non-root master with a 0600 root target → FAIL;
  - untraversable parent → NOT TESTED (skipped as root, with the reason).
- [ ] 3.2 ACL presence as an uncertainty, plus a specific recommendation naming the target path, mode and service group; verify:
  - a test with a mocked `ls -ldL` output carrying `+`;
  - the 0644 recommendation names the file and `0600`/`0640`.
- [ ] 3.3 Verify `Permissions.test_no_content_is_read` still passes, and that the command audit shows only metadata commands

## 4. `srv.inventory` by identity and listener (C)

- [ ] 4.1 Record listen ports per block and the scanned port (design D5), with unparseable `listen` → "can answer"; verify unit tests for `listen 443 ssl`, `[::]:443`, `127.0.0.1:8443`, bare `listen ssl`, and a variable
- [ ] 4.2 Shared-certificate handling in `inventory_finding`; verify new tests in `tests/test_server_deployment.Inventory`:
  - redirect block sharing the certificate → PASS, "shares the certificate", no cause;
  - same name on 8443 → no warning;
  - no presented certificate → PASS with an uncertainty, no cause;
  - the existing `test_another_block_covering_the_domain_warns` and `test_served_certificate_from_the_default_server` still pass.
- [ ] 4.3 Update the inventory cause in `analyze.py` so it is raised only for a WARNING; verify `diagnose` on the 4.2 cases gives no "Another configured certificate could answer" cause, and overall PASS when nothing else fails

## 5. `local.certutil` from the exit status (A)

- [ ] 5.1 New `tests/test_client_machine.py` with mocked `subprocess.run` (design D1); verify these cases fail before the fix:
  - success with `dwErrorStatus=0` chain dump;
  - success with an "error" subject;
  - success with an unreachable CDP URL;
  - localised success;
  - `FAILED: 0x800b010a`;
  - `PermissionError` on start;
  - timeout.
- [ ] 5.2 Exit-status classification, error code in the FAIL evidence, URL-failure evidence line, `OSError` → NOT TESTED, `errors="replace"` decoding; verify all 5.1 cases give PASS, PASS, PASS (with the URL line), PASS, FAIL (with the code), NOT TESTED, NOT TESTED

## 6. `local.clockskew` with a timed reference (D)

- [ ] 6.1 `check_https` records the receive time, round-trip time, source host and `Age` for the `Date` it keeps (design D3); verify with the existing local TLS/HTTP fixture server that the facts are set, and that a redirect to another host names that host
- [ ] 6.2 `check_os_and_clock` uses the receive time, the 120 s freshness window, the `Age` correction and the uncertainty margin; verify `tests/test_client_machine.py` cases:
  - stale reference (360 s) → NOT TESTED;
  - `Age: 600` → PASS with "Age correction";
  - 60/61/300/301 s with 0 s and 3 s uncertainty → PASS/WARNING/WARNING/FAIL and WARNING at 301 s ± 3 s;
  - malformed `Age` → NOT TESTED.
- [ ] 6.3 The clock cause requires a date-related verify error; verify missing issuer + skew FAIL → no "date errors" cause, and "certificate has expired" + skew FAIL → probable client cause
- [ ] 6.4 Document the clock-skew evidence (time source, uncertainty, freshness) in `docs/command-used.md` or README; verify the documented `/tls` then `/local` sequence produces the documented NOT TESTED wording

## 7. `srv.renewal` with source visibility (G)

- [ ] 7.1 Visibility markers in the renewal probe and the `hidden` set in `parse_renewal` (design D6); verify:
  - `test_real_probe_commands_are_read_only` still passes;
  - a `LocalSession` run of the real script on this host prints one marker per source.
- [ ] 7.2 `renewal_for`: no fallback to unrelated schedules; hidden schedule source → NOT TESTED `permission-denied`; hidden acme.sh home with nothing found → NOT TESTED naming it; verify new `test_service_discovery.Renewal` cases:
  - root crontab hidden → NOT TESTED, no cause;
  - all visible + no schedule → WARNING;
  - only a lego cron for a certbot certificate → not PASS;
  - the existing three cases are unchanged.

## 8. Integration gate

- [ ] 8.1 Full-suite comparison: `venv/bin/python tests/baseline/record.py --check` reports 0 removed and 0 failing, and any new skip has a named reason; the service suite has no new failures
- [ ] 8.2 Re-run the audit reproductions (`audit2/*.py`) against the branch; verify each of A, B, C, D, F and G now gives the "expected behaviour" from the audit report, and record the results in `openspec/changes/fix-diagnostic-false-positives/verification.md`
- [ ] 8.3 `openspec validate fix-diagnostic-false-positives --strict` passes, and the brain topic, `_decisions.md` and resume line are updated; verify `brain-check` reports 0 warnings

## Workflow follow-up

- Archive `fix-chain-diagnosis-saas-enterprise`, `fix-tls-handshake-timeout-attribution` and `complete-certificate-diagnostics` before archiving this change, so its MODIFIED deltas find their target requirements.
- Release as 0.11.1 after review, with the CHANGELOG entry from task 1.3.
