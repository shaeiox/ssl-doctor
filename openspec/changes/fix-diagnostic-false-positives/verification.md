# Verification — fix-diagnostic-false-positives (integration gate, group 8)

- **When and where:** 2026-10-27, branch `fix/diagnostic-false-positives`.
- **Environment:** Linux, run as root (as `tests/baseline/baseline.tsv` was recorded); project `venv`; system `openssl` present.
- **Safety:** no command reloads, restarts or signals a service, and no test reads key content.

## 8.1 Full-suite comparison

Full suite, run with `venv/bin/python tests/baseline/record.py --check`:

| | Baseline (v0.10.1) | This branch |
|---|---|---|
| Test ids | 708 | 1009 (+301; v0.11.0 had 958) |
| Removed ids | — | 0 |
| Newly skipped baseline ids | — | 0 |
| Failing | 0 | 0 |

- **Skipped new tests, all root-only with a named reason:**
  - the two `test_private_key_states.*.test_unreadable_file` tests (as in v0.11.0);
  - `test_server_deployment.Permissions.test_untraversable_parent_is_not_tested`, new in this change.
- **The new permission test was also run as `nobody`, where it passes.** In that run two other `Permissions` tests fail; both use `nobody` as the service account.
  - The new `test_service_account_access_is_judged_on_the_target` fails in that run.
  - The pre-existing `test_service_account_cannot_read_the_certificate` fails the same way.
  - Cause: when the suite runs *as* `nobody`, `nobody` owns the files, so they are readable. This is a limit of the test harness, not of the code.
- **Service suite** (from `service/tests`, `PYTHONPATH=.:../..:../../tests:..`): 79 tests, 1 failure, `test_unreadable_nginx_config_is_not_tested_with_reason`.
  - It predates this change: it fails at `2f70fb0` and at v0.11.0, because root can read the "unreadable" file.
  - No new failure.
- **A timing flake found and fixed here:** `test_client_machine.ClockSkew.test_regression_d_stale_reference_is_not_tested` failed once in the full run.
  - `check_os_and_clock` reads the clock with `datetime.now()` (microsecond resolution). That reading is often *earlier* than a `time.time()` taken just before it: 149 391 of 200 000 samples.
  - So an age of exactly 360 s showed as 359.999999 s, and `int()` printed 359.
  - The age is now rounded (`local.py`).

## 8.2 Audit reproductions, re-run

The scripts are in the session scratchpad, `audit2/`. They were recreated verbatim from the audit after the scratchpad was cleared between sessions.

Each scenario is listed with its v0.11.0 result and its result on this branch:

| Item | Scenario | v0.11.0 | This branch |
|---|---|---|---|
| A | certutil exit 0 + `dwErrorStatus=0` chain dump | FAIL | PASS |
| A | certutil exit 0 + one unreachable AIA URL | FAIL | PASS, URL listed as a warning line |
| A | certutil exit 0 + "error" in a subject | FAIL | PASS |
| A | certutil `FAILED: 0x800b010a` | FAIL | FAIL, code in the evidence |
| B | real non-root `nginx -t` (pid file and error log `(13:)`, `syntax is ok`, `test failed`) | FAIL, confirmed cause, overall FAIL | NOT TESTED `permission-denied`, no cause, overall PASS |
| B | unreadable `ssl_certificate_key` + `test failed` | FAIL, confirmed cause | NOT TESTED `permission-denied` |
| B | genuine `unknown directive` | FAIL, confirmed cause | FAIL, confirmed cause (unchanged) |
| C | redirect block sharing the certificate, presented = leaf | WARNING "belongs to server block 'alias.test'" + cause | PASS, "shares the certificate", no cause |
| C | same name on 8443, same pair | WARNING + cause | PASS, "other listener", no cause |
| C | either case, presented certificate unknown | WARNING + cause | PASS, no cause |
| D | `/tls`, then `/local` 300 s later, clocks equal | FAIL "300s ahead" | NOT TESTED "server time reference is 300s old; repeat the network check" (test `test_client_machine.LocalAfterTls`) |
| D | `Date` 600 s old with `Age: 600` | FAIL (derived from the old code, which ignored `Age`; not reproduced) | PASS, "Age correction" named |
| D | missing-issuer verify FAIL + skew FAIL | "Client clock … date errors" cause | issuer cause only |
| F | certbot `live/` symlink → 0600 target | WARNING "readable by other users" (mode=777) | PASS, `link -> target … mode=600` |
| F | the same with a non-root master `nobody` | "readable by the service account" (judged on the link) | FAIL "service account nobody cannot read <target>" |
| F | regular 0644 key | WARNING | WARNING (unchanged), advice `chmod 600 <file>` |
| G | certbot-managed, root crontab not readable | WARNING "unscheduled" + cause | NOT TESTED `permission-denied`, naming `/var/spool/cron/crontabs` |
| G | only another tool's (lego) cron for a certbot certificate | PASS | WARNING "unscheduled" |
| G | `/root/.acme.sh` not readable, nothing found | NOT TESTED, silent | NOT TESTED, "/root/.acme.sh could not be inspected" |
| H | healthy endpoint + unexplained `local.clockskew` FAIL | overall FAIL, exit 1 | overall WARNING, exit 0 (test `test_exit_code…test_client_machine_failure_alone_exits_zero`) |
| H | certutil FAIL + verify NOT TESTED (timeout) | overall FAIL | overall WARNING |

**How the D row was checked.** `audit2/h_verdict.py` still calls `check_os_and_clock(epoch)` without a reference, the legacy signature kept for direct callers, so its first line still prints FAIL. The real `/tls` → `/local` path passes the reference and is verified by `LocalAfterTls`.

**Live check of the G probe.** As `nobody` on this host, the real renewal probe reports `/var/spool/cron/crontabs no` and `/root/.acme.sh no`, which is the audit's scenario. Run as root, it reports every source visible. The per-tool cron grep was checked against scratch files, and a decoy line `acmeXsh` is no longer attributed to acme.sh.

## Deviations from the planning artifacts (all recorded in design.md/tasks.md)

- **D2:** HAProxy's `Fatal errors found in configuration` and Apache's `Action '-t' failed` are summary lines. They are excluded like nginx's `test failed`.
- **D5:** nginx's default `listen` port is 80, not 443 as first written. The 4.1 test list uses "an address without a port" instead of the invalid bare `listen ssl`.
- **D6:** cron hits are reported as `<tool>: <file>`, because a crontab's file name does not name the tool. Missing sources are judged by their nearest existing ancestor.
- **Task 6.2:** the boundary cases use the spec's minimum 1 s uncertainty (61/62/301/302 s), because a 0 s uncertainty cannot occur.
