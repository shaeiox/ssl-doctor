# Proposal

## Why

The read-only diagnostic audit of v0.11.0 reproduced six defects (A–F, H) and one likely defect (G). The report is `ssl-doctor-diagnostic-audit.md` in the session scratchpad and is summarised in design.md. In each case SSL Doctor reports a fault on a healthy system:

- A *confirmed* nginx configuration failure for any unprivileged SSH user (B).
- A Windows chain-engine failure whenever `certutil` output contains the word "error" (A).
- Every certbot key reported as world-readable (F).
- A self-contradicting inventory warning when two server blocks share a certificate (C).
- A clock-skew FAIL that is only an old timestamp (D).
- Renewal "not scheduled" when the crontab is merely invisible (G).
- An overall verdict that lets these client-side and auxiliary checks fail an endpoint whose own checks all pass (H).

A diagnostic tool that blames healthy servers trains its users to ignore it, so these are fixed before new checks are added.

## What Changes

- **`local.certutil` (A).**
  - The result is decided from certutil's exit status and its final status line, not from substrings anywhere in the output.
  - URL-retrieval failures under `-urlfetch` are reported separately, as a revocation-reachability warning, never as a chain failure.
  - A launch error is NOT TESTED.
- **`srv.configtest` (B).**
  - The test output is classified from its error-level lines (`[emerg]`, `[alert]`, `[crit]` and Apache/HAProxy equivalents).
  - nginx's own summary lines (`syntax is ok`, `test is successful`, `… test failed`) are excluded from that classification.
  - A test that failed only on files or directories this account cannot open (pid file, error log, certificate key) is NOT TESTED `permission-denied`.
  - A reported `syntax is ok` is kept as evidence that parsing succeeded.
  - No privileged execution path is added.
- **`srv.inventory` (C).**
  - Certificates are compared by identity.
  - When the selected block's certificate is the one being served, other blocks that use the same certificate are listed for information only and never raise a warning.
  - Only blocks that can answer on the scanned address and port are candidates.
  - With no presented certificate to compare, other covering blocks are listed with an uncertainty, not a warning or a cause.
- **`local.clockskew` (D).**
  - The server time is recorded together with the local time the response was received, its source host and its `Age` header.
  - A cached response is corrected by `Age`.
  - A reference older than the freshness window, or taken from another host after a redirect, is NOT TESTED or labelled.
  - The evidence states the measurement uncertainty.
  - The clock cause requires a date-related validation error.
- **`srv.perms` (F).**
  - Permissions are judged on the file the path resolves to (`stat -L`), and the evidence names both the link and its target.
  - The service account's access is computed on the target.
  - A permission state the session cannot fully see is reported as limited, not as confirmed: ACLs present, or an unreadable parent directory.
  - The recommendation names the actual file and group.
- **`srv.renewal` (G).**
  - The renewal probe reports, for each source (timers, each cron location, acme.sh home), whether it was readable.
  - "Unscheduled" is reported only when every schedule source was readable. Otherwise the result is NOT TESTED `permission-denied`, naming the unreadable sources.
  - A schedule counts only when it belongs to the tool that manages the certificate.
- **Overall verdict (H) — BREAKING for scripts that rely on exit code 1 from a client-side FAIL.**
  - An unexplained FAIL of a client-machine check (`local.*`) counts as WARNING, like the diagnostic-session checks.
  - The overall verdict and exit code then describe the endpoint and its server.
  - Client causes raised by rules are unchanged and still listed. A confirmed client cause still makes the verdict FAIL.
  - This choice (decision U1 in design.md) needs maintainer approval before implementation.
- **Regression tests.** Every fix ships with tests built from real tool output or real file layouts (captured `nginx -t`, `certutil` and certbot `live/` symlinks), replacing the synthetic fixtures that hid these defects.

## Capabilities

### New Capabilities
- `client-machine-diagnostics`: checks about the machine running SSL Doctor — Windows chain-engine validation (`local.certutil`) and clock skew against the server (`local.clockskew`). No spec covers them today.

### Modified Capabilities
- `tls-service-discovery`: the native configuration test separates permission limits from invalid configuration (B), and renewal detection reports visibility per source (G). This capability is introduced by the unarchived change `complete-certificate-diagnostics`.
- `server-certificate-deployment`: permissions are judged on the resolved target with visibility limits (F), and the inventory compares certificates by identity and listener (C). Also introduced by `complete-certificate-diagnostics`.
- `diagnosis-correlation`: the overall verdict weighs unexplained client-machine FAILs as WARNING (H).

## Impact

- **Code:**
  - `ssl_doctor/local.py` (`check_certutil_verify`, `check_os_and_clock`, `run_local_for_remote`).
  - `ssl_doctor/netchecks.py` (`check_https`, `server_time` facts).
  - `ssl_doctor/services.py` (`classify_config_test`, `parse_renewal`, `renewal_for`).
  - `ssl_doctor/server.py` (`permissions`, `_inventory_blocks`, `inventory_finding`, `_RENEWAL_SCRIPT`, `_renewal_finding`).
  - `ssl_doctor/analyze.py` (verdict, clock, inventory and renewal rules).
- **Contract:** stays `findings/1.7` with no schema change. No new check ids, failure kinds or observation values are needed; existing `permission-denied`, `command-failed` and `uncertainty` carry the new states.
- **Behaviour visible to users:**
  - Fewer FAILs and WARNINGs on healthy systems.
  - Batch exit code 0 where only a client-machine check failed without a cause (H).
  - New evidence lines (link → target, `Age`, source visibility).
- **Tests:** new and updated tests in `tests/test_service_discovery.py`, `tests/test_server_deployment.py`, `tests/test_verdict_semantics.py`, and a new `tests/test_client_machine.py`. The baseline guard `tests/baseline/record.py` must show no removed test ids.
- **Ordering:** `complete-certificate-diagnostics` must be archived before this change, so the deltas for `tls-service-discovery` and `server-certificate-deployment` apply to the archived requirements.
- **Out of scope:**
  - The test-order dependency and inconclusive-result caching in `chainval` (audit item I) — a separate small change.
  - An opt-in privileged (`sudo -n`) configuration test.
  - ACL contents (only their presence is detected).
  - ACME clients beyond certbot, acme.sh and lego.
