# Tasks

> Baseline: `python3 -m unittest discover -s tests` = **86 tests, OK (6 skipped)** on the available interpreter.
> Every verification below is that command plus the named module. No task may add a new check id,
> change an existing check id, or hardcode behaviour for a specific host.

## 1. Findings contract 1.3 (additive)

- [ ] 1.1 Add `limitations: List[str] = []` to `Cause` in `ssl_doctor/analyze.py` and serialize it in `to_dict()`; verify a cause without limitations still serializes identically to today (no key churn beyond the new empty list)
- [ ] 1.2 Add `probe-inconclusive` and `endpoint-unreachable` to `contract.FAILURE_KINDS`, and the `facts.endpoints` / `facts.probe_policy` properties (all optional) to `contract.SCHEMA`; bump `SCHEMA_VERSION` to `1.3` and publish `schemas/findings-1.3.schema.json`; verify `findings-1.0/1.1/1.2` are unchanged (`git diff --stat schemas/`) and that a 1.2 document still validates
- [ ] 1.3 Render `limitations` and the endpoint states in `ssl_doctor/report.py` (HTML + JSON meta) only when present; verify an observation-only cause renders its limitation and a chain cause renders none
- [ ] 1.4 Extend `tests/test_contract.py` with the new enum values, the optional `endpoints` block (valid and invalid `state`), and a 1.2-era document; verify the new-key rejection test fails on the current schema
- [ ] 1.5 Document `limitations`, the two new failure kinds and the endpoint states in `docs/findings-contract.md`; verify every value appears in the table

## 2. Endpoint comparison (issue 1)

- [ ] 2.1 Replace the fingerprint-string comparison in `check_multi_ip` (`netchecks.py:712-745`) with per-endpoint state records (D1 of the design: `negotiated`, `tls-rejected`, `tcp-unreachable`, `timed-out`, `probe-unavailable`); verify one reachable + two `ENETUNREACH` addresses no longer produce "different results"
- [ ] 2.2 Compare only `negotiated` endpoints over leaf fingerprint, hostname coverage and chain status; verify a same-leaf/different-chain pair yields WARNING naming the chain attribute, and an all-identical pair yields PASS
- [ ] 2.3 Return NOT TESTED with `failure_kind="probe-inconclusive"` when exactly one endpoint is comparable, and `endpoint-unreachable` when none is; verify the evidence states "1 of N endpoints yielded a certificate" and lists the other states
- [ ] 2.4 Record `facts["endpoints"]` (`ip`, `state`, `detail`, `sha256`) and expose the comparison outcome (comparable count, difference found, differing attribute) in machine-readable form; verify an exported report carries both
- [ ] 2.5 Keep the address cap and read-only behaviour, and keep transport rows in the evidence regardless of the verdict; verify the cap by counting probes in a fixture with five addresses
- [ ] 2.6 Add `tests/test_endpoint_comparison.py` covering: unreachable IPv6 + one success, timeout + one success, two successes with different leaves, two successes with the same leaf and different chains, all unreachable, identical certificates, five addresses (cap); verify the unreachable cases assert the absence of any "different certificates" wording

## 3. Probe reconciliation and bounded retries (issue 2)

- [ ] 3.1 Pass the primary negotiated protocol into `check_protocol_matrix` from `run_remote_diagnostics` (`netchecks.py:~1018`) and record the shared address/SNI/deadline in the finding evidence; verify the evidence names all three and that all probes still use `connect_ip`
- [ ] 3.2 Replace the row vocabulary with accepted / accepted under relaxed policy / refused / inconclusive / unsupported, and route `_NegotiationTimeout`, `_ConnectTimeout` and `OSError` to inconclusive; verify a stalled TLS 1.3 probe row says "inconclusive - probe timed out after Ns" and cites the primary TLSv1.3 negotiation
- [ ] 3.3 Guarantee that a version the primary handshake negotiated is never reported refused or unsupported; verify by simulating a TLS 1.2 refusal while the primary negotiated TLS 1.2 (row must be inconclusive, not refused)
- [ ] 3.4 Retry each inconclusive version once on a fresh connection, never retrying a refusal, with a budget of `timeout × PROBE_BUDGET_FACTOR × len(versions)`; verify a succeeding retry is reported as accepted with the retry noted, a failing retry shows both attempts, and an exhausted budget is stated
- [ ] 3.5 Make an inconclusive row prevent a clean PASS: status WARNING, `failure_kind="probe-inconclusive"`, versions named in `detail`; verify a matrix with one inconclusive and three accepted rows is WARNING and that `/diagnose` adds no server protocol cause but does add an "inconclusive" note
- [ ] 3.6 Add fixtures in `tests/fixtures/fault_server.py`: a server that closes the connection before completing the handshake, and a proxy mode that stalls one specific TLS version only; verify both skip cleanly when `openssl` is absent
- [ ] 3.7 Add `tests/test_probe_consistency.py` covering the five required scenarios (primary succeeds + probe times out; both succeed; explicit rejection; connection closed without handshake; subprocess/timeout error) plus retry-success, retry-failure and budget exhaustion; verify each asserts the row state and the finding status, not evidence substrings alone

## 4. Relaxed policy versus interoperability (issue 4)

- [ ] 4.1 Carry the per-version policy (`default` / `relaxed`) through the version table and render it in every row; verify no row can show a relaxed acceptance without the policy named
- [ ] 4.2 Add the default-policy probe for TLS 1.2 when the relaxed probe accepted, and report the two facts separately (server support vs default-client interoperability); verify "accepted only under relaxed cipher policy - a default-configured modern client is refused" when applicable
- [ ] 4.3 Keep the deprecated-version security warning with the relaxed-policy limitation in `detail` and in the cause limitations; verify TLS 1.0 acceptance is still reported when TLS 1.3 is in use
- [ ] 4.4 Add regression tests for relaxed success + default refusal, ordinary success, explicit rejection, and inconclusive probe (no policy claim attached); verify each asserts both the row text category and the finding status

## 5. SNI observation semantics (issue 3)

- [ ] 5.1 Rewrite `check_sni_difference` (`netchecks.py:665-709`) to the four-outcome vocabulary (same / different / cannot probe without SNI / with-SNI failure) with no configuration assertion and no vhost recommendation; verify the different-case wording contains "legitimate" and no "wrong certificate" or vhost instruction
- [ ] 5.2 Return NOT TESTED (not WARNING) when the no-SNI probe cannot be completed, keeping the reason; verify the "very old clients will fail" claim is gone and the reason is present
- [ ] 5.3 Keep `tls.hostname` as the authority for name coverage and make the SNI finding carry the observation category plus both fingerprints, with no failure classification when both probes complete; verify the finding `failure_kind` is empty in that case
- [ ] 5.4 Add `tests/test_sni_observation.py` covering: correct certificate with SNI and a different default certificate; wrong certificate even with SNI provided; identical certificates; a server that cannot be probed without SNI; insufficient evidence; verify each asserts the observation category and the absence of a vhost recommendation
- [ ] 5.5 Add a fixture/proxy mode that serves a distinct default certificate when no SNI is sent (TLS terminator with a default vhost); verify the fixture reproduces the CDN case without touching `google.com` or any real host

## 6. Diagnosis: certainty, limitations, correlation (issues 1, 3, 5)

- [ ] 6.1 Remove the `tls.multiip` WARNING → probable-server rule (`analyze.py:302-306`); raise an inconsistency cause only from the comparable-endpoint outcome, `confirmed` when two comparable endpoints differ and nothing when the finding is inconclusive; verify an inconclusive comparison produces a note, not a cause
- [ ] 6.2 Restrict the SNI rule (`analyze.py:297-301`) to corroboration: no cause from the observation alone, evidence appended only when a hostname or vhost cause already exists; verify both the isolated and the corroborated cases
- [ ] 6.3 Add the evidence-strength helper and apply it to the affected rules (chain, endpoints, hostname, protocol policy, SNI); verify no rule assigns `confirmed`/`probable` from a transport failure or an inconclusive probe
- [ ] 6.4 Fill `limitations` for causes resting on a single endpoint, a single sample, a relaxed-policy probe, an unavailable no-SNI probe, or an exhausted budget; verify each affected cause lists at least one limitation and the confirmed chain cause lists none
- [ ] 6.5 Route inconclusive outcomes into `Diagnosis.notes` (endpoint comparison inconclusive, version probe inconclusive, SNI dependence undetermined), naming what could not be determined; verify the notes appear for each case
- [ ] 6.6 Pin the verdict rules with tests: observation-only scan is WARNING (never FAIL), confirmed chain fault is FAIL, no-cause scan is PASS; verify the existing `Diagnosis.overall` implementation is unchanged

## 7. Orchestration and facts

- [ ] 7.1 Pass the primary protocol into the matrix and the requested server name into the endpoint comparison, and include the endpoint/ probe facts in `export_facts`; verify an exported 1.3 document validates and carries `endpoints` and `probe_policy`
- [ ] 7.2 Confirm no check loses read-only behaviour, no new network writes occur, and `/timeout` remains the only timing knob; verify by grepping the diff for new socket writes and by running the CLI against the fixtures
- [ ] 7.3 Confirm the scan duration stays bounded: with four stalling versions and a 1 s timeout, the matrix completes within the reported budget; verify with a timing assertion in `test_probe_consistency.py`

## 8. Documentation and release notes

- [ ] 8.1 Update `README.md` (endpoint comparison, SNI observation, probe reconciliation, relaxed policy) and `docs/execution-flow.md` (new probe flow, states, budget); verify each new behaviour is described where the check is documented
- [ ] 8.2 Add a `CHANGELOG.md` entry listing the changed verdicts by check id (`tls.multiip`, `tls.sni`, `tls.protocols`) and the contract bump to 1.3; verify it names no new check id and states the intended verdict changes
- [ ] 8.3 Update the project brain (`projects/ssl-doctor/`) with the evidence-strength rule, endpoint states and SNI semantics; verify the index and compact index stay in sync

## 9. Gate

- [ ] 9.1 Full suite green: `python3 -m unittest discover -s tests` (expected ≥ 110 tests), plus `tests/test_scan_e2e.py`, `tests/test_diagnosis.py`, `tests/test_tls_inspection.py` and `tests/test_handshake_failure_attribution.py` unchanged and passing; verify the count grew only by the new modules and that no existing assertion was edited (`git diff --stat tests/`)
- [ ] 9.2 Re-run the three reproductions from `proposal.md` and confirm the reported symptoms are gone: unreachable-IPv6 comparison is inconclusive, a TLS 1.3 probe stall is reported as inconclusive while citing the primary TLSv1.3 success, and an SNI difference raises no cause; verify by diffing the new output against the transcript in `proposal.md`
- [ ] 9.3 Confirm the acceptance list in `proposal.md` is met item by item, and record any item that cannot be verified in this environment (state the reason) before archiving; verify every acceptance item maps to a named test or a recorded limitation
