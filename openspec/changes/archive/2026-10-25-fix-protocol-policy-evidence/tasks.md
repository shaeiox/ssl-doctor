# Tasks

> Baseline before this change: `python3 -m unittest discover -s tests` = **125 tests, OK (6 skipped)**.
> Every verification below is that command plus the named module. No new check id,
> no CLI change, no host-specific behaviour.

## 1. Trace and reproduce

- [x] 1.1 Trace `_probe_version` → `check_protocol_matrix` → `Finding` → `analyze.diagnose()` for `tls.protocols`; verified - the call chain and the fields available to the diagnosis are documented in `design.md`
- [x] 1.2 Replay the reported google.com scan with a mocked probe and record the probe call log; verified - call log shows TLS 1.0/1.1 were probed only under `relaxed`, producing the reported `[possible · server]` wording verbatim
- [x] 1.3 Determine whether a relaxed handshake proves ordinary-client support; verified - on OpenSSL 3.0.20 the default context holds no TLS 1.0 ciphers, so a default-policy legacy probe fails locally with `NO_PROTOCOLS_AVAILABLE`; `ALL:@SECLEVEL=0` supplies cipher suites the test client would not otherwise use
- [x] 1.4 Reproduce the local-limitation-as-refusal defect; verified - default-policy TLS 1.0 probe returns `('refused', '…NO_PROTOCOLS_AVAILABLE…')` before the change

## 2. Probe layer (`ssl_doctor/netchecks.py`)

- [x] 2.1 Add the `client-limited` state, `_LOCAL_LIMITATION_MARKERS` and `_is_local_probe_limitation()`; verified - `test_client_limitation_is_not_a_server_refusal` and `test_local_marker_detection` pass; `test_probe_consistency` updated for `client-limited`
- [x] 2.2 Rewrite `check_protocol_matrix` with the typed `SUPPORT_*` classes and the per-version default-policy probe for legacy versions; verified - `tests/test_protocol_policy.py` covers all classes
- [x] 2.3 Record `facts["probe_policy"]["support" | "confirmed_legacy" | "unverified_legacy"]`; verified - asserted through the mocked matrix in `tests/test_protocol_policy.py`
- [x] 2.4 Scale the retry budget for the extra probes and never retry a refusal; verified - budget assertions and refusal-count assertions in `tests/test_protocol_policy.py`
- [x] 2.5 Keep the primary-handshake reconciliation: a version the primary negotiated is never `refused`; verified - `test_primary_tls13_success_with_timed_out_probe_is_inconclusive` and the TLS 1.3 case

## 3. Diagnosis layer (`ssl_doctor/analyze.py`)

- [x] 3.1 Branch on typed observations (`legacy-accepted-default`, `legacy-accepted-relaxed-only`, `legacy-accepted-unverified`, `probe-inconclusive`) instead of on status; verified - `test_server_refusing_the_default_probe_is_relaxed_only`, `test_legacy_accepted_with_default_policy_is_a_real_finding`, `test_reported_scan_no_longer_claims_legacy_for_ordinary_clients`
- [x] 3.2 Attach the relaxed-policy limitation to the relaxed-only cause and the remediation that matches it; verified - certainty/limitation/remediation assertions per class
- [x] 3.3 Emit a note, not a cause, for `legacy-accepted-unverified`, while keeping the finding `WARNING`; verified - `test_unverified_legacy_raises_no_protocol_cause` / `test_unverified_legacy_is_still_visible_as_a_warning`
- [x] 3.4 Keep the inconclusive note keyed on `failure_kind == "probe-inconclusive"` and limited to the inconclusive rows; verified - `test_inconclusive_probe_adds_no_server_cause` (row-scoped)
- [x] 3.5 Remove the prose-parsing helper (`_policy_support`); verified - `grep -n "_policy_support" ssl_doctor/` returns nothing

## 4. Contract 1.4 (additive)

- [x] 4.1 Add the four observations and the `probe_policy.support` / `confirmed_legacy` / `unverified_legacy` properties; bump `SCHEMA_VERSION` to `1.4`; verified - `tests/test_contract.py` pin updated, 1.0–1.3 schemas untouched (`git diff --stat schemas/`)
- [x] 4.2 Publish `schemas/findings-1.4.schema.json` from `contract.SCHEMA`; verified - `test_published_schema_and_docs_match_source` passes
- [x] 4.3 Document the 1.4 row, the new observations and the probe-policy block in `docs/findings-contract.md`, and the matrix behaviour in `docs/execution-flow.md`; verified - docs updated and the check-id registry test still passes

## 5. Regression tests

- [x] 5.1 Legacy 1.0/1.1 relaxed-only acceptance: class, row wording, observation, cause certainty, limitation and remediation
- [x] 5.2 TLS 1.2 accepted with the default policy stays `PASS`/`default` and is not described as insecure
- [x] 5.3 TLS 1.3 accepted is `default`; a failed TLS 1.3 re-probe while the primary negotiated 1.3 is `inconclusive`, not refused
- [x] 5.4 Legacy fails default but passes relaxed ⇒ `relaxed-only`, never "ordinary clients can negotiate"
- [x] 5.5 Timeout/failure before the handshake ⇒ `inconclusive`, no server-support claim; a local SSL-context error ⇒ `client-limited`
- [x] 5.6 Endpoint-comparison invariants preserved: one of two endpoints yielding a certificate ⇒ `NOT TESTED` + no cause; two comparable endpoints that differ ⇒ `WARNING` and a cause
- [x] 5.7 All tests mock the network through the `_probe_version` seam; no public site is contacted
- [x] 5.8 `python3 -m unittest discover -s tests` ⇒ **139 tests, OK (6 skipped)**
