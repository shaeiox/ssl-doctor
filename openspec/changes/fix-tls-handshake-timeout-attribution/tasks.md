# Tasks

> Baseline before starting: `python3 -m unittest discover -s tests` runs 54 tests, OK (6 skipped). Every verification step below is that command plus the named test module. No task may change a check identifier or an existing test's expectation.

## 1. Findings contract: the failure classification field

- [ ] 1.1 Add `failure_kind: str = ""` to `Finding` in `ssl_doctor/findings.py`, include it in `to_dict()`, and declare the value registry once in `ssl_doctor/contract.py`; verify `Finding(...).to_dict()["failure_kind"] == ""` for a check that does not classify failures
- [ ] 1.2 Add the optional `failure_kind` property (enum of the registry values) to `contract.SCHEMA`, bump `SCHEMA_VERSION` to `1.2`, and publish `schemas/findings-1.2.schema.json`; verify `schemas/findings-1.0.schema.json` and `schemas/findings-1.1.schema.json` are byte-identical to the previous commit (`git diff --stat`)
- [ ] 1.3 Render the field in `ssl_doctor/report.py` (HTML row meta and JSON) only when non-empty; verify an exported report with a classified finding contains it and a report without one does not
- [ ] 1.4 Extend `tests/test_contract.py`: a 1.1-era document without the field still validates, a document carrying each registry value validates, and a document with an unregistered value is rejected; verify both cases fail on the pre-change schema
- [ ] 1.5 Document the field and its values in `docs/findings-contract.md`; verify every value in the registry appears in that table

## 2. Handshake probe: phase, address and typed failure

- [ ] 2.1 Split `ssl_doctor/netchecks.py :: _handshake` into connect and negotiate phases that raise `_ConnectTimeout` / `_NegotiationTimeout` (private, message-preserving), keeping the composition's signature compatible; verify existing callers (`:281`, `:355`, `:420`, `:462`, `:507`, `:556`, `:587`) still work unchanged
- [ ] 2.2 Map the phases in `check_tls_basic` to `failure_kind` and to distinct evidence wording that names the phase, address, port and elapsed time; verify a stall and a connect timeout produce different evidence and different `failure_kind`
- [ ] 2.3 Classify a TLS alert or no-shared-cipher error as `tls-alert` and a reset/unreachable error as `network-error`, keeping the existing FAIL status and recommendation text semantics; verify the alert path still names the OpenSSL message
- [ ] 2.4 Pass `connect_ip` into `check_tls_basic` and `check_protocol_matrix` from `run_remote_diagnostics`, using the address `check_tcp` verified, and record it in evidence and in `facts["handshake_ip"]`; verify a two-record fixture proves all later probes used the same address as `net.tcp`

## 3. Handshake probe: confirm a stall before failing

- [ ] 3.1 Add a single retry of timeout-class failures in `check_tls_basic` on a fresh connection (`_HANDSHAKE_RETRIES = 1`), never retrying `tls-alert`, and record `facts["handshake_attempts"]`; verify the alert path performs exactly one attempt (assert the fixture's connection count)
- [ ] 3.2 Return `WARNING` with the stall `failure_kind` and full facts (protocol, cipher, certificate, chain) when the retry succeeds, so downstream checks still run; verify `tls.chain`, `tls.hostname`, `tls.verify` and validity findings are still produced in the stall-once fixture
- [ ] 3.3 Return `FAIL` with both attempts in evidence when both attempts stall; verify the evidence contains the elapsed time for each attempt
- [ ] 3.4 Keep `run_remote_diagnostics`' early return keyed on `FAIL` only, so a recovered stall continues through the full suite; verify the flaky fixture produces more than the handshake and matrix findings

## 4. Protocol matrix: classified rows and disclosed policy

- [ ] 4.1 Classify each row as `accepted`, `refused`, `timed out after Ns (no response)` or `network error (…)`, and remove the current mapping of timeouts into `refused` (`netchecks.py:469-471`); verify a stall-server fixture yields only "timed out" rows
- [ ] 4.2 Set `failure_kind` to `no-version-answered` when every row timed out or errored and `no-version-accepted` when every row was refused; verify both fixtures (`stall`, `refused-only`) produce their own value and neither produces the other's
- [ ] 4.3 Add the evidence line naming the relaxed cipher policy used for TLS 1.0–1.2 probes and repeat it in `detail` when such a version was accepted; verify the accepted-versions fixture evidence contains the policy statement
- [ ] 4.4 Leave status computation untouched (`netchecks.py:473-487`); verify the existing verdicts for the `TLSServer` fixtures are unchanged

## 5. Orchestration: coherent handshake and matrix findings

- [ ] 5.1 In `run_remote_diagnostics`, after a FAIL handshake followed by a matrix with at least one accepted version, append one evidence line to the handshake finding naming the accepted versions and stating stall-versus-rejection; verify the reproduced pair renders as a stall, not as "no TLS version works"
- [ ] 5.2 Record `facts["handshake_failure"]` and the matrix's accepted versions so agents and the service receive the same classification without re-deriving it from text; verify `export_facts`/report output carries the classification once 1.1 is extended (or explicitly documents why not)
- [ ] 5.3 Confirm the matrix is still executed exactly once on the failure path (`netchecks.py:764-766` versus `:820`); verify by counting probe connections in the stall fixture

## 6. Diagnosis: attribution by failure mode

- [ ] 6.1 Replace the status-plus-substring rule in `ssl_doctor/analyze.py:100-112` with the failure-mode branches from the design's attribution table, deriving "some version accepted" from the matrix status rather than from evidence text; verify no new rule parses evidence strings to decide origin
- [ ] 6.2 Add the invariant that a "protocol/cipher mismatch" cause requires `failure_kind == "tls-alert"`; verify a timeout plus four accepted versions yields no such cause and no server-origin cause from these findings
- [ ] 6.3 Raise the network-origin stall cause (probable, recommendation = repeat measurement / inspect inspection devices and idle timeouts) for timeout-class failures, including the `WARNING` (recovered) case; verify the overall diagnosis is not PASS for the recovered case
- [ ] 6.4 Add the conservative fallback for a FAIL handshake without a classification, and confirm independent server rules (chain, chain file, vhost, certref, configured-versus-presented) still run during a stall; verify a stall plus leaf-only chain produces both causes
- [ ] 6.5 Cap certainty for stall/timeout causes at "probable"; verify a single staged timeout sample never yields "confirmed"

## 7. Fixtures and regression tests

- [ ] 7.1 Add a `stall` mode to `tests/fixtures/tls_server.py` (plain TCP listener: accept, never respond, closed on teardown) and a `stall-once` mode that stalls the first connection and hands the second to `openssl s_server`; verify both skip cleanly when `openssl` is absent
- [ ] 7.2 Add `tests/test_handshake_failure_attribution.py` with the unit matrix over `{negotiation-timeout, connect-timeout, tls-alert, network-error, unclassified} × {matrix accepted, matrix FAIL, matrix absent}`, asserting origin, certainty and that no server protocol cause appears for timeout-class input; verify the module runs standalone (`python3 -m unittest discover -s tests -p "test_handshake_failure_attribution.py"`) and covers all 15 combinations
- [ ] 7.3 Add the exact reproduction test: handshake FAIL "timed out after 8s" plus four accepted matrix rows → no "protocol/cipher mismatch" summary, top cause origin `network`; verify the test fails against the pre-change `analyze.py` (`git stash` the rule, run, restore)
- [ ] 7.4 Add fixture-backed tests for `stall` (FAIL, `negotiation-timeout`, address named, both attempts) and `stall-once` (`WARNING`, downstream checks present); verify both assert `failure_kind`, not evidence substrings
- [ ] 7.5 Add the alert fixture test (`tls-alert` keeps the server cause) and the address-pinning test (all probes use the `net.tcp` address); verify the pinning test fails if `connect_ip` is not propagated
- [ ] 7.6 Re-run `tests/test_scan_e2e.py` and `tests/test_diagnosis.py` unchanged; verify their verdict table and chain-cause assertions still pass (no stall in those fixtures)

## 8. Documentation and release notes

- [ ] 8.1 Update `docs/execution-flow.md` (handshake failure flow, retry, address pinning, matrix classification) and `README.md` (check table notes for `tls.handshake` / `tls.protocols`); verify every `failure_kind` value and the retry behavior appear in the docs
- [ ] 8.2 Add a `CHANGELOG.md` entry naming the intended behavior changes (stall = WARNING, network attribution, contract 1.2) and the check ids affected; verify it names `tls.handshake` and `tls.protocols` and does not list a new check id
- [ ] 8.3 Update `.project-brain/projects/ssl-doctor/chain-diagnosis.md` (or a new topic file) and the index line with the attribution rule; verify the compact index is regenerated or the pointer is still accurate

## 9. Gate and archive

- [ ] 9.1 Full suite green on Python 3.10 and 3.12: `python3 -m unittest discover -s tests`; verify test count grew and no previously passing test is skipped without a platform reason
- [ ] 9.2 Reproduce the artifact scenario end-to-end (`/scan --client-only` against the `stall` fixture, then `/report both`) and attach the report to the change; verify the diagnosis shows a probable network stall and no server protocol cause
- [ ] 9.3 Re-read the design's Open Questions and record the answers (retry budget exposure, verdict level for a recovered stall) before archiving; verify `design.md` no longer lists them as open
- [ ] 9.4 Archive the change once the gate passes, and verify the requirements land under `openspec/specs/` alongside the archived `fix-chain-diagnosis-saas-enterprise` capabilities
