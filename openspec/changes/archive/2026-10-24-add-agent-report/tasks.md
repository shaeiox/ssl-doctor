# Tasks

## 1. Shared report inputs

- [x] 1.1 Extract the diagnosis/meta/secrets/facts preparation of `cmd_report` into `_report_inputs()` and use it for `html|json|both`; verify the existing contract/report tests pass unchanged and a before/after `/report json` of a fixture session differs only in `generated_utc`

## 2. Agent document

- [x] 2.1 Build the agent `meta` (`report_kind`, `agent_report.scan|environment|configuration`, `null` for missing values) and the payload via `report.build_payload()`; verify with tests that it validates against `schemas/findings-1.5.schema.json`, equals `/report json`'s findings/diagnosis/facts, and keeps `probe_policy.default_probe`, `endpoint_comparison` coverage, `failure_kind`, `observation` and `uncertainty`
- [x] 2.2 Document the agent `meta` keys in `docs/findings-contract.md` (no schema version change); verify the contract docs test still passes and the documented keys match the generated document

## 3. Markdown renderer

- [x] 3.1 Add the verbatim prompt constant from design.md's appendix; verify with a test that compares it byte-for-byte with the appendix text
- [x] 3.2 Implement `report.agent_markdown(payload)` with the seven sections in order, metadata and executive summary from the payload; verify with tests for section order and that counts/overall status equal the JSON summary and diagnosis
- [x] 3.3 Render evidence areas by check-id group with "not collected in this session" for empty groups, policy labels for protocol rows, default-probe labels (`client-limited` is not a server rejection) and endpoint coverage (resolved/probed/reachable/comparable); verify with tests on fixture sessions: client-only scan, the google-like legacy-TLS matrix, 4-of-7 endpoint coverage
- [x] 3.4 Render diagnosis groups (observations, hypotheses/possible, probable, confirmed, unresolved, notes) and next steps (recorded recommendations, missing evidence, fixed read-only preface); verify with tests that NOT TESTED stays NOT TESTED, an unresolved legacy-TLS warning is never called confirmed, the "did not record contradicting evidence" line appears, and no finding/cause title appears that is absent from the payload

## 4. Command and file output

- [x] 4.1 Add `agent` to `cmd_report`: require a completed scan, default directory `ssl-doctor-agent-report-<ts>` or the given `dir`, refuse to overwrite either file, print both paths and the summary; verify with CLI tests for success after `cli_session(...)`, the fresh-session error (no file or directory created), the overwrite refusal, and that the store and `_diagnosis` findings are unchanged afterwards
- [x] 4.2 Write both files atomically (serialise first, temp files + `os.replace`, clean up on `OSError`); verify with tests that patch the JSON write to fail and a read-only directory, asserting no `agent-report.md`/`.json` remains and the session keeps working
- [x] 4.3 Verify redaction with the existing `FakeSession` password fixture: neither file contains the password, its base64 form or a `PRIVATE KEY` block, and both contain the redaction marker
- [x] 4.4 Add `/report agent [dir]` to `/help`, the `/report` completion description, README's command table and CHANGELOG Unreleased; verify the `/help` row and README text match the implemented arguments

## 5. Integration

- [x] 5.1 Run the full suite (`venv/bin/python -m unittest discover -s tests`) and verify it passes, including the unchanged `/report html|json|both` tests
- [x] 5.2 Run `/tls 127.0.0.1:<port>` then `/report agent` against the local `openssl s_server` fixture in batch mode; verify both files are written, the JSON validates, and the Markdown ends with the verbatim prompt
