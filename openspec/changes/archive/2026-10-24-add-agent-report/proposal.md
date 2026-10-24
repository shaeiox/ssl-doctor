# Proposal

## Why

Operators increasingly hand a failing TLS case to an AI model (ChatGPT, Claude,
Gemini or a local model) for deeper analysis. Today they paste fragments of the
terminal or an HTML report, which loses structure, mixes observations with
conclusions, and invites the model to over-read warnings — exactly the
mistakes SSL Doctor's diagnosis was built to avoid (relaxed-policy handshakes,
client-side probe limits, partial endpoint coverage). An export designed for
that reader keeps the evidence, the uncertainty and the analysis rules together.

## What Changes

- New command **`/report agent [dir]`** that exports the session's most recent
  completed scan, without re-running anything, as two files in one directory:
  - `agent-report.md` — a paste-ready report with fixed sections (metadata,
    executive summary, target and environment, detailed evidence, findings and
    diagnosis, recommended next steps) followed by the **AI analysis prompt
    reproduced verbatim**.
  - `agent-report.json` — a findings-contract document (`findings/1.5`, the
    schema `/report json` already writes) whose `meta` carries the scan target,
    resolved addresses, negotiated protocol/cipher, execution environment and
    report kind.
- Default location follows `/report`'s convention (current directory, timestamped):
  `./ssl-doctor-agent-report-<YYYYmmdd-HHMMSS>/`; an optional `dir` argument
  overrides it. The CLI prints both paths and a one-line summary.
- Clear errors, and no files left behind, when no completed scan exists or when
  serialization or writing fails.
- `/report html|json|both` behaviour is unchanged; `/help`, completion, README,
  CHANGELOG and `docs/findings-contract.md` document the new mode.

Not changing: checks, findings, severity, the diagnosis engine, the findings
schema version. Nothing is sent to any AI service; no API keys, no new
dependencies.

## Capabilities

### New Capabilities
- `agent-report`: exporting a completed scan as an AI-ready Markdown report and
  a matching machine-readable document — content, fidelity to the source data,
  redaction, file output and failure handling.

### Modified Capabilities
<!-- none: no archived spec's requirements change -->

## Impact

- `ssl_doctor/report.py`: Markdown renderer built from the (redacted) contract
  payload; the verbatim prompt as a constant; agent `meta` assembly.
- `ssl_doctor/cli.py`: `agent` mode in `cmd_report` sharing the existing
  report-input preparation (diagnosis, meta, secrets, facts) with html/json;
  atomic two-file write; `/help` and completion text.
- `docs/findings-contract.md`: documents the `meta` keys an agent report adds
  (no schema change — `meta` is an open object in every published schema).
- Tests: new `tests/test_agent_report.py` using the existing deterministic
  fixtures (`cli_session`, `FakeSession`); no network beyond the local
  `openssl s_server` fixture other report tests already use.
