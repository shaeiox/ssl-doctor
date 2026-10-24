---
project: ssl-doctor
topic: agent-report
tags: [report, ai, export, contract, redaction]
status: done
trust: ai-inferred
last_done: 2026-10-24
version: 1
---

**What:** `/report agent [dir]` (OpenSpec `add-agent-report`) writes `agent-report.md` +
`agent-report.json` for the latest completed scan into `./ssl-doctor-agent-report-<ts>/` or `dir`.

**How:** `cli._report_inputs()` is the shared html/json/agent preparation (html/json output
byte-identical to before). `cli._agent_payload()` = `report.build_payload()` with
`report.agent_meta()` (`meta.report_kind`, `meta.agent_report.scan|environment|configuration`;
missing values `null`). `report.agent_markdown(payload)` renders **only from the redacted JSON
document**; `report.AGENT_ANALYSIS_PROMPT` is the user-specified prompt, pinned by
`tests/fixtures/agent_prompt.txt`. `report.write_agent_report()` refuses to overwrite and leaves
both files or neither.

**Rules:** "completed scan" = `remote_facts["host"]` set and store non-empty; no schema bump
(`meta` is open). Never add interpretation to the renderer: framing text only.

**Tests:** `tests/test_agent_report.py` (30).
