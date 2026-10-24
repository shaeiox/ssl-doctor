# Design

## Context

- `SSLDoctorCLI.cmd_report` handles `html|json|both [path]`: it reuses or computes
  the diagnosis (`diagnose(items, {"cert": ...})`), builds `_meta()`, collects
  `server.known_secrets()` and `netchecks.export_facts(remote_facts)` (only when
  `remote_facts` has a `host`), and writes timestamped files in the current
  directory via `report.write_json` / `report.write_html`, which both go through
  `report.build_payload()` → `contract.redact()`.
- The session store holds every finding since the last `/clear`; `/report html`
  exports all of them. `remote_facts` is replaced only when `_gather_remote`
  returns, so an interrupted `/tls` or `/scan` leaves no new `remote_facts`.
- `remote_facts` carries `host`, `port`, `sni`, `ips`, `protocol`, `cipher`,
  `final_url`, `handshake_ip`, `endpoints`, `endpoint_comparison`,
  `probe_policy`; `export_facts()` keeps only the contract's facts subset.
- Python/OpenSSL/OS details exist only as `local.os` evidence (when `/local`
  ran); the reporting process can read `platform` / `ssl.OPENSSL_VERSION` itself.
- The contract schema declares `meta` as an open object in every published
  version; unknown `meta` keys validate.

## Goals / Non-Goals

**Goals:** two files from one redacted document; strict fidelity to the source
data; the existing serialisation and redaction; atomic output.

**Non-Goals:** per-scan filtering of the store (the scope is the same as
`/report html`: everything since the last `/clear`); evidence for or against
hypotheses beyond what findings and causes record; calling any AI service;
a contract version bump.

## Decisions

1. **One source document.** `report.build_payload(items, diag, meta, secrets,
   facts)` produces the redacted findings-contract document. The JSON file is
   that document; the Markdown is rendered *from the parsed document*, never from
   live objects. This guarantees "same scan", same redaction, and that the
   renderer cannot reach data the JSON lacks. Rejected: rendering Markdown from
   `Finding`/`Diagnosis` objects (two paths could disagree; redaction would need a
   second pass over prose).
2. **Agent data lives in `meta`.** `meta = _meta() | {"report_kind": "agent",
   "agent_report": {...}}` with `scan` (`host`, `port`, `sni`, `ips`,
   `handshake_ip`, `protocol`, `cipher`, `final_url`, `first_finding_utc`,
   `last_finding_utc`, `targets` = distinct finding targets), `environment`
   (`tool`, `python`, `openssl`, `platform` of the reporting process, plus the
   `local.os` evidence lines when present), and `configuration` (timeouts, SSH
   state). Missing values are `null`, never guessed. No schema change; the keys
   are documented in `docs/findings-contract.md`. Rejected: a new top-level
   block or a 1.6 schema — `meta` already exists for run context.
3. **Shared preparation, separate writer.** Extract the html/json preamble of
   `cmd_report` into `_report_inputs()` (diagnosis, meta, secrets, facts) used by
   every mode, so html/json output stays byte-identical; `agent` adds its meta and
   calls `report.write_agent_report(dir, payload)`.
4. **"Completed scan" = `remote_facts["host"]` is set and the store is
   non-empty.** That is exactly what a finished `/tls` or `/scan` leaves behind;
   `/clear` empties the store. The error text: `no completed scan in this session
   - run /scan <target> or /tls <target> first`.
5. **Markdown renderer** (`report.agent_markdown(payload) -> str`), pure and
   deterministic:
   - Sections exactly as the spec orders them; findings in recorded order.
   - Evidence areas map check ids to groups (`net.tcp`; `tls.handshake`;
     `tls.certvalid|hostname|chain|verify|verify.rootonly`; `tls.sni`;
     `tls.protocols`; `tls.weakcipher`; `tls.multiip`; `https.response`;
     `local.*`; `ssh.*|srv.*|nginx.*`; `cert.*` under certificate). A group with no
     finding prints `not collected in this session`.
   - Each finding prints status word (never a glyph alone), check id, title,
     evidence, `failure_kind`, `observation`, `uncertainty`, detail, `fix:`.
   - Protocol rows state the policy; `facts.probe_policy.default_probe` states are
     printed with fixed labels (`client-limited` → "this client could not offer
     the version — not a server rejection").
   - Endpoint coverage from `facts.endpoint_comparison` (`addresses`, `probed`,
     `comparable`) and `facts.endpoints[].state` (reachable = not
     `tcp-unreachable`/`timed-out`).
   - Diagnosis groups: confirmed / probable / possible (labelled "hypothesis")
     causes with evidence, limitations, remediation and the fixed line "SSL Doctor
     did not record contradicting evidence for this cause"; unresolved entries
     with observed / conclusion / uncertainty / next step; notes.
   - Next steps: recorded recommendations (causes, unresolved, findings,
     de-duplicated, in that order), then "missing evidence" from uncertainty and
     NOT TESTED findings, then a fixed preface that read-only verification comes
     before configuration changes. No other advice is generated.
   - The prompt (appendix below) is a module constant emitted unchanged.
6. **Atomic two-file write.** Serialise JSON (`json.dumps(..., ensure_ascii=False,
   indent=2, sort_keys=False, default=str)`) and Markdown in memory first; refuse
   if either target file exists; create the directory; write both to temp names
   in that directory, `os.replace` each into place; on any `OSError` remove what
   this call created (temps, renamed files, a directory it made) and print
   `error: could not write agent report: <path>: <reason>`. Encoding is UTF-8.

## Risks / Trade-offs

- [Session holds several targets] → the report states every distinct finding
  target in metadata and the scan section names the latest scan; advising
  `/clear` before a new case is documented. Filtering is deferred (Non-Goals).
- [Environment of the reporting process differs from the scan's] → both are in
  the same CLI session, and `local.os` evidence, when present, is quoted as the
  scan-time record.
- [Long reports exceed some chat limits] → out of scope; the JSON is the full
  record, the Markdown stays complete rather than truncated.
- [Prompt drift] → the prompt is a single constant with a test comparing it to
  the appendix text.

## Appendix: AI analysis prompt (verbatim)

The text between the rules below is the exact prompt to embed.

---

You are a senior TLS/PKI engineer and network troubleshooting specialist. Analyze the SSL Doctor report as evidence, not as unquestionable truth.

Your objective is to identify the most likely root cause of the reported problem, determine what is actually established by the available evidence, and recommend the safest next diagnostic steps.

Follow these rules:

1. Separate confirmed facts, probable explanations, unresolved hypotheses, and observations. Never present an unverified hypothesis as a confirmed root cause.

2. For every proposed root cause, provide:
   - A concise explanation.
   - Supporting evidence from the report.
   - Contradicting evidence or missing evidence.
   - Confidence level and justification.
   - The next test that would best confirm or reject it.

3. Interpret TLS protocol probes carefully. A successful handshake under a relaxed OpenSSL security policy does not, by itself, establish compatibility with ordinary clients. A `NO_PROTOCOLS_AVAILABLE` error can indicate a client-side limitation rather than a server rejection. Distinguish client limitations, server rejections, timeouts, and unreachable endpoints.

4. Evaluate certificate subject and SAN coverage, hostname matching, validity dates, trust-chain validation, intermediate certificates, SNI behavior, and differences between endpoints. Do not treat a different certificate without SNI as a defect by itself.

5. Interpret endpoint comparisons according to actual coverage. Do not generalize results from a subset of DNS addresses to all endpoints. Do not infer certificate mismatch when an endpoint never completed a comparable TLS handshake.

6. Distinguish TLS negotiation failures from HTTP redirects, application-layer errors, DNS problems, TCP connectivity failures, and local trust-store limitations.

7. Consider the local environment, including the operating system, OpenSSL version, proxy configuration, system clock, and client security policy. Explain how these factors may affect the observations.

8. Prioritize hypotheses by evidence strength and practical impact. Do not manufacture a root cause simply because the report contains a warning.

9. Recommend a minimal, ordered troubleshooting plan. Start with safe, read-only checks and tests that distinguish competing hypotheses. Explain what each test would prove and how to interpret its outcomes.

10. Recommend configuration changes only when evidence supports them. Identify the relevant component (for example, the TLS terminator, reverse proxy, load balancer, web server, certificate chain, or client trust store). Clearly distinguish verification steps from remediation steps.

11. Explicitly list the additional information required if the current report is insufficient. Never fabricate command output, server configuration, certificate properties, network conditions, or test results.

12. End with:
   - Most likely root cause, or state that the evidence is insufficient.
   - Confidence level.
   - Strongest supporting evidence.
   - Most important uncertainty.
   - Three prioritized next actions.
   - A clear statement of whether a server-side configuration change is justified by the current evidence.

Use precise technical language. Be concise but thorough. Reference exact report fields and observed values whenever possible.

---
