# Spec Delta

## Purpose

Exports a completed SSL Doctor scan as an AI-ready Markdown report plus a
matching machine-readable findings document, so an operator can hand the case
to any AI model without losing evidence, uncertainty or analysis rules.

## ADDED Requirements

### Requirement: `/report agent` exports the latest completed scan
`/report agent [dir]` SHALL write `agent-report.md` and `agent-report.json` for
the session's findings and its most recent completed remote scan, without
running any check, and SHALL print both file paths and a one-line summary
(target, overall status, finding counts).

#### Scenario: After a scan
- **WHEN** `/tls shop.example` has completed and the operator runs `/report agent`
- **THEN** both files exist in one new directory and the CLI shows their paths, the target and the counts

#### Scenario: No probe is re-run
- **WHEN** `/report agent` runs
- **THEN** no network connection, SSH command or local check is performed

### Requirement: Output location follows the report convention
Without an argument, the files SHALL be written to a new timestamped directory
`ssl-doctor-agent-report-<YYYYmmdd-HHMMSS>` in the current directory. With a
`dir` argument they SHALL be written into that directory, creating it if needed.
An existing `agent-report.md` or `agent-report.json` there SHALL NOT be
overwritten.

#### Scenario: Default location
- **WHEN** the operator runs `/report agent`
- **THEN** the files are `./ssl-doctor-agent-report-<timestamp>/agent-report.md` and `.json`

#### Scenario: Directory already holds a report
- **WHEN** `/report agent out` runs and `out/agent-report.md` exists
- **THEN** the command fails with a message naming the file and nothing is written

### Requirement: A completed scan is required
When the session has no completed `/scan` or `/tls` (none ran, it was
interrupted, or `/clear` discarded it), the command SHALL write nothing and SHALL
explain how to produce a scan first.

#### Scenario: Fresh session
- **WHEN** `/report agent` is the first command of a session
- **THEN** it reports that no completed scan is available, suggests `/scan <target>` or `/tls <target>`, and creates no file or directory

### Requirement: Failures leave no partial report
Both documents SHALL be fully serialised before anything is written. A
serialisation or file-system error SHALL be reported as an error, SHALL leave no
partial or single file behind, and SHALL leave the session usable.

#### Scenario: Directory not writable
- **WHEN** the target directory cannot be written
- **THEN** the CLI prints an error naming the path and neither file exists

#### Scenario: Second file fails
- **WHEN** writing `agent-report.json` fails after the Markdown was prepared
- **THEN** no `agent-report.md` remains either

### Requirement: The JSON is a findings-contract document
`agent-report.json` SHALL be a valid findings-contract document of the current
schema version, generated with the same serialisation as `/report json`, with
generation timestamp, findings, diagnosis and facts. It SHALL add only `meta`
keys describing the report kind, scan target, resolved addresses, negotiated
protocol and cipher, and execution environment.

#### Scenario: Contract validation
- **WHEN** `agent-report.json` is validated against `schemas/findings-<version>.schema.json`
- **THEN** it is valid, and its findings, diagnosis and facts equal those of `/report json` for the same session

#### Scenario: Probe detail preserved
- **WHEN** the scan recorded legacy protocol probes and partial endpoint coverage
- **THEN** the JSON keeps `probe_policy` (support, default-probe states) and `endpoint_comparison` (addresses, probed, comparable), plus every finding's `failure_kind`, `observation` and `uncertainty`

### Requirement: Both files describe the same scan
The Markdown SHALL be rendered only from the same redacted document that is
written as JSON, so both files carry the same target, timestamps, counts,
statuses, findings and diagnosis.

#### Scenario: Same counts
- **WHEN** the JSON summary has 8 PASS, 1 WARNING and 4 NOT TESTED
- **THEN** the Markdown executive summary states exactly those counts and the same overall status

### Requirement: The Markdown has the fixed section structure
`agent-report.md` SHALL contain, in order: report metadata (tool version,
schema version, scan time, target, configuration, environment), executive
summary, target and environment, detailed evidence, findings and diagnosis,
recommended next steps, and AI analysis instructions.

#### Scenario: Sections present
- **WHEN** the report is generated
- **THEN** the seven section headings appear in that order

### Requirement: Evidence is grouped by area and gaps are explicit
Detailed evidence SHALL be grouped by area: TCP, TLS handshake, certificate and
trust, SNI, protocol probes with the policy of each probe, ciphers, endpoint
comparison, HTTPS and redirects, local machine, and server-side checks. An area
with no finding SHALL be stated as not collected in this session.

#### Scenario: Server checks not run
- **WHEN** the scan was client-only
- **THEN** the server-side area says no server-side checks were run

#### Scenario: Endpoint coverage
- **WHEN** DNS returned 7 addresses and 4 were compared
- **THEN** the endpoint area states 7 resolved, 4 probed, the reachable count and 4 comparable, and does not describe all 7 as checked

### Requirement: Statuses and conclusions are never upgraded
Every finding SHALL keep its exact status (PASS, FAIL, WARNING, NOT TESTED) and
the overall status SHALL be the diagnosis's. Observations, possible causes,
probable causes, confirmed causes and unresolved findings SHALL appear in
separate labelled groups, with each cause's evidence, limitations and
remediation as recorded. No finding, cause or conclusion absent from the source
data SHALL appear.

#### Scenario: Unverified legacy TLS
- **WHEN** the scan holds an unresolved `tls.protocols` warning and no protocol cause
- **THEN** the Markdown lists it under unresolved findings with its uncertainty, and no section calls legacy TLS confirmed

#### Scenario: Not tested stays not tested
- **WHEN** `tls.sni` is NOT TESTED
- **THEN** it is shown as NOT TESTED, never as PASS or FAIL

#### Scenario: No contradicting evidence recorded
- **WHEN** a cause has no contradicting evidence in the source data
- **THEN** the report states that SSL Doctor did not record contradicting evidence instead of inventing any

### Requirement: Client limitations are separated from server results
Probe outcomes that the source data marks as client-limited, timed out or
unreachable SHALL be labelled as such and SHALL NOT be presented as server
rejections.

#### Scenario: Client could not offer TLS 1.0
- **WHEN** the default-policy TLS 1.0 probe is `client-limited`
- **THEN** the Markdown labels it a limitation of this client, not a server rejection

### Requirement: Next steps come from the source data
Recommended next steps SHALL reproduce the recorded remediation of causes,
unresolved findings and findings, list the missing evidence recorded as
uncertainty or NOT TESTED, and SHALL NOT add configuration-change advice that
the source data does not contain.

#### Scenario: Unresolved finding
- **WHEN** an unresolved finding recommends a controlled verification
- **THEN** that recommendation appears under next steps together with its uncertainty as missing evidence

### Requirement: The AI analysis prompt is included verbatim
The Markdown SHALL end with the AI analysis prompt exactly as specified for this
feature, unmodified; report-specific details SHALL be supplied in the earlier
sections, not by editing the prompt.

#### Scenario: Prompt fidelity
- **WHEN** the prompt section of `agent-report.md` is compared with the specified text
- **THEN** they are identical

### Requirement: Reports contain no secrets
Both files SHALL be redacted with the same conventions as other reports: session
secrets (in plain, URL-encoded, base64 and hex forms) and private-key blocks
replaced by the redaction marker. Nothing SHALL be transmitted anywhere.

#### Scenario: Password in evidence
- **WHEN** an SSH password appears in a finding's evidence
- **THEN** neither file contains it, in any encoding, and both contain the redaction marker

### Requirement: Existing report modes are unchanged
`/report html`, `/report json` and `/report both` SHALL keep their arguments,
file names and content.

#### Scenario: HTML report after this change
- **WHEN** the operator runs `/report html out.html`
- **THEN** the file is written exactly as before this change
