# diagnosis-correlation Specification

## Purpose

Makes the diagnosis separate raw observations from inferred causes, derive its confidence labels from the strength and completeness of the collected evidence, and state the limits of that evidence. Extends the requirements introduced by the pending changes `fix-chain-diagnosis-saas-enterprise` and `fix-tls-handshake-timeout-attribution`.

## Requirements

### Requirement: Observations and inferred causes are distinct
The diagnosis SHALL treat probe results as observations and only those combinations that establish a fault as causes. An observation SHALL NOT be converted into a probable or confirmed configuration defect without independent supporting evidence.

#### Scenario: Observation without corroboration
- **WHEN** the only evidence is that certificates differ with and without SNI, or that a probe was inconclusive
- **THEN** no confirmed or probable cause is raised
- **AND** the observation remains visible in the exposed evidence and notes

### Requirement: Certainty reflects evidence strength and completeness
The certainty of a cause SHALL be derived from the evidence rules: `confirmed` requires direct measurement of the fault with complete evidence; `probable` requires direct measurement with a material gap; `possible` applies to observations, corroboration, and results whose scope is limited by the probe.

#### Scenario: Two comparable endpoints disagree
- **WHEN** two endpoints both yielded a certificate and the certificates differ
- **THEN** the inconsistency cause may be `confirmed`

#### Scenario: One comparable endpoint
- **WHEN** only one endpoint yielded a certificate
- **THEN** no inconsistency cause is raised
- **AND** the diagnosis notes state that endpoint comparison was inconclusive

#### Scenario: Probe policy limits the conclusion
- **WHEN** a deprecated version is reported accepted only under a relaxed policy
- **THEN** the security cause is at most `possible`
- **AND** its limitations state the policy used

### Requirement: Transport failures and inconclusive probes are never promoted
A cause SHALL NOT be `confirmed` or `probable` when its only support is a transport failure, a timeout, an unreachable endpoint, or an inconclusive probe.

#### Scenario: Unreachable endpoint
- **WHEN** endpoints are unreachable and one endpoint answered
- **THEN** no cause of certificate or configuration inconsistency is raised from the unreachable endpoints
- **AND** any network cause raised is labelled `possible` or stated as a note

#### Scenario: Inconclusive version probe
- **WHEN** a version probe is inconclusive while the primary handshake succeeded
- **THEN** the diagnosis does not raise a server protocol cause
- **AND** it notes that the probe result was inconclusive

### Requirement: Every cause states its supporting evidence and its limitations
Each cause SHALL expose the evidence that supports it and, where the evidence has a material gap, list that gap as a limitation. Causes that cannot state a limitation SHALL be reserved for direct, complete measurements.

#### Scenario: Cause with a gap
- **WHEN** a cause is inferred from a single measurement, a single endpoint, a relaxed-policy probe, or an unavailable comparison
- **THEN** its limitations name that gap

#### Scenario: Cause with direct evidence
- **WHEN** the served chain is measured incomplete, or two comparable endpoints serve different certificates
- **THEN** the cause may be `confirmed` and needs no limitation about missing evidence

### Requirement: Existing verdict semantics are preserved
The overall verdict rules SHALL remain: `confirmed` causes give FAIL, any cause gives WARNING, no cause gives PASS. Introducing observation-only results MUST NOT silently turn a scan into PASS, and MUST NOT turn an observation into FAIL.

#### Scenario: Observation-only scan
- **WHEN** the only results are observations such as an SNI difference
- **THEN** the overall verdict is not FAIL

#### Scenario: Confirmed fault
- **WHEN** a cause is confirmed from direct evidence
- **THEN** the overall verdict is FAIL, as before

### Requirement: The diagnosis exposes its inconclusive outcomes
When evidence needed for a conclusion could not be collected — endpoints without certificates, an inconclusive version probe, a probe without SNI — the diagnosis SHALL state the missing evidence in its notes, naming what could not be determined and what would settle it.

#### Scenario: Endpoint comparison inconclusive
- **WHEN** only one endpoint yielded a certificate
- **THEN** the notes state that the endpoint comparison was inconclusive and which endpoints produced no certificate
