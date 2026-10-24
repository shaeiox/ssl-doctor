# Spec Delta

## Purpose

Extends the probe diagnostics with reconciliation between the primary handshake and the per-version probes, bounded retries for inconclusive probes, and an explicit distinction between acceptance under a relaxed cipher policy and ordinary client interoperability.

This delta adds requirements to the capability introduced by the pending change `fix-tls-handshake-timeout-attribution`; it replaces none of its requirements.

## ADDED Requirements

### Requirement: All probes of one scan share the same target, server name, address and deadline
The primary handshake and every per-version probe SHALL connect to the same address, port, server name and probe deadline, and the finding evidence SHALL state the address, server name and deadline used.

#### Scenario: Shared probe parameters
- **WHEN** a scan negotiates a handshake and then runs the per-version probes
- **THEN** every probe uses the same resolved address, port and server name
- **AND** the evidence of the per-version finding names them

### Requirement: A per-version probe outcome is explicit and a timeout is inconclusive
Each version row SHALL be reported as one of: accepted, accepted under relaxed cipher policy, refused (TLS alert), inconclusive (timeout or transport error), or unsupported by this client build. A probe that produced no answer within its deadline MUST NOT be reported as refused or as proof that the version is unsupported.

#### Scenario: Version probe times out
- **WHEN** a version probe receives no response before its deadline
- **THEN** its row is reported as inconclusive with the elapsed time
- **AND** the version is not counted as refused or unsupported

#### Scenario: Version probe is refused
- **WHEN** the server answers the probe with a TLS alert
- **THEN** its row is reported as refused with the alert text

### Requirement: The primary handshake is authoritative for its negotiated version
The per-version probes SHALL be reconciled with the protocol the primary handshake negotiated. A version that the primary handshake established MUST NOT be reported as refused or unsupported; if its dedicated probe is inconclusive, the row SHALL say so and cite the primary success.

#### Scenario: Primary TLS 1.3 succeeds and the TLS 1.3 probe stalls
- **WHEN** the primary handshake negotiated TLS 1.3 and the dedicated TLS 1.3 probe times out
- **THEN** the TLS 1.3 row is reported as inconclusive
- **AND** the row cites that the primary handshake negotiated TLS 1.3
- **AND** no wording states or implies that the server lacks TLS 1.3

#### Scenario: Both probes succeed
- **WHEN** the primary handshake and the dedicated probe for the same version both succeed
- **THEN** the row is reported as accepted and no inconsistency is recorded

### Requirement: Inconclusive probe results are visible, not silent
A version finding that contains an inconclusive row SHALL NOT be reported as a clean PASS. The finding SHALL carry a failure classification of `probe-inconclusive`, name the inconclusive versions in its detail, and prevent the scan from being reported as fully passing on protocol grounds.

#### Scenario: Inconclusive row inside an otherwise acceptable matrix
- **WHEN** one version is inconclusive and the others are accepted
- **THEN** the finding status is WARNING, its detail names the inconclusive version, and its failure classification is `probe-inconclusive`

#### Scenario: Protocol policy warnings remain
- **WHEN** deprecated versions are accepted under a relaxed policy and another version is inconclusive
- **THEN** both the policy warning and the inconclusive result are reported

### Requirement: Inconclusive probes are retried once within a bounded budget
Each inconclusive version SHALL be retried once on a fresh connection with the same parameters. The retry budget SHALL be derived from the configured probe deadline and the number of versions, and SHALL be reported when it is exhausted. Retries MUST NOT extend the scan without bound.

#### Scenario: Retry succeeds
- **WHEN** the first probe for a version is inconclusive and the retry completes a handshake
- **THEN** the row is reported as accepted with a note that a retry was needed
- **AND** the version counts as accepted for policy purposes

#### Scenario: Retry fails as well
- **WHEN** both the probe and its retry are inconclusive
- **THEN** the row remains inconclusive and states both attempts

#### Scenario: Budget exhausted
- **WHEN** the configured budget is exhausted before all retries are attempted
- **THEN** the remaining rows state that the retry was skipped because the budget was exhausted

#### Scenario: Retry does not change a definite answer
- **WHEN** the probe is refused with a TLS alert
- **THEN** it is not retried

### Requirement: Relaxed-policy acceptance is distinguished from default-client interoperability
The finding SHALL record, per version, whether the probe used a relaxed cipher or security policy. When a version is accepted only under a relaxed policy, the finding SHALL state that a default-configured modern client may still be refused, and MUST NOT present the result as proof that ordinary clients can connect with that version.

#### Scenario: Accepted only under a relaxed policy
- **WHEN** a version is accepted with a relaxed cipher policy and refused when the same client offers its default policy
- **THEN** the row states that it was accepted only under the relaxed policy
- **AND** the finding states that a default-configured client is refused

#### Scenario: Accepted with the default policy
- **WHEN** the version is accepted with default security settings
- **THEN** the row is reported as accepted and interoperability with default clients is stated

#### Scenario: Explicit rejection under both policies
- **WHEN** both probes are refused
- **THEN** the row is reported as refused and no relaxed-policy statement is attached

### Requirement: Deprecated-version security findings are preserved
Acceptance of deprecated TLS versions SHALL continue to be reported as a security/policy finding, with the probe's limitations stated. A successful modern handshake elsewhere in the scan MUST NOT remove that finding.

#### Scenario: TLS 1.0 accepted while TLS 1.3 is in use
- **WHEN** the primary handshake negotiates TLS 1.3 and a relaxed probe shows TLS 1.0 accepted
- **THEN** the finding reports the deprecated version as enabled
- **AND** its detail states that acceptance required the relaxed policy and what that implies for default clients
