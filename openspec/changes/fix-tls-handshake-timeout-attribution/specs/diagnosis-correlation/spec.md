# Spec Delta

## Purpose

Extends the correlation rules so that each cause is attributed from the *failure mode* recorded by the probe, not from the check status alone. A handshake that stalls is a network-path cause; a handshake the server rejects is a server cause.

This delta builds on the requirements in the pending change `fix-chain-diagnosis-saas-enterprise` (capability `diagnosis-correlation`); nothing is archived under `openspec/specs/` yet, so these are additive requirements rather than modifications of an archived baseline.

## ADDED Requirements

### Requirement: A stalled handshake is not a protocol/cipher mismatch
The diagnosis MUST NOT raise a cause describing a protocol or cipher mismatch when the handshake finding reports a timeout-class failure, even when the per-version probe accepts some or all versions. The cause summary MUST require rejection evidence.

#### Scenario: Timeout with TLS 1.2 and 1.3 accepted
- **WHEN** the handshake finding is FAIL with a timeout-class failure and the protocol matrix reports TLS 1.2 and TLS 1.3 accepted
- **THEN** no cause describes a protocol/cipher mismatch
- **AND** no server-origin cause is raised *to explain the failure* from the handshake or protocol findings (the independent protocol-hardening observation may still appear)
- **AND** the top-ranked cause has origin "network" and names a stall or path interference
- **AND** the recommendation is to repeat the measurement or inspect the network path, not to change the server's protocol configuration

#### Scenario: Rejection with some versions accepted
- **WHEN** the handshake finding is FAIL because the peer rejected the offer with a TLS alert, and the protocol matrix reports some versions accepted
- **THEN** a probable server-origin cause describes the protocol/cipher mismatch
- **AND** its evidence states which versions were accepted and under which cipher policy

### Requirement: Attribution follows the recorded failure mode
The diagnosis SHALL select its cause from the handshake finding's recorded failure mode, using this mapping:

| Failure mode | Version probes | Origin | Certainty |
|---|---|---|---|
| negotiation stall | at least one accepted | network | probable |
| connect timeout | at least one accepted | network | probable |
| TLS alert | at least one accepted | server | probable |
| no version answered | none accepted | network | probable |
| every version refused | none accepted | network or server, per the refusal evidence | probable |

#### Scenario: Connect timeout but versions accepted
- **WHEN** the connection attempt times out while per-version probes complete
- **THEN** the cause has origin "network" and cites path instability or an inspection device

#### Scenario: Nothing answers
- **WHEN** no version probe receives a TLS response
- **THEN** the cause has origin "network" and states that the port may not serve TLS or that middle-boxes interfere

#### Scenario: Connection dropped during negotiation
- **WHEN** the handshake fails with a transport error although version probes complete
- **THEN** the cause has origin "network" and names reset/drop behaviour on the path

### Requirement: A recovered stall still produces a cause
When the handshake finding is a WARNING because a retry completed after a stall, the diagnosis SHALL raise a probable network-origin cause describing intermittent behaviour. It MUST NOT recommend a server configuration change for that cause.

#### Scenario: Handshake completed on retry
- **WHEN** the handshake finding is WARNING with a timeout-class failure mode
- **THEN** a probable network-origin cause reports the stall and its recovery
- **AND** the overall diagnosis is not PASS

### Requirement: Timeout evidence is never certain
A cause derived from a stalled or timed-out probe SHALL be labelled at most "probable". It MUST NOT be labelled "confirmed".

#### Scenario: Single stalled probe
- **WHEN** the only evidence for the cause is one timed-out handshake
- **THEN** the cause certainty is "probable"

### Requirement: Causes expose the failure classification and probe results
Each cause raised from handshake or protocol findings SHALL include the recorded failure mode and the per-version probe results in its evidence, so that a report can be audited without re-running the scan.

#### Scenario: Timeout cause evidence
- **WHEN** a network-origin stall cause is raised
- **THEN** its evidence includes the timeout phase, the probed address, the attempts made, and the accepted protocol versions

### Requirement: Unclassified failures fall back conservatively
When a handshake failure carries no failure classification, the diagnosis SHALL NOT claim a server protocol or cipher mismatch. It SHALL raise at most a probable network-origin cause and note that the failure mode could not be classified.

#### Scenario: Legacy finding without classification
- **WHEN** the handshake finding is FAIL without a recorded failure mode while the protocol matrix reports accepted versions
- **THEN** no cause describes a protocol/cipher mismatch
- **AND** the cause origin is "network" with a note that the failure mode was not classified

### Requirement: Independent server faults are still reported during a stall
A stalled handshake MUST NOT suppress server-side causes established by other checks. Chain, chain-file, vhost and configured-versus-presented causes SHALL be raised as before.

#### Scenario: Stall plus incomplete chain
- **WHEN** the handshake stalls and the chain check reports a missing intermediate
- **THEN** both the network-origin stall cause and the server-origin chain cause appear in the diagnosis
