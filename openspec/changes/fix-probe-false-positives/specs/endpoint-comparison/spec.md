# Spec Delta

## Purpose

Compares the TLS endpoints a hostname resolves to, classifies what each probe actually produced, and decides whether a certificate difference between nodes is established — without ever treating a transport failure as a certificate fact.

## ADDED Requirements

### Requirement: Each endpoint probe reports an explicit outcome state
The endpoint comparison SHALL record one state per probed address: `negotiated` (handshake completed and certificate facts captured), `tls-rejected` (peer answered with a TLS alert), `tcp-unreachable` (connect failed), `timed-out` (deadline exceeded) or `probe-unavailable` (handshake completed but no certificate could be read). The state SHALL be reported per address in the finding evidence and in the structured facts.

#### Scenario: Mixed reachable and unreachable endpoints
- **WHEN** one address completes a handshake and another address reports a routing error
- **THEN** the first endpoint is recorded as `negotiated` and the second as `tcp-unreachable`
- **AND** the evidence shows the OS error for the unreachable address alongside its state

#### Scenario: Endpoint rejected the handshake
- **WHEN** an address answers with a TLS alert
- **THEN** that endpoint is recorded as `tls-rejected`, not as an error string

#### Scenario: Probe deadline exceeded
- **WHEN** an address does not answer within the probe deadline
- **THEN** it is recorded as `timed-out`

### Requirement: Only endpoints with collected certificate evidence are compared
The comparison SHALL use only endpoints in state `negotiated`. Transport failures, rejections, timeouts and unreadable certificates MUST NOT participate in the comparison of certificates.

#### Scenario: Unreachable address next to a working one
- **WHEN** one endpoint negotiated and three endpoints are unreachable
- **THEN** the finding MUST NOT state that the endpoints present different certificates
- **AND** the unreachable addresses appear only as unreachable endpoints

#### Scenario: Timeout next to a working endpoint
- **WHEN** one endpoint negotiated and another timed out
- **THEN** the timeout is not counted as a differing certificate

### Requirement: Comparison covers identity, hostname coverage and chain
For comparable endpoints the comparison SHALL cover the leaf certificate fingerprint, the hostname coverage of the requested server name, and the presented-chain status. A difference in any of these SHALL be reported, naming the attribute that differs.

#### Scenario: Different leaves on two reachable nodes
- **WHEN** two endpoints negotiate and present different leaf fingerprints
- **THEN** the finding is a WARNING that names both addresses and both fingerprints

#### Scenario: Same leaf, different chain
- **WHEN** two endpoints present the same leaf but one sends an incomplete chain
- **THEN** the finding is a WARNING that names the chain status as the differing attribute

#### Scenario: Same certificate facts everywhere
- **WHEN** every comparable endpoint presents the same fingerprint, hostname coverage and chain status
- **THEN** the finding is PASS

### Requirement: Inconsistency requires at least two comparable endpoints
The system MUST NOT report endpoint inconsistency with fewer than two endpoints that yielded certificate evidence. With exactly one comparable endpoint the result SHALL be inconclusive, and the finding SHALL state how many endpoints yielded evidence and why the others did not.

#### Scenario: Single comparable endpoint
- **WHEN** exactly one endpoint negotiated and the rest did not yield a certificate
- **THEN** the finding status is NOT TESTED with a failure classification of `probe-inconclusive`
- **AND** its evidence states "1 of N endpoints yielded a certificate" and lists the states of the others

#### Scenario: No comparable endpoint
- **WHEN** no endpoint yielded a certificate
- **THEN** the finding status is NOT TESTED
- **AND** the failure classification is `endpoint-unreachable` when every failure was a transport failure

### Requirement: Transport reachability stays available as its own evidence
Transport failures found while comparing endpoints SHALL remain visible as evidence rows with their state and reason, and SHALL NOT be removed from the report merely because the comparison is inconclusive.

#### Scenario: Unreachable IPv6 endpoints reported
- **WHEN** IPv6 endpoints report that the network is unreachable
- **THEN** each address and its reason appear in the finding evidence
- **AND** no cause of certificate inconsistency is raised from them

### Requirement: Comparison results are available to the diagnosis
The comparison finding SHALL expose its conclusion in a machine-readable form (comparable endpoint count, whether a difference was found, the differing attribute) and its per-endpoint states in the structured facts, so correlation and reporting do not have to parse evidence text.

#### Scenario: Consumer reads the outcome
- **WHEN** a report is exported
- **THEN** the endpoint states and the comparison outcome are present in the structured facts
