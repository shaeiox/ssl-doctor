# Spec Delta

## Purpose

Defines how the TLS handshake probe and the per-version protocol probes classify, confirm and report their failures, so that a stalled negotiation is never confused with a protocol/cipher rejection and the two probes can never contradict each other without saying why.

## ADDED Requirements

### Requirement: Handshake failures are classified in a machine-readable field
The `tls.handshake` finding SHALL carry an optional `failure_kind` field whose value is one of `connect-timeout`, `negotiation-timeout`, `tls-alert`, `network-error`, or empty when no failure occurred. The diagnosis MUST be able to distinguish the failure modes without parsing evidence text.

#### Scenario: Negotiation stalls
- **WHEN** the TCP connection opens but the peer sends no TLS response before the timeout elapses
- **THEN** the finding status is FAIL and `failure_kind` is `negotiation-timeout`

#### Scenario: Protocol or cipher rejected
- **WHEN** the peer answers with a TLS alert or a no-shared-cipher error
- **THEN** the finding status is FAIL and `failure_kind` is `tls-alert`

#### Scenario: TCP connect times out
- **WHEN** the connection attempt to the probed address itself exceeds the timeout
- **THEN** the finding status is FAIL and `failure_kind` is `connect-timeout`

#### Scenario: Connection dropped during negotiation
- **WHEN** the connection is reset or becomes unreachable after the socket opened
- **THEN** the finding status is FAIL and `failure_kind` is `network-error`

#### Scenario: Handshake succeeds
- **WHEN** the handshake completes
- **THEN** `failure_kind` is empty

### Requirement: Handshake evidence names the phase, the address and the attempt
The `tls.handshake` finding SHALL state whether the connect phase or the negotiation phase failed, which address and port were probed, the elapsed time, and how many attempts were made. Evidence MUST NOT describe a connect timeout and a stalled negotiation with the same wording.

#### Scenario: Stalled negotiation reported
- **WHEN** the negotiation phase times out
- **THEN** the evidence reads that TCP connected, TLS negotiation stalled for N seconds, and names the probed address and port

#### Scenario: Repeated attempts
- **WHEN** more than one attempt was made
- **THEN** the evidence names each attempt and its outcome

### Requirement: A stall is confirmed before a handshake is reported as failed
A timeout-class handshake failure (`connect-timeout`, `negotiation-timeout`) SHALL be retried once on a fresh connection with the same parameters before the finding is set to FAIL. A failure caused by an explicit TLS rejection MUST NOT be retried. A retry that succeeds SHALL produce a `WARNING`, not a `FAIL`, and MUST retain the negotiated protocol, cipher and presented certificate so that downstream checks still run.

#### Scenario: Stall then success
- **WHEN** the first attempt stalls and a second attempt completes the handshake
- **THEN** the finding status is WARNING with `failure_kind` describing the stall
- **AND** the evidence records that the handshake completed on the second attempt
- **AND** certificate, chain, hostname and validation checks still execute

#### Scenario: Stall on both attempts
- **WHEN** both attempts stall
- **THEN** the finding status is FAIL with `failure_kind` describing the stall, and the evidence names both attempts

#### Scenario: Rejection is not retried
- **WHEN** the peer rejects the handshake with a TLS alert
- **THEN** exactly one attempt is made and the finding status is FAIL

### Requirement: Probes measure the address the TCP check verified
The handshake probe and every per-version probe SHALL connect to the same address that `net.tcp` proved reachable, and SHALL record that address in their evidence. Comparing several addresses SHALL remain the responsibility of the multi-address check.

#### Scenario: Multiple DNS records
- **WHEN** the hostname resolves to several IPv4/IPv6 addresses and the TCP check passed against one of them
- **THEN** the handshake and the per-version probes use that address
- **AND** their evidence names it

### Requirement: Per-version probe outcomes are classified, and a timeout is not a refusal
Each row of the `tls.protocols` finding SHALL be classified as accepted, refused (TLS alert), timed out, or network error. A probe that produced no TLS response MUST NOT be reported as refused. The finding SHALL carry `failure_kind` `no-version-accepted` when every version was refused, `no-version-answered` when every version timed out or errored, and an empty value otherwise.

#### Scenario: Every version times out
- **WHEN** no version probe receives a TLS response
- **THEN** the finding status is FAIL, `failure_kind` is `no-version-answered`, and no row says "refused"

#### Scenario: Some versions accepted
- **WHEN** at least one version probe completes a handshake
- **THEN** the finding is PASS or WARNING, its rows name the accepted versions, and `failure_kind` is empty

### Requirement: Probe evidence discloses the cipher policy used
When the per-version probe relaxes cipher security for legacy versions, the finding SHALL state that policy in its evidence, so that "accepted" is not read as proof that a modern client can connect.

#### Scenario: Legacy versions accepted under a relaxed policy
- **WHEN** TLS 1.0, 1.1 or 1.2 is reported accepted while the probe used a relaxed cipher policy
- **THEN** the evidence states that a relaxed cipher policy was used for those versions

### Requirement: Handshake and protocol findings are mutually consistent
When the generic handshake fails but at least one per-version probe completes, the handshake finding SHALL state that the failure is a stall or rejection on the default path rather than a protocol/cipher limitation, and SHALL name the versions that worked.

#### Scenario: Reported timeout with working version probes
- **WHEN** the handshake finding is FAIL for a timeout and the protocol matrix reports accepted versions
- **THEN** the handshake finding's evidence names those accepted versions and describes the failure as a stall
- **AND** the two findings do not present the endpoint as unable to negotiate TLS

### Requirement: Failure classification is an additive contract change
The failure classification SHALL be published as an optional field in a new minor findings schema version. Documents produced before the change MUST continue to validate, and the existing check identifiers MUST remain unchanged.

#### Scenario: Older document consumed
- **WHEN** a findings document without the failure field is loaded
- **THEN** it validates unchanged

#### Scenario: New document consumed
- **WHEN** a findings document carrying a failure classification is exported and validated
- **THEN** it validates against the published minor schema version that declares the field
