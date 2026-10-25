# protocol-policy-evidence Specification

## Purpose

Makes the TLS protocol matrix report what each probe established about the server
and what it established about the client, and makes the diagnosis state the
limits of that evidence instead of asserting ordinary-client support from a
deliberately weakened handshake.

## Requirements

### Requirement: Relaxed-policy acceptance is not ordinary-client support
The protocol matrix SHALL probe every deprecated version that answers under a
relaxed cipher policy again with the client's default policy, and SHALL report the
two results separately.

#### Scenario: Legacy version accepted under both policies
- **WHEN** TLS 1.0 answers with `ALL:@SECLEVEL=0` and also with the default policy
- **THEN** the version is classed `default`
- **AND** the diagnosis may state that ordinary clients can negotiate it

#### Scenario: Legacy version accepted only under the relaxed policy
- **WHEN** TLS 1.0 answers with `ALL:@SECLEVEL=0` and the default-policy probe is refused
- **THEN** the version is classed `relaxed-only`
- **AND** the finding stays `WARNING` with `observation="legacy-accepted-relaxed-only"`
- **AND** the cause is `possible` and carries the limitation that a default-configured client is refused

#### Scenario: Default-policy probe gives no answer
- **WHEN** the relaxed probe accepts a legacy version and the default-policy probe times out or is client-limited
- **THEN** the version is classed `relaxed-only-unverified`
- **AND** no cause about server support is raised, only a diagnosis note
- **AND** the remediation asks for a retest from a capable client

### Requirement: A local probe limitation is never a server refusal
A probe that fails before the server is asked SHALL be reported as a limitation of
the test.

#### Scenario: Client has no applicable protocol or cipher
- **WHEN** the local SSL context cannot build the offer (`NO_PROTOCOLS_AVAILABLE`, `NO_CIPHERS_AVAILABLE`, `CA MD TOO WEAK`)
- **THEN** the row states that this client could not offer the version
- **AND** the version is not counted as refused and no cause claims it is unsupported

### Requirement: TLS 1.2 and 1.3 availability stays accurate
The matrix SHALL NOT describe TLS 1.2 or 1.3 as unsupported or insecure because a
relaxed probe also succeeded.

#### Scenario: TLS 1.2 accepted with the default policy
- **WHEN** the TLS 1.2 probe succeeds with default settings
- **THEN** the version is classed `default` and the finding is `PASS` unless another version warrants a warning

#### Scenario: TLS 1.3 accepted
- **WHEN** the primary handshake negotiated TLS 1.3
- **THEN** the TLS 1.3 row is never `refused`, and a failed re-probe is `inconclusive`

### Requirement: Confidence, limitations and remediation match the evidence
The certainty, limitations and remediation of a protocol cause SHALL follow the
policy that produced the evidence.

#### Scenario: Default-policy acceptance
- **WHEN** the evidence is a default-policy acceptance
- **THEN** the cause may be `possible`/`probable` with no policy limitation and a remediation to disable the version

#### Scenario: Relaxed-only acceptance
- **WHEN** the evidence is a relaxed-only acceptance
- **THEN** the cause is `possible`, lists the relaxed-policy limitation and still recommends disabling TLS 1.0/1.1

#### Scenario: Unverified or inconclusive evidence
- **WHEN** the evidence is unverified or inconclusive
- **THEN** no cause asserts server support, and the diagnosis notes name the probe gap
