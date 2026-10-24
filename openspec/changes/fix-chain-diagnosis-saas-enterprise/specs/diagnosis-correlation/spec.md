# Spec Delta

## Purpose

Turns individual findings from the network, client machine and server into ranked root causes. Attributes each cause to the correct side (server, client, certificate, network), so engineers fix the right system.

## ADDED Requirements

### Requirement: Incomplete server chain is a server cause
The system SHALL raise a probable or confirmed server-origin cause, "server does not send the full chain", whenever the network chain check or the nginx chain-file check reports a missing intermediate. This MUST hold even when validation on the checking machine passes.

#### Scenario: Customer scenario — leaf-only nginx, cached intermediate
- **WHEN** the network chain check is WARNING for a missing intermediate, and system-store validation passes
- **THEN** the diagnosis overall is not PASS
- **AND** the top-ranked cause has origin "server" and recommends serving the full chain in `ssl_certificate`

### Requirement: Server-side nginx findings are correlated
The system SHALL consider every nginx server-side finding (chain file, vhost selection, certificate reference, protocols) when building the diagnosis.

#### Scenario: Leaf-only chain file on server
- **WHEN** the nginx chain-file finding reports one certificate in the configured file
- **THEN** the diagnosis includes a server-origin cause citing that file path

#### Scenario: Fallback vhost answers
- **WHEN** the nginx vhost finding reports the domain is served by a fallback server block
- **THEN** the diagnosis includes a server-origin cause that the domain has no dedicated server block

### Requirement: Client trust is not blamed for server chain faults
The system MUST NOT raise a client-origin "issuing CA missing from trusted root store" cause when the presented chain is incomplete, unreadable, or not yet captured.

#### Scenario: Full chain correctly served
- **WHEN** the server presents a complete chain whose root is in the client ROOT store
- **THEN** no client-origin trust-store cause is raised

#### Scenario: Incomplete chain
- **WHEN** the presented chain is incomplete
- **THEN** the client trust-store check is skipped or NOT TESTED, and only the server chain cause is raised

### Requirement: Certainty reflects evidence
The system SHALL label a cause "confirmed" only when it is backed by direct evidence of the fault. A cause inferred from the checking machine's environment SHALL be labelled at most "probable".

#### Scenario: Inferred cause
- **WHEN** a cause is derived only from a validation failure on the checking machine
- **THEN** its certainty is "probable", not "confirmed"
