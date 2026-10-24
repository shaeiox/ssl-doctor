# Spec Delta

## Purpose

Defines the versioned, machine-readable format for findings and diagnoses, so that the CLI, scan agents and hosted service exchange and store results interchangeably.

## ADDED Requirements

### Requirement: Results carry a schema version
Every exported findings or diagnosis document SHALL include a schema version. Consumers SHALL reject documents with an unsupported major version, with an explicit error.

#### Scenario: Unsupported major version
- **WHEN** the service receives a document whose major schema version it does not support
- **THEN** it rejects the document with an error naming the received and supported versions

### Requirement: Results are identical across producers
A scan of the same endpoint SHALL produce structurally identical findings (same check identifiers, statuses and scopes), whether run from the CLI or an agent.

#### Scenario: CLI and agent parity
- **WHEN** the CLI and an agent scan the same endpoint under the same conditions
- **THEN** their findings documents match on check identifiers, statuses and scopes

### Requirement: Secrets never appear in results
Findings and diagnosis documents MUST NOT contain passwords, private key material, or authentication tokens.

#### Scenario: Password-auth server scan
- **WHEN** a server-side scan used password authentication
- **THEN** the exported document contains no password value or derivative of it
