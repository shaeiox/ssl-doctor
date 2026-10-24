# Spec Delta

## Purpose

Gives each customer organization an isolated workspace in the hosted service. Each workspace holds its own targets, scan jobs, results history, and diagnoses.

## ADDED Requirements

### Requirement: Tenant data is isolated
The system MUST NOT return or modify one organization's targets, jobs, results, agents or audit records in response to a request authenticated for another organization.

#### Scenario: Cross-tenant read
- **WHEN** a user of organization A requests a scan result belonging to organization B by its identifier
- **THEN** the system responds as if the result does not exist

### Requirement: Targets can be registered
A permitted user SHALL be able to register a target as host or URL, port, optional SNI name, and the agents allowed to scan it.

#### Scenario: Register target
- **WHEN** an engineer registers `shop.example:443` with a client agent and a server agent
- **THEN** the target appears in the workspace with both agents assigned

### Requirement: Scans run on demand and record history
A permitted user SHALL be able to start a scan of a target. The system SHALL keep every completed scan's findings and diagnosis as an immutable history entry.

#### Scenario: Repeat scans
- **WHEN** a target is scanned twice
- **THEN** both results are kept and can be compared side by side

### Requirement: Results are shareable as reports
A permitted user SHALL be able to export any scan result as an HTML or JSON report in the findings-contract format.

#### Scenario: Export JSON
- **WHEN** a user exports a scan result as JSON
- **THEN** the file validates against the current findings-contract schema
