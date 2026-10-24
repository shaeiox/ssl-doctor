# Spec Delta

## Purpose

Provides each organization with a tamper-evident record of security-relevant actions, for compliance reviews and incident investigation.

## ADDED Requirements

### Requirement: Security-relevant actions are recorded
The system SHALL record an audit entry for every sign-in, role or member change, SSO change, agent enrollment or revocation, target change, scan start, and report export. Each entry SHALL include actor, organization, action, object, timestamp and source address.

#### Scenario: Agent revoked
- **WHEN** an admin revokes an agent
- **THEN** an audit entry names the admin, the agent, the action "agent.revoke" and the time

### Requirement: Audit records are tamper-evident
Audit entries SHALL be append-only. Any modification or deletion of a stored entry SHALL be detectable by an integrity verification.

#### Scenario: Altered entry
- **WHEN** a stored audit entry is altered outside the application
- **THEN** integrity verification reports the chain broken at that entry

### Requirement: Audit log is exportable
Owners and admins SHALL be able to export their organization's audit log for a date range, in a machine-readable format.

#### Scenario: Export range
- **WHEN** an admin exports the audit log for one month
- **THEN** the export contains exactly that organization's entries for that month
