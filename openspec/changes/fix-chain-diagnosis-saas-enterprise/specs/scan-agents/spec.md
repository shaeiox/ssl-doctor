# Spec Delta

## Purpose

Lets an organization run SSL Doctor checks from inside its own networks — on client machines and on the nginx host — and report results to the service, without exposing inbound ports or sharing server credentials.

## ADDED Requirements

### Requirement: Agents enroll with a one-time token
An agent SHALL enroll using a single-use, expiring enrollment token issued for one organization. After enrollment it SHALL authenticate with its own credential.

#### Scenario: Token reuse
- **WHEN** an already-used enrollment token is presented
- **THEN** enrollment is refused

#### Scenario: Successful enrollment
- **WHEN** a valid unused token is presented
- **THEN** the agent is registered to that organization and receives its own credential

### Requirement: Agents connect outbound only
An agent SHALL communicate with the service only over connections it initiates. It MUST NOT require any inbound port.

#### Scenario: Firewalled network
- **WHEN** the agent's network allows outbound HTTPS only
- **THEN** the agent receives scan jobs and uploads results successfully

### Requirement: Agents declare their role
An agent SHALL be registered with a role: "client" (network and client-machine checks) or "server" (read-only nginx checks on the host it runs on). It SHALL only accept jobs matching that role.

#### Scenario: Server job sent to client agent
- **WHEN** a server-side job is assigned to a client-role agent
- **THEN** the agent declines the job and the job is reported as not runnable

### Requirement: Server agents are read-only
A server-role agent MUST NOT modify configuration, restart services, or escalate privileges. When permissions are insufficient, it SHALL report checks as NOT TESTED with the reason.

#### Scenario: Unreadable nginx config
- **WHEN** the agent account cannot read the nginx configuration
- **THEN** the nginx findings are NOT TESTED with the missing permission named

### Requirement: Agent credentials are revocable
An organization administrator SHALL be able to revoke an agent. A revoked agent's requests SHALL be refused immediately.

#### Scenario: Revoked agent uploads
- **WHEN** a revoked agent uploads results
- **THEN** the upload is refused and nothing is stored
