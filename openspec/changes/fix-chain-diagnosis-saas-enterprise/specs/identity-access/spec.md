# Spec Delta

## Purpose

Controls who can sign in to an organization's workspace, and what each person may do there, using the organization's own identity provider.

## ADDED Requirements

### Requirement: Organizations can enforce SSO
An organization SHALL be able to configure OIDC or SAML single sign-on. When SSO is enforced, password sign-in for its members SHALL be refused.

#### Scenario: Enforced SSO
- **WHEN** SSO is enforced and a member attempts password sign-in
- **THEN** sign-in is refused and the member is directed to the identity provider

### Requirement: Permissions follow roles
The system SHALL assign each member one role: owner, admin, engineer or viewer. It SHALL enforce:
- only owners and admins manage members, SSO and agents;
- engineers, admins and owners manage targets and start scans;
- every role views results.

#### Scenario: Viewer starts scan
- **WHEN** a viewer attempts to start a scan
- **THEN** the request is refused as forbidden

#### Scenario: Engineer revokes agent
- **WHEN** an engineer attempts to revoke an agent
- **THEN** the request is refused as forbidden

### Requirement: Deprovisioned users lose access
When the identity provider deprovisions a member, or an admin removes one, that member's sessions and API tokens SHALL stop working.

#### Scenario: Removed member's API token
- **WHEN** a removed member's API token is used
- **THEN** the request is refused as unauthenticated
