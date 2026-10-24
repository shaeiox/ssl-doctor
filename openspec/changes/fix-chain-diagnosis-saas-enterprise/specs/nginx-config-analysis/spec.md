# Spec Delta

## Purpose

Determines, from nginx configuration read without modification, which server block answers a given domain and port, and whether the certificate configured for it is complete and correct.

## ADDED Requirements

### Requirement: Server block selection follows nginx rules
The system SHALL select the server block for a domain and port as nginx does:
- consider only blocks listening on the target port;
- exact name, then leading wildcard, then trailing wildcard, then regex;
- the first matching block wins;
- otherwise the `default_server` for that port, otherwise the first block on that port.

#### Scenario: Duplicate exact names
- **WHEN** two TLS server blocks on port 443 both list `server_name shop.example`
- **THEN** the first block in configuration order is selected and a WARNING notes the conflict

#### Scenario: Default server on another port
- **WHEN** the only `default_server` listens on 8443 and the target port is 443
- **THEN** it is not selected for a 443 target

### Requirement: Inherited certificate directives are resolved
The system SHALL resolve `ssl_certificate` and `ssl_certificate_key` inherited from the enclosing `http` context when the selected server block does not set them.

#### Scenario: Certificate set at http level
- **WHEN** the selected block has no `ssl_certificate`, but the `http` context does
- **THEN** the inherited certificate path is used and reported as inherited

### Requirement: Configured chain file linkage is verified
The system SHALL verify that the configured certificate file starts with the leaf and that each following certificate issued the one before it. It SHALL report a WARNING for a leaf-only file or a broken link.

#### Scenario: Wrong intermediate in file
- **WHEN** the file holds the leaf plus an intermediate that did not issue the leaf
- **THEN** the chain-file finding is WARNING and names the broken link

#### Scenario: Correct full chain file
- **WHEN** the file holds the leaf followed by its issuing intermediate(s)
- **THEN** the chain-file finding is PASS
