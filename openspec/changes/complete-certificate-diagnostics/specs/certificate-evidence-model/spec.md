# Spec Delta

## Purpose

Defines the machine-readable form in which certificate, chain, key, revocation and service evidence is published in findings documents, so reports, agents and the service consume structured facts instead of parsing evidence text, while existing consumers keep working.

## ADDED Requirements

### Requirement: Findings documents move to schema 1.7 additively
The contract version SHALL become `1.7`, published as `schemas/findings-1.7.schema.json`. Every field of 1.6 SHALL keep its name, type and meaning. Documents of versions 1.0–1.6 SHALL still load and validate against their own schema.

#### Scenario: Old document loads
- **WHEN** a stored 1.6 document is loaded by the 1.7 tool or service
- **THEN** it validates against `findings-1.6.schema.json` and is displayed without error

#### Scenario: New document validates
- **WHEN** a scan with server checks is exported with `/report json`
- **THEN** the document declares version 1.7 and validates against `findings-1.7.schema.json`

### Requirement: New check ids are registered
The registry SHALL add, each with a description: `chain.validity`, `chain.usage`, `chain.trust`, `cert.policy`, `cert.cafile`, `tls.revocation`, `srv.service`, `srv.configtest`, `srv.reload`, `srv.renewal`, `srv.keystartup`, `srv.inventory`. `srv.perms` and `srv.compare` keep their ids.

#### Scenario: Unknown check id reported
- **WHEN** a document contains a finding whose check id is not in the registry
- **THEN** the registry check lists that id
- **AND** schema validation still accepts the document, so a 1.7 consumer keeps reading documents of a later 1.x minor version

### Requirement: Inconclusive verification has machine-readable kinds
`failure_kind` SHALL gain `verifier-unavailable` (no tool to verify signatures or keys), `key-encrypted`, `key-unreadable`, `command-failed` (a remote or local command exited non-zero) and `permission-denied`. NOT TESTED findings caused by these SHALL carry the kind.

#### Scenario: Encrypted key pairing
- **WHEN** pairing is NOT TESTED because the key is encrypted
- **THEN** the finding's `failure_kind` is `key-encrypted`

### Requirement: Structured certificate facts are published
`facts.certificates` SHALL map each judged chain (`presented`, `configured:<path>`, `supplied:<path>`) to its status, trust class, anchor, revocation state and `certificates` list. Each entry gives position, role, SHA-256, subject, issuer, notBefore, notAfter, key type and size, signature algorithm, CA flag, path length, KU, EKU, SKI, AKI and its link's verification result. No key material SHALL appear.

#### Scenario: Consumer reads the expired intermediate
- **WHEN** a scan finds an expired intermediate
- **THEN** `facts.certificates.presented.certificates[1].role` is `intermediate`, and its `not_after` is in the past, without parsing evidence text

### Requirement: Existing facts keep their meaning
`facts.leaf`, `facts.chain_status`, `facts.endpoints`, `facts.endpoint_comparison` and `facts.probe_policy` SHALL keep their 1.6 meaning. `chain_status` SHALL be `complete` only when the new chain validation reports a verified, anchored path; otherwise `incomplete`, `broken` or `unread`.

#### Scenario: Monitoring alert on a forged chain
- **WHEN** the presented chain's second link fails signature verification
- **THEN** `facts.chain_status` is `broken`, and the service's chain alert condition fires

### Requirement: Diagnosis entries for unexplained failures are published
The diagnosis block SHALL gain an `unexplained` list, each entry naming the check, status, title and evidence summary of a FAIL finding that no cause rule explained. `overall` keeps its values `PASS`, `WARNING` and `FAIL`.

#### Scenario: Unexplained failure exported
- **WHEN** a FAIL finding has no matching cause rule
- **THEN** the exported diagnosis lists it under `unexplained`, and `overall` is `FAIL`

### Requirement: Exports contain no secrets
Every exported document (JSON, HTML, agent report, agent upload) SHALL be produced through the existing redaction. It SHALL contain no private-key material, no passphrase or passphrase-file content, and no SSH password.

#### Scenario: Redaction holds with the new facts
- **WHEN** a scan of a server with an encrypted key and an `ssl_password_file` is exported
- **THEN** no line of the key file or the passphrase file appears in any export
