# Spec Delta

## Purpose

Captures the certificate chain a TLS server actually presents and judges whether it is complete and correctly linked, independent of the trust store of the machine running the check.

## ADDED Requirements

### Requirement: Presented chain is captured on all supported runtimes
The system SHALL record every certificate the server sends in the handshake, in the order sent, on every supported Python version (3.10 and later).

#### Scenario: Full chain served
- **WHEN** the server sends the leaf followed by one intermediate
- **THEN** the recorded presented chain contains exactly two certificates, leaf first

#### Scenario: Leaf-only served
- **WHEN** the server sends only the leaf certificate
- **THEN** the recorded presented chain contains exactly one certificate

### Requirement: Unreadable chain is reported as not tested
The system SHALL report the chain check as NOT TESTED, stating the reason, when the presented chain cannot be read. It MUST NOT substitute the leaf alone as the presented chain.

#### Scenario: Chain unavailable
- **WHEN** no method of reading the presented chain succeeds
- **THEN** the chain finding status is NOT TESTED and its evidence names the reason
- **AND** no "server sends only the leaf" finding is produced

### Requirement: Incomplete chain is detected independent of local trust
The system SHALL report a WARNING when the presented chain ends in a certificate that is neither self-signed nor issued by a root. This verdict MUST NOT depend on the trust store or cached intermediates of the machine running the check.

#### Scenario: Leaf-only with intermediate cached locally
- **WHEN** the server sends only the leaf, and the checking machine has the intermediate in its trust or cache store
- **THEN** the chain finding is WARNING with evidence "intermediate certificate(s) not sent"

#### Scenario: Complete chain
- **WHEN** the server sends the leaf and all intermediates up to (but excluding) the root
- **THEN** the chain finding is PASS

### Requirement: Chain linkage is verified
The system SHALL verify that each presented certificate is issued by the next one. Linkage MUST be judged by issuer/subject name and by key identifiers when present. The system SHALL report a WARNING naming the first broken link.

#### Scenario: Wrong intermediate
- **WHEN** the second presented certificate did not issue the leaf
- **THEN** the chain finding is WARNING and names position 1 as the broken link

### Requirement: Validation without cached intermediates
The system SHALL perform one validation using only trusted root anchors, with no intermediate cache. The result SHALL be reported separately from the validation that uses the full system store.

#### Scenario: Cache masks missing intermediate
- **WHEN** the server sends only the leaf, and validation passes with the full system store
- **THEN** the root-only validation fails and both results are shown

### Requirement: Hostname coverage follows modern client rules
The system SHALL judge hostname coverage only from subjectAltName entries. When a certificate has no SAN DNS entries, the hostname finding SHALL be FAIL even when the common name equals the hostname.

#### Scenario: CN-only certificate
- **WHEN** the certificate has CN=shop.example and no subjectAltName
- **THEN** the hostname finding for shop.example is FAIL, with evidence that modern clients ignore the CN

#### Scenario: SAN covers host
- **WHEN** the certificate SAN includes DNS:shop.example
- **THEN** the hostname finding for shop.example is PASS
