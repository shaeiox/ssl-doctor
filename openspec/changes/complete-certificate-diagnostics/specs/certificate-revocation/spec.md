# Spec Delta

## Purpose

Reports whether the certificates SSL Doctor judges are revoked, with an explicit statement of how the status was obtained, and never as a silent pass when revocation was not checked.

## ADDED Requirements

### Requirement: Revocation status is one of five explicit states (audit #30)
For the leaf (and, when online checking is enabled, each intermediate), SSL Doctor SHALL report a revocation state:
- `good`: a valid OCSP response says not revoked.
- `revoked`: with the reason and time when present.
- `unavailable`: no OCSP URL, CRL or stapled response exists.
- `not-checked`: disabled by the operator.
- `inconclusive`: a response was unreachable, timed out, was unsigned or stale, or did not match.

#### Scenario: Revoked leaf
- **WHEN** a valid OCSP response for the leaf says revoked
- **THEN** `tls.revocation` is FAIL "revoked" with the revocation time, and the diagnosis raises a confirmed certificate cause

#### Scenario: Responder unreachable
- **WHEN** the OCSP responder does not answer within the deadline
- **THEN** `tls.revocation` is NOT TESTED with failure classification `probe-inconclusive`, never FAIL

#### Scenario: No revocation information
- **WHEN** the certificate has no AIA OCSP URL, no CRL distribution point, and nothing is stapled
- **THEN** the state is `unavailable`, and the finding is NOT TESTED

### Requirement: The default revocation source is the stapled response
By default, SSL Doctor SHALL request OCSP stapling in the handshake and judge the stapled response, which needs no extra network destination. A live OCSP or CRL query to the CA SHALL run only when the operator enables online revocation checking. The evidence SHALL state the source used (`stapled`, `ocsp`, `crl`).

#### Scenario: Default offline-friendly scan
- **WHEN** a scan runs with default settings and the server staples a good response
- **THEN** the state is `good` with source `stapled`, and no request is sent to the CA

#### Scenario: Online checking disabled and nothing stapled
- **WHEN** the server staples nothing and online checking is off
- **THEN** the state is `not-checked`, with a note naming the option that enables online checking

### Requirement: A response is used only when it is valid for the certificate
An OCSP response SHALL be used only when its signature verifies against the issuer or a delegated responder, it names the certificate's issuer and serial, and its thisUpdate/nextUpdate window includes the current time. Otherwise the state SHALL be `inconclusive`, naming the defect.

#### Scenario: Stale stapled response
- **WHEN** the stapled response's nextUpdate is in the past
- **THEN** the state is `inconclusive` "stapled response expired", and a server-side WARNING recommends checking OCSP stapling

### Requirement: Revocation never upgrades or masks other results
A `good` state SHALL NOT turn other chain findings into PASS, and a missing revocation result SHALL NOT lower the overall verdict.

#### Scenario: Good OCSP on an incomplete chain
- **WHEN** revocation is `good` but the presented chain is incomplete
- **THEN** the chain finding stays WARNING
