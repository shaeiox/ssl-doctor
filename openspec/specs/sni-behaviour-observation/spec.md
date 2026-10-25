# sni-behaviour-observation Specification

## Purpose

Records how a server answers with and without SNI, and constrains what may be concluded from that difference. A different certificate for clients that send no SNI is normal for CDNs, shared hosting, reverse proxies and any TLS terminator with a default virtual host, so the observation must not become a configuration defect on its own.

## Requirements

### Requirement: The SNI comparison reports an observation, not a defect
The `tls.sni` finding SHALL report which of a fixed set of observations applies: the same certificate is served with and without SNI; a different certificate is served without SNI; the probe without SNI could not be completed; or the handshake with SNI failed. It MUST NOT assert that virtual-host configuration is wrong, and its recommendation MUST NOT instruct the engineer to change virtual-host configuration on the strength of a fingerprint difference.

#### Scenario: Different default certificate, correct certificate with SNI
- **WHEN** the certificate served with the requested SNI covers the requested hostname and validation succeeds, and the certificate served without SNI differs
- **THEN** the finding records the difference as an observation with PASS status
- **AND** the wording states that a default certificate for clients without SNI is legitimate
- **AND** no recommendation to change virtual-host configuration is attached

#### Scenario: Same certificate with and without SNI
- **WHEN** both probes obtain the same certificate
- **THEN** the finding is PASS and records that the certificate does not depend on SNI

### Requirement: An SNI difference alone never raises a cause
The diagnosis MUST NOT raise a server configuration cause from an SNI difference alone. The observation MAY be used as corroboration only when an independent finding already establishes a fault (hostname mismatch, unexpected certificate, or a virtual-host finding from the server side).

#### Scenario: Observation with no other evidence
- **WHEN** the only relevant finding is that certificates differ with and without SNI
- **THEN** no cause is raised
- **AND** the observation remains available in the finding evidence

#### Scenario: Observation with independent hostname mismatch
- **WHEN** the certificate served with the requested SNI does not cover that hostname, and certificates also differ without SNI
- **THEN** the hostname cause is raised as before
- **AND** the SNI observation appears in that cause's evidence as supporting context

#### Scenario: Independent server-side vhost fault
- **WHEN** the server-side nginx checks report that the domain is served by a fallback block, and an SNI difference was observed
- **THEN** the server-side cause is raised from the vhost finding
- **AND** the SNI observation appears as supporting evidence, not as the basis of the cause

### Requirement: An unobtainable no-SNI probe is inconclusive
When the probe without SNI cannot be completed, the finding SHALL report that SNI dependence could not be determined and SHALL NOT warn about old clients or configuration. The reason for the failed probe SHALL be preserved in the evidence.

#### Scenario: Server resets connections without SNI
- **WHEN** the handshake without SNI fails or is reset
- **THEN** the finding status is NOT TESTED with the reason in its evidence
- **AND** it does not state that clients without SNI will fail as a defect

#### Scenario: Server requires SNI and then serves the requested name
- **WHEN** the no-SNI probe is refused and the with-SNI probe serves a certificate covering the requested hostname
- **THEN** the report states that the server requires SNI as an observation
- **AND** no cause is raised from it

### Requirement: A failing handshake with the requested SNI is a real finding
When the probe with the requested SNI cannot complete, the finding SHALL report a failure, because the endpoint does not serve the requested name.

#### Scenario: With-SNI handshake fails
- **WHEN** the handshake using the requested server name fails
- **THEN** the finding status is FAIL with the failure reason in its evidence

### Requirement: The observation is preserved for correlation
The finding SHALL carry the compared certificate fingerprints and the observation category in its evidence, and SHALL be free of a failure classification when both probes completed, so correlation can distinguish an observation from a failure.

#### Scenario: Both probes complete with different certificates
- **WHEN** both probes complete and present different certificates
- **THEN** both fingerprints appear in the evidence
- **AND** the finding carries no failure classification
