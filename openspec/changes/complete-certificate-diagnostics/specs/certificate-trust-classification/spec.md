# Spec Delta

## Purpose

States, for every certificate SSL Doctor judges, whether it is valid for the requested domain and who trusts it: the public trust store, a private CA, nobody (self-signed), or unknown. The verdict comes only from verified evidence, never from issuer names.

## ADDED Requirements

### Requirement: Configured and presented certificates get the same domain and trust verdict (audit #7)
For the presented leaf, the configured leaf on the server, and a supplied file with a hostname, SSL Doctor SHALL report hostname coverage, validity period and chain trust as separate results. A configured certificate SHALL NOT be PASS while it is expired, not yet valid, or does not cover the target domain.

#### Scenario: Expired configured certificate
- **WHEN** the configured `ssl_certificate` leaf on the server is past its notAfter
- **THEN** `srv.cert` is FAIL "certificate expired <n> days ago", and the diagnosis raises a certificate-validity cause for the configured file

#### Scenario: Configured certificate does not cover the vhost domain
- **WHEN** the configured leaf's SAN does not include the target domain
- **THEN** `srv.cert` reports the hostname mismatch as FAIL, naming the SAN entries

### Requirement: Trust class is explicit and evidence-based (audit #25)
Each judged chain SHALL carry one trust class:
- `public`: a verified path to an anchor of the system or platform trust store.
- `private`: verifies only against a CA file the operator supplied or the service references.
- `self-signed`: the leaf's self-signature verifies and no other path exists.
- `unknown`: no verified path, or verification unavailable.

Issuer names SHALL NOT determine the class.

#### Scenario: Internal CA certificate
- **WHEN** the chain does not validate against the system store, but validates against the CA file referenced by `ssl_trusted_certificate`
- **THEN** the trust class is `private`, and the evidence names that CA file

#### Scenario: Issuer named like a public CA
- **WHEN** the issuer name resembles a public CA, but no path verifies to a system anchor
- **THEN** the trust class is `unknown`, not `public`

#### Scenario: Verification not possible
- **WHEN** signature verification is unavailable
- **THEN** the trust class is `unknown`, with uncertainty naming the missing verifier

### Requirement: Trust-anchor validity and trust-store limits are reported (audit #42)
SSL Doctor SHALL report the validity of the anchor each verdict relies on. It SHALL report when the only verified path ends at an expired anchor, and when the trust store could not be read or is empty. It SHALL describe these as trust-store conditions of the checking machine, and SHALL NOT state that every client is affected.

#### Scenario: Path ends at an expired root
- **WHEN** the only verified path ends at a root past its notAfter
- **THEN** the chain trust finding is WARNING "anchor expired", naming the root
- **AND** the limitation states that clients with other trust stores may build a different path

#### Scenario: Empty or unreadable trust store
- **WHEN** no anchors can be loaded from the system store
- **THEN** trust validation is NOT TESTED "no trust anchors available", not FAIL

#### Scenario: Store source is named
- **WHEN** any trust verdict is produced
- **THEN** its evidence names the trust-store location or platform store and its anchor count

### Requirement: Client trust-store gaps are not blamed on the server
When the presented chain is complete and verified but its anchor is absent from the checking machine's store, SSL Doctor SHALL classify the result as a client-side trust gap (`private` or `unknown`), and SHALL NOT raise a server chain cause.

#### Scenario: Full chain from an internal CA checked from a public client
- **WHEN** the server sends leaf and intermediate, and their root is not in this machine's store
- **THEN** no "server does not send the full chain" cause is raised, and the diagnosis names the missing anchor as a client trust question
