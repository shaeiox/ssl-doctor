# Spec Delta

## Purpose

Decides whether a certificate chain, whether presented by a server, configured in a service, or supplied as a file, is correctly built, cryptographically sound, and anchored, using signatures and CA constraints rather than names.

## ADDED Requirements

### Requirement: Full-chain versus leaf-only is reported for every chain source (audit #2)
For a presented chain, a configured certificate file and a supplied file, SSL Doctor SHALL state whether the source holds the leaf only, or the leaf plus the intermediates needed to reach an anchor. It SHALL apply the same rules to all three sources.

#### Scenario: Leaf-only configured file
- **WHEN** the configured `ssl_certificate` file holds only a leaf issued by an intermediate
- **THEN** `nginx.chainfile` is WARNING "intermediate certificate(s) not included", as today

#### Scenario: Full chain with verified links
- **WHEN** the file holds the leaf and its issuing intermediate, and every link verifies
- **THEN** the chain-file finding is PASS, and its evidence states "signatures verified"

### Requirement: Issuer and subject relationships are checked by canonical name (audit #15)
For each candidate link, the child's issuer name SHALL be compared with the parent's subject name in canonical form (RFC 5280 name comparison, not display strings). A name mismatch SHALL be reported with the position and both names.

#### Scenario: Wrong intermediate
- **WHEN** the certificate after the leaf has a subject different from the leaf's issuer
- **THEN** the chain is `broken` at position 1, and the evidence names both names

#### Scenario: Equivalent names in different encodings
- **WHEN** the issuer and subject differ only in case or string type, which are equal under RFC 5280 comparison
- **THEN** they are treated as matching

### Requirement: Every link's signature is verified (audit #4, #16)
A link SHALL count as verified only when the child's signature verifies with the parent's public key. Matching names or key identifiers alone SHALL NOT make a link verified. A failed signature SHALL make the chain `broken`.

#### Scenario: Forged intermediate with the same name and SKI
- **WHEN** the intermediate has the expected subject and SKI but a different key than the one that signed the leaf
- **THEN** the chain is `broken` at position 1 with "signature does not verify", and the chain finding is not PASS

#### Scenario: Verifier unavailable
- **WHEN** no `openssl` binary is available to verify signatures
- **THEN** the chain verdict is at most WARNING, with uncertainty "links matched by name only; signatures not verified"
- **AND** the chain is never PASS on name evidence alone

### Requirement: CA eligibility follows Basic Constraints (audit #17)
Each issuer in a path SHALL carry Basic Constraints `CA:TRUE` and SHALL respect any `pathLenConstraint`. A leaf with `CA:TRUE` SHALL be reported. A non-CA certificate in an issuer position SHALL make the chain `broken`.

#### Scenario: Leaf used as an issuer
- **WHEN** a certificate with `CA:FALSE` (or no Basic Constraints) signed the certificate below it
- **THEN** the chain is `broken` at that position with "issuer is not a CA certificate"

#### Scenario: Path length exceeded
- **WHEN** an intermediate with `pathLenConstraint:0` is followed by another CA below it
- **THEN** the chain is `broken`, naming the constraint

### Requirement: Key Usage and Extended Key Usage fit TLS server authentication (audit #18)
The leaf SHALL have EKU `serverAuth` (or no EKU), and a Key Usage compatible with its key type when present. Each issuer with a Key Usage extension SHALL include `keyCertSign`. Any violation SHALL be FAIL naming the certificate and the extension value.

#### Scenario: Client-only certificate on a server
- **WHEN** the leaf's EKU is `clientAuth` only
- **THEN** the chain usage finding is FAIL "certificate is not valid for TLS server authentication"
- **AND** the diagnosis names that cause, not a generic validation failure

#### Scenario: CA without keyCertSign
- **WHEN** an intermediate's Key Usage lacks `keyCertSign`
- **THEN** the finding is FAIL naming that intermediate

### Requirement: AKI and SKI guide issuer selection (audit #19)
When the child has an Authority Key Identifier and candidate issuers have Subject Key Identifiers, SSL Doctor SHALL prefer the candidate whose SKI equals the AKI. It SHALL report when several candidates share the issuer name. It SHALL record the AKI/SKI per link in the evidence and SHALL still require the signature to verify.

#### Scenario: Two roots with the same name
- **WHEN** the trust store holds two roots with the same subject and different keys
- **THEN** the root whose SKI matches the top certificate's AKI is selected, and the evidence notes the ambiguity

### Requirement: Alternative and cross-signed paths are enumerated (audit #20)
SSL Doctor SHALL build every valid path from the leaf to an anchor, using the presented or configured certificates and the trust anchors in use, up to a bounded number of paths. It SHALL report each path and its anchor, and state which path the verdict uses.

#### Scenario: Cross-signed intermediate
- **WHEN** the presented intermediate is cross-signed, and paths to two different roots both verify
- **THEN** both paths are listed with their anchors, and the chain verdict is PASS if any path validates to a trusted anchor

#### Scenario: Only the legacy path validates
- **WHEN** the newer root is absent from the trust store and only the cross-signed path validates
- **THEN** the evidence states which path validated, and why the other did not

### Requirement: Self-signed is a verified property (audit #21)
A certificate SHALL be reported as self-signed only when its subject equals its issuer and its own signature verifies with its own public key. A certificate whose names match but whose signature does not SHALL be reported as "self-issued name, not self-signed".

#### Scenario: Name-only self-signed certificate
- **WHEN** a certificate has subject equal to issuer but was signed by another key
- **THEN** it is not reported as self-signed, and it is not accepted as a chain anchor

#### Scenario: Genuine self-signed leaf
- **WHEN** a server presents a single certificate whose self-signature verifies
- **THEN** it is reported as a verified self-signed certificate

### Requirement: Missing intermediates are detected and the missing issuer is named (audit #6)
When no path reaches an anchor from the certificates provided, SSL Doctor SHALL report the chain `incomplete` from what was provided, independent of any intermediate cache on the checking machine. It SHALL name the missing issuer's subject, the leaf's AIA `caIssuers` URL and, where determinable, the AKI. It SHALL NOT fetch it.

#### Scenario: Leaf-only server with a cached intermediate locally
- **WHEN** the server sends only the leaf, and this machine has the intermediate cached
- **THEN** the chain is `incomplete`, `tls.verify.rootonly` fails, and the evidence names the missing issuer and its AIA URL

#### Scenario: Linked chain whose top is not anchored
- **WHEN** the provided certificates form a verified chain whose top is an intermediate whose issuer is absent from the trust configuration
- **THEN** the chain status stays `complete` (the server sent what it must), the result is marked anchor-unknown with the top's issuer named, and no missing-intermediate cause is raised; trust is reported by the trust verdict

### Requirement: Validation names its trust anchor and trust configuration (audit #22)
A chain-validation result SHALL name the trust configuration used (system store path, Windows store, or an explicitly supplied CA file), its number of anchors, and the anchor reached. A chain SHALL be `valid` only when a verified path reaches an anchor of that configuration and every certificate on the path is within its validity period.

#### Scenario: Valid public chain
- **WHEN** the presented chain verifies to a root in the system store
- **THEN** the evidence names the store, its anchor count and the anchor subject

#### Scenario: Configured chain validated on the server's files
- **WHEN** the configured certificate file is read over SSH
- **THEN** its chain is validated with the same rules, against the trust configuration named in the evidence

#### Scenario: Expired intermediate on the path
- **WHEN** the only path includes an intermediate past its notAfter
- **THEN** chain validation is FAIL naming the expired intermediate

### Requirement: Chain findings keep their established identifiers
Chain verdicts SHALL keep the check ids `tls.chain`, `nginx.chainfile` and `cert.chainfile`. Statuses: `complete` with verified links → PASS. `incomplete`, or `broken` by name or order → WARNING (as today). `broken` by a failed signature, a non-CA issuer or a violated path length → FAIL. Name-only evidence → WARNING with uncertainty. Unread → NOT TESTED. New detail SHALL be additive.

#### Scenario: Existing consumer reads tls.chain
- **WHEN** a 1.6-era consumer reads a 1.7 document of a full-chain server
- **THEN** it finds `tls.chain` PASS and `facts.chain_status` `complete`, as before
