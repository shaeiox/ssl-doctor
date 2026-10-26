# Spec Delta

## Purpose

Turns any certificate input SSL Doctor reads (a local file, a configured file read over SSH, or a trust bundle) into a complete, strictly parsed inventory of certificates, so later checks never act on a partial or misread file.

## ADDED Requirements

### Requirement: Format is detected from content (audit #8)
SSL Doctor SHALL classify each input by its content as PEM certificate(s), DER certificate, PKCS#7, PKCS#12, private key, or unrecognised, and SHALL NOT rely on the file extension except to word a hint. Unsupported formats SHALL be FAIL naming the detected format and a conversion command.

#### Scenario: DER certificate with a .pem extension
- **WHEN** a file named `site.pem` contains one DER-encoded certificate
- **THEN** the certificate is parsed and the evidence states the format "DER"

#### Scenario: PKCS#7 bundle
- **WHEN** a `.crt` file contains a PEM `PKCS7` block
- **THEN** `cert.parse` is FAIL naming "PKCS#7" and an `openssl pkcs7 -print_certs` conversion

#### Scenario: PKCS#12 detected without the extension
- **WHEN** a file without a `.pfx`/`.p12` extension holds a PKCS#12 structure
- **THEN** `cert.parse` is FAIL naming "PKCS#12", and no key material is read or printed

#### Scenario: Private key supplied as a certificate
- **WHEN** the input contains only a private-key block
- **THEN** `cert.parse` is FAIL "this is a private key, not a certificate", with no key content in the evidence

### Requirement: Malformed and truncated input is a failure (audit #9)
Every `BEGIN CERTIFICATE` marker SHALL have a matching `END` marker, and every block SHALL decode as an X.509 certificate. An unterminated block, invalid Base64, malformed ASN.1, or an undecodable block SHALL make `cert.parse` (and `nginx.chainfile` for a configured file) FAIL naming the block position, even if other blocks parsed.

#### Scenario: Truncated trailing block
- **WHEN** a file holds one complete certificate followed by an unterminated `BEGIN CERTIFICATE` block
- **THEN** `cert.parse` is FAIL with "block 2 is not terminated", and it is not PASS with a count of 1

#### Scenario: Corrupt middle block
- **WHEN** the second of three blocks has invalid Base64
- **THEN** `cert.parse` is FAIL naming block 2, and no PASS `cert.parse` finding is produced for the file

#### Scenario: Configured file truncated on the server
- **WHEN** the nginx `ssl_certificate` file read over SSH ends in an unterminated block
- **THEN** `nginx.chainfile` is FAIL naming the truncated block, and it is not an incomplete-chain warning

#### Scenario: Empty file
- **WHEN** the input is empty or whitespace only
- **THEN** `cert.parse` is FAIL "file is empty"

### Requirement: Every certificate in a file is inventoried (audit #10)
For an input holding several certificates, SSL Doctor SHALL report the count and, per certificate in file order, its position, subject, issuer, SHA-256 fingerprint prefix, validity window, CA flag and inferred role.

#### Scenario: Leaf plus two intermediates
- **WHEN** a file holds a leaf and two intermediates
- **THEN** the evidence lists three entries in file order, each with its role

### Requirement: Certificate roles are classified from certificate content (audit #11)
Each certificate SHALL be classified as `leaf` (not a CA), `intermediate` (a CA that is not self-signed), `root` (a CA whose self-signature verifies), or `unrelated` (not on any path from the first certificate). The classification SHALL come from Basic Constraints and signatures, not from position, filename or names.

#### Scenario: Intermediate placed first
- **WHEN** the first certificate in a server certificate file is a CA certificate
- **THEN** the chain-file finding is FAIL "the first certificate is a CA certificate, not the server certificate"
- **AND** the leaf found later in the file is named

#### Scenario: Unrelated certificate in the bundle
- **WHEN** a bundle holds a certificate that neither issued nor was issued by any other entry
- **THEN** it is classified `unrelated`, and the finding is WARNING naming its position

### Requirement: Duplicates are reported as duplicates (audit #12)
Certificates with identical DER encoding SHALL be reported as duplicates with their positions. They SHALL be excluded from linkage evaluation, so a repetition alone is never reported as a broken or misordered chain.

#### Scenario: Leaf repeated at the end
- **WHEN** a file holds leaf, intermediate, leaf
- **THEN** a WARNING reports "position 3 duplicates position 1"
- **AND** the chain is evaluated as leaf → intermediate and is not reported as broken

### Requirement: Root and CA bundle files are parsed and classified (audit #3)
When a CA or root file is supplied or referenced by the service configuration (for example nginx `ssl_trusted_certificate`, Apache `SSLCACertificateFile`), SSL Doctor SHALL parse it under the same strict rules and report each certificate's role. An entry SHALL be reported as a root only when it is a CA and its self-signature verifies.

#### Scenario: Root file that contains an intermediate
- **WHEN** a file referenced as a root bundle holds one root and one intermediate
- **THEN** the evidence counts 2 certificates, classifies one as root and one as intermediate, and the finding is WARNING "file contains non-root certificates"

#### Scenario: Service CA file with intermediates
- **WHEN** nginx `ssl_trusted_certificate` names a file holding a root and the intermediate below it
- **THEN** both are listed with their roles, and the finding is PASS, because nginx uses intermediates in this file to verify OCSP responses and client certificates

#### Scenario: Name-only "root"
- **WHEN** a bundle entry has subject equal to issuer but its self-signature does not verify
- **THEN** it is not classified as a root, and the finding names it as not self-signed

### Requirement: Certificate content is public, key content is never shown
Certificate parsing SHALL never read, print, log or export private-key material that appears in the same input. Mixed certificate-and-key files SHALL be parsed for certificates only, and the evidence SHALL state that a key block was present and ignored.

#### Scenario: Certificate and key in one file
- **WHEN** a PEM file contains a certificate followed by a private-key block
- **THEN** the certificate is inventoried, the evidence says "a private-key block is present and was not read", and no key bytes appear in any output
