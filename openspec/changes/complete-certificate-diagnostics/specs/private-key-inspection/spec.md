# Spec Delta

## Purpose

Determines, without ever exposing key material, whether a private key can be read and whether it cryptographically belongs to the intended certificate. An inconclusive key result is never reported as a mismatch.

## ADDED Requirements

### Requirement: The key state is classified before pairing (audit #1)
Before any pairing, SSL Doctor SHALL classify the key as `readable`, `encrypted`, `unreadable` (no permission), `missing`, or `unsupported` (not a key, or an unsupported algorithm). It SHALL do so from the key's structure: legacy PEM encryption headers, `ENCRYPTED PRIVATE KEY` PEM, DER-encoded PKCS#8 `EncryptedPrivateKeyInfo`, and an encrypted PKCS#12. This applies locally and on the server.

#### Scenario: PEM-encrypted key
- **WHEN** the key is a PEM key with `Proc-Type: 4,ENCRYPTED` or an `ENCRYPTED PRIVATE KEY` block
- **THEN** the key state is `encrypted`

#### Scenario: DER-encoded encrypted PKCS#8 key
- **WHEN** the key file is DER-encoded `EncryptedPrivateKeyInfo`
- **THEN** the key state is `encrypted`, and `cert.keymatch` is NOT TESTED, not FAIL

#### Scenario: Encrypted key on the server
- **WHEN** the configured `ssl_certificate_key` on the server is encrypted
- **THEN** `srv.keymatch` is NOT TESTED with the reason "the private key is passphrase-encrypted"

### Requirement: Pairing compares public keys cryptographically (audit #5)
The pairing SHALL compare the SHA-256 of the DER SubjectPublicKeyInfo derived from the key with the one in the certificate. It SHALL be PASS only when both digests were derived successfully and are equal, and FAIL only when both were derived and differ. Filenames and names SHALL NOT influence the verdict.

#### Scenario: Matching pair
- **WHEN** the key belongs to the certificate
- **THEN** pairing is PASS and the evidence shows the public-key digest

#### Scenario: Mismatched pair
- **WHEN** both digests are derived and differ
- **THEN** pairing is FAIL and the evidence shows both digests

### Requirement: An unextractable digest is inconclusive, never a mismatch (audit #5)
When either digest cannot be derived (the tool is missing, the command failed, the key is encrypted or unsupported, or a command timed out), the pairing SHALL be NOT TESTED with the reason. A command's success SHALL be judged by its exit status, never by whether it produced output, and a digest of empty input SHALL never be compared.

#### Scenario: openssl fails on the key over SSH
- **WHEN** the remote key-to-public-key command exits non-zero
- **THEN** `srv.keymatch` is NOT TESTED naming the failed step, and no "does NOT match" evidence appears

#### Scenario: Certificate public key cannot be extracted locally
- **WHEN** the certificate's public key cannot be extracted
- **THEN** `cert.keymatch` is NOT TESTED, not FAIL

#### Scenario: openssl unavailable
- **WHEN** no `openssl` binary is available where the comparison must run
- **THEN** the pairing is NOT TESTED "openssl not available"

### Requirement: Pairing targets the intended certificate
On the server, the key SHALL be paired with the certificate the service configuration pairs it with. In a multi-certificate configuration, each key SHALL be paired with its own certificate. The leaf (position 1 of its file) SHALL be the certificate compared, and the evidence SHALL name both paths.

#### Scenario: RSA and ECDSA pairs in one server block
- **WHEN** a server block configures an RSA certificate/key pair and an ECDSA certificate/key pair
- **THEN** two pairing results are reported, each naming its certificate and key path

### Requirement: Passphrases are never requested, stored or exposed
SSL Doctor SHALL NOT prompt for, accept on the command line, store, or log a key passphrase. Key bytes and passphrase-file contents SHALL NOT appear in findings, evidence, reports, logs, agent uploads or temporary files. Decryption with a passphrase is out of scope until a separately approved change defines a secure channel.

#### Scenario: Secret material absent from outputs
- **WHEN** a scan inspects an encrypted key and a key with a matching certificate
- **THEN** no output, JSON document, HTML report or agent upload contains any line of either key file

#### Scenario: Remote commands do not place key data in temporary files
- **WHEN** pairing runs over SSH
- **THEN** the key is read only by the remote `openssl` process, and only public-key digests are returned
