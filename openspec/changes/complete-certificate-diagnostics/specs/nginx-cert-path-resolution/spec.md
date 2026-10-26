# Spec Delta

## ADDED Requirements

### Requirement: Every certificate/key pair of the selected block is resolved (audit #32, #38)
When the selected server block, or its inherited `http{}` level, has several `ssl_certificate` and `ssl_certificate_key` directives, every value SHALL be resolved with the configuration-prefix rule. Values SHALL be paired by order of appearance. `nginx.path_resolution` SHALL list each pair, and a count mismatch between certificates and keys SHALL be FAIL.

#### Scenario: RSA and ECDSA pairs
- **WHEN** the block configures `rsa.pem`/`rsa.key` and `ecdsa.pem`/`ecdsa.key`
- **THEN** `nginx.path_resolution` lists both pairs with their resolved paths and states

#### Scenario: More certificates than keys
- **WHEN** the block has two `ssl_certificate` directives and one `ssl_certificate_key`
- **THEN** `nginx.path_resolution` is FAIL "2 certificates but 1 key configured"

### Requirement: Each resolved pair is validated
`nginx.chainfile`, `srv.cert` and `srv.keymatch` SHALL be produced for each resolved pair whose certificate was opened. The evidence SHALL name the pair, and the existing single-pair findings SHALL remain unchanged in wording for single-pair configurations.

#### Scenario: Second pair unreadable
- **WHEN** the RSA pair is readable and the ECDSA certificate is missing
- **THEN** the RSA pair is validated, and the ECDSA pair's `srv.cert` is NOT TESTED "certificate file could not be opened"

### Requirement: Path-resolution failures reach the overall verdict
A FAIL `nginx.path_resolution` (a missing file in a confirmed configuration, or a certificate/key count mismatch) SHALL produce a server cause or an unexplained failure, so the overall verdict is never PASS while it is FAIL.

#### Scenario: Missing certificate in a verified configuration
- **WHEN** `nginx.path_resolution` is FAIL because the configured certificate does not exist
- **THEN** the overall verdict is FAIL, with a server cause naming the missing path
