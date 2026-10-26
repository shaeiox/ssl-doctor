# Spec Delta

## ADDED Requirements

### Requirement: Validation handshakes classify transport failures (audit #22)
The validation handshakes behind `tls.verify` and `tls.verify.rootonly` SHALL use the handshake failure classification. A connect timeout, negotiation timeout or network error SHALL make the finding NOT TESTED with its `failure_kind`. Only a certificate verification error or a TLS alert received after the server's certificate SHALL make it FAIL.

#### Scenario: Silent server during validation
- **WHEN** TCP connects, but the validation handshake receives no TLS response before the deadline
- **THEN** `tls.verify` is NOT TESTED with failure kind `negotiation-timeout`, not FAIL

#### Scenario: Genuine verification error
- **WHEN** the validation handshake fails with "unable to get local issuer certificate"
- **THEN** `tls.verify` is FAIL with that reason, as today

### Requirement: Validation handshakes measure the verified address
The validation handshakes SHALL connect to the address the TCP check verified, like the primary handshake and the per-version probes, and their evidence SHALL name that address.

#### Scenario: Multi-address hostname
- **WHEN** the hostname resolves to several addresses and TCP verified the first
- **THEN** `tls.verify` and `tls.verify.rootonly` connect to that address, and their evidence names it

### Requirement: The presented chain feeds the verified chain analysis (audit #26)
The chain captured from the primary handshake, in the order sent and by the reader that captured it, SHALL be the input to chain validation, lifecycle and policy checks. The reader used SHALL stay in the evidence, and an unread chain SHALL keep producing NOT TESTED, never a synthetic one-certificate chain.

#### Scenario: Full chain captured on Python 3.12
- **WHEN** the server sends leaf and intermediate and the private-API reader captures them
- **THEN** chain validation receives both certificates, and the evidence names the reader

#### Scenario: Chain unreadable
- **WHEN** no reader returns the chain
- **THEN** `tls.chain`, `chain.validity` and `cert.policy` for the presented chain are NOT TESTED with the reader errors

### Requirement: The handshake requests a stapled OCSP response (audit #30)
The primary handshake SHALL request OCSP stapling, and SHALL record whether a response was stapled for revocation evaluation. A server that staples nothing SHALL NOT fail the handshake finding.

#### Scenario: No stapled response
- **WHEN** the server does not staple an OCSP response
- **THEN** `tls.handshake` keeps its status, and the revocation evaluation records "nothing stapled"
