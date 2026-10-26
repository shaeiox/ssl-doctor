# Spec Delta

## Purpose

Checks about the machine running SSL Doctor — Windows chain-engine validation and clock skew against the server — reported so that a measurement or tool-output artefact is never presented as a client fault.

## ADDED Requirements

### Requirement: Windows chain-engine validation is decided by certutil's own result (audit A)
`local.certutil` SHALL be PASS when `certutil -verify` exits 0 and its final status line reports success, and FAIL only when it exits non-zero or reports `-verify command FAILED`. The FAIL evidence SHALL name the error code. Words such as "error" elsewhere in the output, in certificate names, chain-dump fields or URL lines, SHALL NOT decide the status.

#### Scenario: Successful verification with a chain dump
- **WHEN** certutil exits 0, prints chain-dump lines containing `dwErrorStatus=0`, and ends with "-verify command completed successfully."
- **THEN** `local.certutil` is PASS

#### Scenario: Error text inside a certificate name
- **WHEN** certutil exits 0 and the subject is `CN=error-reporting.example.com`
- **THEN** `local.certutil` is PASS

#### Scenario: Chain cannot be built
- **WHEN** certutil exits non-zero with "-verify command FAILED: 0x800b010a (CERT_E_CHAINING)"
- **THEN** `local.certutil` is FAIL, and its evidence contains `0x800b010a`

#### Scenario: Localised output
- **WHEN** certutil exits 0 and prints its messages in another language
- **THEN** `local.certutil` is PASS

### Requirement: Revocation-URL retrieval failures are not chain failures (audit A)
When certutil reports a failed AIA, CDP or OCSP URL retrieval but the verification itself succeeds, `local.certutil` SHALL stay PASS. The failed URLs SHALL be recorded as a revocation-reachability WARNING evidence line, not as a chain failure.

#### Scenario: One CDP URL unreachable
- **WHEN** certutil exits 0, ends with "completed successfully", and reports "Error retrieving URL … ERROR_WINHTTP_NAME_NOT_RESOLVED" for one CDP URL
- **THEN** `local.certutil` is not FAIL, and its evidence names the unreachable URL

### Requirement: certutil that cannot run is not tested (audit A)
A timeout, a missing `certutil`, a non-Windows platform, or an operating-system error when starting certutil SHALL make `local.certutil` NOT TESTED with the reason, never FAIL.

#### Scenario: Access denied when starting certutil
- **WHEN** starting certutil raises an operating-system permission error
- **THEN** `local.certutil` is NOT TESTED naming that error

### Requirement: Clock skew is measured against a fresh server timestamp (audit D)
The server time SHALL be recorded with the local time its response was received and the host that sent it. Skew SHALL be computed against that receive time, never against the time the local check runs. A reference older than 120 seconds when the local check runs SHALL make `local.clockskew` NOT TESTED "server time reference is <n>s old; repeat the network check".

#### Scenario: Local check run long after the network check
- **WHEN** `/tls` ran 6 minutes before `/local`, and the clocks agree
- **THEN** `local.clockskew` is NOT TESTED naming the age of the reference, not FAIL

#### Scenario: Local checks right after the network checks
- **WHEN** `/scan` runs the local checks seconds after the HTTPS response, and the clocks agree within 2 seconds
- **THEN** `local.clockskew` is PASS

### Requirement: Cached responses are corrected by their Age (audit D)
When the response carrying `Date` also carries a valid `Age` header, the server time SHALL be taken as `Date + Age`, and the evidence SHALL say so. A malformed `Age` SHALL make the measurement NOT TESTED.

#### Scenario: Response served from a cache
- **WHEN** `Date` is 600 seconds before the receive time, `Age: 600` is present, and the clocks agree
- **THEN** `local.clockskew` is PASS, and its evidence names the Age correction

### Requirement: Clock-skew evidence names its source and uncertainty (audit D)
The `local.clockskew` evidence SHALL name the host whose `Date` was used and the measurement uncertainty (one second of `Date` resolution plus the request round-trip time). When that host differs from the target after a redirect, the evidence SHALL say so. The 60/300-second WARNING/FAIL thresholds SHALL apply to the skew minus its uncertainty.

#### Scenario: Date taken from a redirect target
- **WHEN** the target redirects to `login.example.net`, whose response provides the `Date`
- **THEN** the evidence names `login.example.net` as the time source

#### Scenario: Boundary within uncertainty
- **WHEN** the measured skew is 301 seconds and the uncertainty is 3 seconds
- **THEN** `local.clockskew` is WARNING, not FAIL

### Requirement: The clock cause needs date-related validation errors (audit D)
The diagnosis SHALL raise the "client clock is significantly off" cause only when `local.clockskew` is FAIL and the validation failure is date-related (certificate not yet valid or expired). Any other validation failure SHALL keep its own cause.

#### Scenario: Missing issuer with a skewed clock
- **WHEN** `tls.verify` fails with "unable to get local issuer certificate" and `local.clockskew` is FAIL
- **THEN** no cause says that validation fails with date errors
