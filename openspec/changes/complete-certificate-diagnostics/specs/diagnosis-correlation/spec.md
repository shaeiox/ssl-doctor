# Spec Delta

## MODIFIED Requirements

### Requirement: Existing verdict semantics are preserved
The overall verdict SHALL be FAIL when any cause is `confirmed` or any FAIL finding is unexplained, WARNING when any other cause or unexplained WARNING exists, and PASS otherwise. An unexplained FAIL of the network path (transport `failure_kind`) or of the diagnostic session (SSH, remote command execution) counts as WARNING. Observations MUST NOT hide a genuine FAIL, nor become FAIL.

#### Scenario: Observation-only scan
- **WHEN** the only results are observations such as an SNI difference
- **THEN** the overall verdict is not FAIL

#### Scenario: Confirmed fault
- **WHEN** a cause is confirmed from direct evidence
- **THEN** the overall verdict is FAIL, as before

#### Scenario: FAIL finding with no matching rule
- **WHEN** `chain.validity` is FAIL for an expired intermediate and no cause rule applies
- **THEN** the overall verdict is FAIL, and the diagnosis lists the finding under unexplained failures

#### Scenario: Unexplained transport failure
- **WHEN** the only unexplained FAIL carries failure kind `negotiation-timeout`
- **THEN** the overall verdict is WARNING, not FAIL

#### Scenario: SSH authentication failed
- **WHEN** the only unexplained FAIL is `ssh.auth`
- **THEN** the overall verdict is WARNING, and no server cause is raised

#### Scenario: Only inconclusive results
- **WHEN** no FAIL or WARNING finding exists and some checks are NOT TESTED
- **THEN** the overall verdict is PASS, and the notes list every NOT TESTED check with its reason

## ADDED Requirements

### Requirement: The CLI exit code follows the overall verdict (audit #7, #22)
A batch or scripted run SHALL exit with status 1 when the overall verdict is FAIL, and with 0 otherwise, including WARNING and verdicts with NOT TESTED checks. Usage errors keep their existing non-zero codes. The exit code SHALL be derived from the same diagnosis that is printed and exported.

#### Scenario: Expired intermediate in batch mode
- **WHEN** `ssl-doctor -c "/scan host --client-only"` finds an expired intermediate
- **THEN** the process exits with status 1

#### Scenario: Warnings only
- **WHEN** the only causes are possible protocol-hardening causes
- **THEN** the process exits with status 0

### Requirement: Inconclusive validation never becomes a certificate cause (audit #22)
A `tls.verify` or `tls.verify.rootonly` result that is NOT TESTED because of a timeout, network error or unavailable trust store SHALL NOT raise a certificate, chain or client trust cause. The diagnosis SHALL note what could not be verified.

#### Scenario: Validation handshake stalled
- **WHEN** the primary handshake passed, and the validation handshake timed out
- **THEN** no cause of origin `certificate` is raised from `tls.verify`, and the notes state that validation was inconclusive

### Requirement: Pairing failures need conclusive key evidence (audit #1, #5)
A key/certificate mismatch cause SHALL be raised only from a FAIL pairing finding, which requires two derived and differing public-key digests. A NOT TESTED pairing (encrypted, unreadable or unsupported key, or a failed command) SHALL appear in the notes. When the key is encrypted, the startup-compatibility result SHALL be referenced.

#### Scenario: Encrypted key on the server
- **WHEN** `srv.keymatch` is NOT TESTED with failure kind `key-encrypted`
- **THEN** no "configured private key does not match" cause is raised, and the notes name the encrypted key and the `srv.keystartup` result

### Requirement: Every validation error has a specific cause (audit #13, #18, #22, #41)
Each failing validation reason SHALL map to a cause naming the certificate involved: expiry of any chain certificate, not yet valid, unsuitable purpose (EKU), a failed signature, a non-CA issuer, an untrusted or expired anchor, a revoked certificate, and a hostname mismatch. A reason no rule maps SHALL be reported as an unexplained failure, never dropped.

#### Scenario: Expired intermediate
- **WHEN** validation fails because an intermediate expired
- **THEN** a confirmed certificate cause names that intermediate and its notAfter

#### Scenario: Unsuitable purpose
- **WHEN** validation fails because the leaf's EKU lacks serverAuth
- **THEN** a confirmed certificate cause states the leaf is not valid for TLS server authentication

### Requirement: Server deployment findings feed the diagnosis (audit #33, #35, #36, #37, #39)
Failing results of path resolution, configuration test, reload state, encrypted-key startup, permissions and configured-vs-active comparison SHALL each map to a server cause. They SHALL be gated by the existing rule that nginx-derived causes need a confirmed running configuration. Ungated results SHALL be capped at `probable`.

#### Scenario: Certificate replaced without reload
- **WHEN** `srv.reload` is WARNING (certificate newer than workers) and `srv.compare` is FAIL
- **THEN** one server cause states that the new certificate is not yet served because the service was not reloaded

#### Scenario: Configuration test failure
- **WHEN** `srv.configtest` is FAIL
- **THEN** a confirmed server cause quotes the test's error summary and exit status
