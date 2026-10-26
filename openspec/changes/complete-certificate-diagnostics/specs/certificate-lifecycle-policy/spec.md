# Spec Delta

## Purpose

Judges every certificate in a chain against time and against an explicit cryptographic policy: validity windows, expiry warnings with configurable thresholds, intermediates that expire before the leaf, key strength, and deprecated signature algorithms.

## ADDED Requirements

### Requirement: Every certificate's validity window is checked (audit #13)
For presented, configured and supplied chains, SSL Doctor SHALL compare each certificate's notBefore and notAfter with the current UTC time. It SHALL report expired and not-yet-valid certificates by position and role. Leaf results keep their existing ids (`tls.certvalid`, `cert.validity`, `srv.cert`); non-leaf results are reported as `chain.validity`.

#### Scenario: Not-yet-valid leaf
- **WHEN** the leaf's notBefore is in the future
- **THEN** the leaf validity finding is FAIL "not valid until <date>", and the recommendation mentions the client clock and issuance date

#### Scenario: Expired intermediate on a live endpoint
- **WHEN** the server presents a valid leaf and an expired intermediate
- **THEN** `chain.validity` is FAIL naming the intermediate, and the overall verdict is FAIL

### Requirement: Expiry warnings use a configurable threshold (audit #40)
The remaining validity SHALL be reported in days for each certificate. A certificate expiring within the warning threshold SHALL be WARNING. The threshold SHALL default to 30 days and be settable per scan (CLI option and agent job parameter) within 1–365 days, and the evidence SHALL state the threshold used.

#### Scenario: Default threshold
- **WHEN** the leaf expires in 20 days and no threshold is set
- **THEN** the leaf validity finding is WARNING and the evidence says "threshold 30 days"

#### Scenario: Custom threshold
- **WHEN** the operator sets a 14-day threshold and the leaf expires in 20 days
- **THEN** the leaf validity finding is PASS, with "20 days remaining (threshold 14 days)"

#### Scenario: Out-of-range threshold
- **WHEN** the operator passes a threshold of 0 or 400
- **THEN** the command is refused with the allowed range, and no scan runs

### Requirement: Intermediates expiring before the leaf are reported (audit #41)
When an intermediate on the validating path expires before the leaf, SSL Doctor SHALL report a WARNING naming the intermediate, its notAfter, and the date from which the chain stops validating. When it is within the warning threshold, the WARNING SHALL say so.

#### Scenario: Intermediate shortens the chain lifetime
- **WHEN** the leaf is valid for 300 more days and its intermediate for 40
- **THEN** `chain.validity` is WARNING "chain stops validating on <intermediate notAfter>"

### Requirement: Key strength is judged by an explicit policy (audit #14)
Each certificate's public key SHALL be reported with type and size or curve, and judged by a documented policy:
- RSA below 2048 bits → FAIL.
- DSA → FAIL.
- EC curves other than P-256, P-384 or P-521 → WARNING.
- Ed25519 and Ed448 → PASS.

The policy version SHALL be stated in the evidence.

#### Scenario: 1024-bit RSA leaf
- **WHEN** the leaf has a 1024-bit RSA key
- **THEN** `cert.policy` is FAIL naming the key size and the policy minimum

#### Scenario: P-256 ECDSA leaf
- **WHEN** the leaf has a P-256 key
- **THEN** the key is reported as compliant

### Requirement: Deprecated signature algorithms are judged by the same policy (audit #43)
The signature algorithm of every non-anchor certificate SHALL be judged:
- MD5 and SHA-1 based signatures → FAIL.
- RSA-PSS and SHA-2/SHA-3 family signatures → PASS.

A trust anchor's own self-signature SHALL be reported but not judged, because clients do not rely on it. Protocol and cipher policy findings remain as specified elsewhere.

#### Scenario: SHA-1 signed intermediate
- **WHEN** the intermediate is signed with sha1WithRSAEncryption
- **THEN** `cert.policy` is FAIL naming the intermediate and the algorithm

#### Scenario: SHA-1 self-signed root
- **WHEN** only the trust anchor's self-signature uses SHA-1
- **THEN** no policy failure is raised, and the evidence notes the anchor's algorithm

### Requirement: Policy results do not hide each other
Validity, expiry-warning and algorithm results SHALL be reported for every certificate, even when an earlier certificate already failed, so that one scan lists every lifecycle and policy problem in the chain.

#### Scenario: Two problems in one chain
- **WHEN** the leaf is expiring within the threshold and the intermediate is SHA-1 signed
- **THEN** both results are reported
