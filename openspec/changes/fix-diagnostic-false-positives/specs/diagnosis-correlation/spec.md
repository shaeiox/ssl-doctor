# Spec Delta

## MODIFIED Requirements

### Requirement: Existing verdict semantics are preserved
The overall verdict SHALL be FAIL when any cause is `confirmed` or any FAIL finding is unexplained, WARNING when any other cause or unexplained WARNING exists, and PASS otherwise. An unexplained FAIL of the network path (transport `failure_kind`), of the diagnostic session (SSH, remote command execution), or of a check about the client machine running SSL Doctor (`local.*`) counts as WARNING. Observations MUST NOT hide a genuine FAIL, nor become FAIL.

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

#### Scenario: Unexplained client-machine failure
- **WHEN** every endpoint and server check passes and the only unexplained FAIL is `local.clockskew`
- **THEN** the overall verdict is WARNING, the batch exit code is 0, and the diagnosis still lists `local.clockskew` under unexplained findings

## ADDED Requirements

### Requirement: Client-machine causes keep their certainty (audit H)
Cause rules about the client machine SHALL keep their certainty, and a confirmed client cause SHALL still make the overall verdict FAIL. Only unexplained client-machine FAILs are weighed as WARNING.

#### Scenario: Probable Windows chain-engine cause
- **WHEN** `tls.verify` passes, `local.certutil` genuinely fails, and the rule raises its probable client cause
- **THEN** the cause is listed with certainty probable, and the overall verdict is WARNING

### Requirement: Auxiliary checks are FAIL only on conclusive evidence (audit H)
A server-state or client-machine check whose cause rule is `confirmed` SHALL be FAIL only when the evidence shows the fault itself. A permission limit, an unreadable source, a stale measurement, or a tool-output pattern that also occurs on success SHALL make it NOT TESTED or WARNING.

#### Scenario: Permission-limited configuration test
- **WHEN** `srv.configtest` could not complete because of access errors only
- **THEN** no confirmed cause is raised, and the overall verdict does not become FAIL because of it
