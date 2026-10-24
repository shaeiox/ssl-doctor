# Spec Delta

## Purpose

Watches registered targets over time so that expiring certificates, chain regressions and unexpected certificate changes are caught before customers' clients fail.

## ADDED Requirements

### Requirement: Targets are re-scanned on a schedule
The system SHALL re-scan each monitored target at its configured interval, with the interval not shorter than the plan's minimum.

#### Scenario: Daily schedule
- **WHEN** a target is monitored with a 24-hour interval
- **THEN** a new scan result is recorded about every 24 hours

### Requirement: Expiry is alerted in advance
The system SHALL alert when the presented leaf expires within the configured threshold (default 30 days). It SHALL alert again when the certificate expires.

#### Scenario: Within threshold
- **WHEN** a scheduled scan finds the leaf expires in 20 days and the threshold is 30
- **THEN** an expiry alert is sent to the target's notification channels

### Requirement: Chain and certificate drift is alerted
The system SHALL alert when, between consecutive scans:
- the presented leaf fingerprint changes;
- the chain changes from complete to incomplete;
- different endpoints of the target present different certificates.

#### Scenario: Chain regression after renewal
- **WHEN** the previous scan had a complete chain and the current scan's chain is incomplete
- **THEN** a chain-regression alert is sent, citing both scans

### Requirement: Alerts are deduplicated
The system SHALL send at most one alert per target and condition until that condition clears.

#### Scenario: Persisting condition
- **WHEN** three consecutive scans show the same incomplete chain
- **THEN** exactly one chain alert has been sent
