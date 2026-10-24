# Spec Delta

## Purpose

Examines how a Windows client machine will judge a server's certificate: its trusted root store and the Windows chain engine that Schannel-based applications use.

## ADDED Requirements

### Requirement: Root store is readable on Windows
The system SHALL read the Windows ROOT store entries on every supported Windows and Python combination. It SHALL report the root-store check as PASS or FAIL, never NOT TESTED due to an internal error, when the store is accessible.

#### Scenario: Standard Windows host
- **WHEN** the check runs on Windows with an accessible ROOT store
- **THEN** the root-store finding status is PASS or FAIL with the anchor names in evidence

### Requirement: Trust anchor is determined by path building
The system SHALL determine the expected trust anchor by following issuer links from the presented chain, identifying the anchor that issued the topmost presented certificate. It MUST NOT treat an intermediate CA as the expected root.

#### Scenario: Leaf plus intermediate presented
- **WHEN** the server presents a leaf and an intermediate issued by root R
- **THEN** the root-store check looks for R

#### Scenario: Only leaf presented
- **WHEN** the server presents only a leaf issued by intermediate I
- **THEN** the root-store check is NOT TESTED with evidence "presented chain incomplete; anchor cannot be determined"
- **AND** no FAIL is reported for I being absent from ROOT

### Requirement: Windows chain engine runs in the guided scan
The system SHALL run the Windows chain-engine validation against the presented leaf during the guided scan on Windows, without the user supplying a certificate file.

#### Scenario: Guided scan on Windows
- **WHEN** the guided scan runs on Windows after a successful handshake
- **THEN** a chain-engine finding for the presented leaf is recorded
