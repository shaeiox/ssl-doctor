# Spec Delta

## Purpose

Lets enterprises run the complete SSL Doctor platform on their own infrastructure, including networks with no internet access, with the same behavior as the hosted service.

## ADDED Requirements

### Requirement: Platform installs as native executables
The CLI, the scan agent and the platform server SHALL each be delivered as native executables for Windows (.exe) and Linux. They MUST run without a container runtime, without a Python installation, and without a separately installed database.

#### Scenario: Host without Python or containers
- **WHEN** the server executable is run on a host with no Python interpreter and no container runtime
- **THEN** it initializes its embedded database, starts, and answers its health check

#### Scenario: CLI executable
- **WHEN** `ssl-doctor` is run from the bundle on a host without Python
- **THEN** it prints its version and performs a TLS scan

### Requirement: Executables run as system services
On Windows, the agent and server executables SHALL install and run as Windows services. On Linux they SHALL run under systemd.

#### Scenario: Windows service
- **WHEN** an administrator installs the agent executable as a service on Windows
- **THEN** the service starts at boot and processes jobs without an interactive session

### Requirement: Platform runs without outbound internet
A self-hosted installation SHALL install, start, scan, and alert without any outbound connection outside the customer network. This includes no telemetry, license checks, or package downloads.

#### Scenario: Air-gapped install
- **WHEN** the platform is installed from the offline bundle on a host with no internet route
- **THEN** installation completes and a scan of an internal target succeeds

### Requirement: Releases are verifiable
Every release artefact (executables and the offline bundle) SHALL be published with a signature and a software bill of materials that the customer can verify offline, using only tools already present on the customer's host.

#### Scenario: Tampered bundle
- **WHEN** an offline bundle is modified after signing
- **THEN** signature verification fails

### Requirement: Upgrades preserve data
Upgrading a self-hosted installation to a newer supported version SHALL preserve all organizations, targets, results history and audit records.

#### Scenario: Version upgrade
- **WHEN** an installation is upgraded by one minor version
- **THEN** all prior scan results and audit entries remain readable, and audit integrity verification passes
