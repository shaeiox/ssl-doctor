# Spec Delta

## Purpose

Defines how the interactive SSL Doctor CLI surfaces diagnostic findings to the
terminal: progressively, as each check completes, instead of buffering a whole
phase and dumping it at the end. Keeps non-interactive and batch output stable.

## ADDED Requirements

### Requirement: Interactive CLI streams findings as checks complete
The interactive CLI SHALL print each finding to the terminal as soon as its
check completes, rather than buffering all findings for a phase and printing
them only when the phase finishes. Each finding SHALL use the same formatting
as the existing buffered output.

#### Scenario: Finding printed on completion
- **WHEN** a check in an interactive session finishes producing a finding
- **THEN** that finding is printed before the next check starts

#### Scenario: Order preserved
- **WHEN** a single check produces multiple findings
- **THEN** they are printed in the order produced

### Requirement: Spinner indicates indeterminate work
The CLI SHALL show a spinner while a check is running and no finding has yet
been emitted. Once the first finding is emitted, the spinner SHALL be cleared
and findings printed incrementally.

#### Scenario: Spinner shown before first finding
- **WHEN** a check runs and produces no finding for longer than one spinner frame
- **THEN** a spinner is visible on the terminal

#### Scenario: Spinner cleared on first finding
- **WHEN** the first finding is emitted during a check
- **THEN** the spinner is removed and the finding line appears

### Requirement: Non-interactive mode keeps buffered output
WHEN stdout is not a terminal, or the CLI is invoked in batch mode, the CLI
SHALL buffer findings and print them once the phase completes, preserving
existing output and exit-code behavior.

#### Scenario: Piped output buffered
- **WHEN** the CLI's stdout is piped to another process
- **THEN** no findings are printed until the phase completes

#### Scenario: Batch exit code unchanged
- **WHEN** running in batch mode with a FAIL diagnosis
- **THEN** the process exits with status 1 as before

### Requirement: Check modules support optional emit hooks
The check modules SHALL accept an optional emit callback. When provided,
findings SHALL be delivered to the callback as they are produced, in addition
to being returned. When not provided, behavior SHALL be unchanged.

#### Scenario: Hook invoked per finding
- **WHEN** an emit callback is supplied to a check module
- **THEN** it is called once per finding in production order

#### Scenario: No hook leaves behavior unchanged
- **WHEN** no emit callback is supplied
- **THEN** the module returns findings as before and produces no output

### Requirement: Interrupted scans retain partial output
WHEN a scan is interrupted after at least one finding has been emitted, the
findings already emitted SHALL remain visible on the terminal and the session
SHALL remain usable.

#### Scenario: Partial output retained
- **WHEN** the user interrupts a scan mid-phase
- **THEN** previously printed findings remain and the REPL prompt returns
