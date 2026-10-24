# Spec Delta

## Purpose

Defines the optional typewriter rendering mode for the SSL Doctor interactive
CLI: printing output character-by-character at a configurable speed, toggled at
runtime or via flags, and automatically disabled outside an interactive terminal.

## ADDED Requirements

### Requirement: Typewriter mode renders output gradually
When typewriter mode is enabled, the CLI SHALL print each character of its
output with a delay determined by the configured speed, rather than flushing
whole lines at once. The final text SHALL be byte-identical to non-typewriter
output.

#### Scenario: Characters appear progressively
- **WHEN** typewriter mode is enabled and a finding is printed
- **THEN** characters appear one at a time with the configured delay

#### Scenario: Final text identical
- **WHEN** the same output is produced with and without typewriter mode
- **THEN** the resulting text is identical aside from timing

### Requirement: Typewriter mode is toggleable at runtime
The CLI SHALL provide a `/typewriter` command accepting `on`, `off`, and
`speed <cps>`. `on` enables the mode, `off` disables it, and `speed` sets the
rendering rate in characters per second. Invalid arguments SHALL produce an
error and leave the current state unchanged.

#### Scenario: Enable and disable
- **WHEN** the user runs `/typewriter on` then `/typewriter off`
- **THEN** the mode is enabled then disabled

#### Scenario: Set speed
- **WHEN** the user runs `/typewriter speed 80`
- **THEN** the rendering rate becomes 80 characters per second

#### Scenario: Invalid argument
- **WHEN** the user runs `/typewriter frobnicate`
- **THEN** an error is printed and the mode is unchanged

### Requirement: Typewriter mode is disabled outside interactive terminals
When stdout is not a terminal, or the CLI runs in batch mode, typewriter mode
SHALL be disabled and SHALL NOT be re-enabled by commands or flags. Output
SHALL be produced immediately.

#### Scenario: Piped output immediate
- **WHEN** the CLI's stdout is piped and typewriter mode was requested
- **THEN** output is produced immediately with no delay

#### Scenario: Batch mode immediate
- **WHEN** the CLI runs with `-c`
- **THEN** typewriter mode is disabled regardless of flags

### Requirement: All CLI output respects typewriter mode
When enabled, typewriter mode SHALL apply to every CLI output path: banner,
findings, diagnosis, reports, and prompts.

#### Scenario: Findings typed out
- **WHEN** a finding is printed while typewriter mode is enabled
- **THEN** the finding line is rendered with the typewriter effect

#### Scenario: Diagnosis typed out
- **WHEN** `/diagnose` runs while typewriter mode is enabled
- **THEN** the diagnosis output is rendered with the typewriter effect
