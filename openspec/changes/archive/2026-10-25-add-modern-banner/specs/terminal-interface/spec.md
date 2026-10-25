# Spec Delta

## Purpose

Defines the startup banner added after `warm-terminal-ui`: a modern
double-rule wordmark built from two-stroke block letters, carrying the app
name, description, version, read-only note and creator credit. It replaces the
clean-text banner of `warm-terminal-ui` and amends that change's "no ASCII art"
clause, which no longer applies to the startup banner.

## ADDED Requirements

### Requirement: The startup banner is a two-stroke wordmark
On startup the system SHALL print a banner consisting of a double horizontal
rule, a five-row wordmark spelling the application name, a description line, a
version line, a read-only note and an explicit `creator: eleven` credit, closed
by a second double rule. Each letter of the wordmark SHALL be drawn with
two-character-wide strokes so the wordmark reads as paired straight lines, and
no line of the banner SHALL exceed the terminal width.

#### Scenario: Full banner on a wide terminal
- **WHEN** the REPL starts on an 80-column terminal
- **THEN** a double rule is printed, followed by exactly five wordmark rows, the description, the version, the read-only note and `creator: eleven`, and a closing double rule

#### Scenario: Banner width
- **WHEN** the banner is rendered on a terminal narrower than the wordmark
- **THEN** no banner line is wider than the terminal and the wordmark is replaced by the compact form

### Requirement: The banner degrades with the rest of the interface
The banner SHALL use the theme's primary role for its rules and wordmark, muted
for the description and note, and accent for the creator credit. In plain mode
it SHALL use only ASCII characters (`#` for the wordmark and `=` for the rules)
and emit no escape sequences.

#### Scenario: Plain banner
- **WHEN** stdout is not a terminal
- **THEN** the banner is drawn with `#` and `=` only and contains no escape sequence

#### Scenario: Colour banner
- **WHEN** stdout is a TrueColor terminal
- **THEN** the rules and wordmark are painted with the primary role and the creator credit with the accent role

### Requirement: The creator credit is part of the banner and is not configurable at runtime
The banner SHALL print the literal credit `creator: eleven`. No command, flag or
environment variable SHALL change, hide or override it.

#### Scenario: Credit is always present
- **WHEN** the banner is printed in any mode, at any width
- **THEN** the text `creator: eleven` appears

#### Scenario: Commands are unaffected
- **WHEN** `/help`, `/version` or `/scan` runs
- **THEN** their output and exit codes are unchanged by the banner change
