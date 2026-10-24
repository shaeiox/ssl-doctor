# Spec Delta

## Purpose

Removes the output frame from the full-screen shell: the transcript flows
directly under the banner in the centred column, with each command's output
centred as a block. The dashed input, status line and key hints stay.

## ADDED Requirements

### Requirement: There is no output frame
The full-screen shell SHALL NOT draw a box, border or panel label around the
transcript. Command output SHALL appear as plain text inside the centred
column.

#### Scenario: A command produces findings
- **WHEN** `/tls example.com` returns findings in the shell
- **THEN** they are drawn as text rows with no surrounding border and no `output` label

#### Scenario: Empty session
- **WHEN** the shell opens before any command runs
- **THEN** no empty bordered region is drawn

### Requirement: The transcript begins directly under the banner
The transcript SHALL start immediately below the header block, separated by a
single blank line, and SHALL grow downward. The status line, dashed input and
key hints SHALL follow the transcript, so a short session reads as one centred
block rather than a footer pinned to the bottom of the screen.

#### Scenario: Short session
- **WHEN** one command has produced two lines of output on a 24-row terminal
- **THEN** the banner is at the top, the two lines follow it, and the status line and input come next

#### Scenario: Long session
- **WHEN** the transcript exceeds the available rows
- **THEN** the newest lines are shown and the chrome sits on the last rows

### Requirement: Each command's output is centred as a block
Blocks separated by blank lines SHALL each be centred on their own width, so
that internal alignment (evidence continuations, the help table) is preserved
while the block sits in the middle of the centred column. Lines wider than the
column SHALL NOT be centred or clipped.

#### Scenario: Centred short output
- **WHEN** a command prints `SSL Doctor v0.3.0`
- **THEN** the line is centred under the banner

#### Scenario: Alignment preserved
- **WHEN** a finding prints evidence on the following line
- **THEN** the evidence keeps its indentation relative to the finding

### Requirement: Commands are separated by one blank line
Each executed command SHALL be followed by a blank line in the transcript, so
consecutive commands form distinct centred blocks.

#### Scenario: Two commands in a row
- **WHEN** `/version` then `/timeout` run
- **THEN** their outputs are separated by exactly one blank line

### Requirement: The dashed input and status line are unchanged in role
The status line SHALL remain muted and centred above the input, the input SHALL
remain a dashed rule pair with a `> ` prompt, and the key hints SHALL remain
centred below it.

#### Scenario: Typing
- **WHEN** the operator types `/scan example.com`
- **THEN** the text appears after `> ` between two dashed rules, and the caret follows the text
