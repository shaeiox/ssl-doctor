# Spec Delta

## Purpose

Turns the full-screen shell into a terminal: left-aligned output that scrolls
with the mouse, `/` completion in the command bar, and one framed block per
command's results.

## ADDED Requirements

### Requirement: The transcript is left-aligned, never centred
Every transcript row SHALL start at the same left gutter, independent of its
width. The application column SHALL span the terminal width, capped for
readability, and SHALL NOT be horizontally centred. The header, status line,
command bar and key hints SHALL share that gutter; the dashed input rules SHALL
span the full column.

#### Scenario: Short and long output
- **WHEN** a command prints `SSL Doctor v0.3.0` and a later command prints a long evidence line
- **THEN** both start at the same column and the long line wraps at the column's right edge

#### Scenario: Wide terminal
- **WHEN** the terminal is 200 columns wide
- **THEN** the column is capped (120) and still starts at the left edge

### Requirement: The transcript scrolls with the mouse wheel
The shell SHALL report wheel events while the command bar or a question is
awaiting input, and SHALL stop reporting them otherwise. A wheel-up event SHALL
scroll back into the transcript and a wheel-down event SHALL return towards the
newest line. PageUp/PageDown SHALL keep working.

#### Scenario: Scrolling back
- **WHEN** the operator rolls the wheel up over a long session
- **THEN** earlier output appears and the typed command text is preserved

#### Scenario: Scrolling during a command
- **WHEN** a network check is running
- **THEN** the shell is not reporting mouse events, so no wheel bytes reach the command's input

### Requirement: Typing `/` offers completions and Tab accepts one
While the command bar holds a partial command name that begins with `/`, the
shell SHALL show a list of matching commands (at most three rows, each with its
description). `Tab` SHALL replace the command bar text with the highlighted
command and a trailing space. `Up`/`Down` SHALL move the highlight while the
list is visible, and a space or `Escape` SHALL dismiss it.

#### Scenario: Completing a command
- **WHEN** the operator types `/sc` and presses Tab
- **THEN** the command bar reads `/scan ` and the list is gone

#### Scenario: List bounds
- **WHEN** the operator types `/`
- **THEN** at most three matching commands are listed with their descriptions

#### Scenario: No list with arguments
- **WHEN** the command bar reads `/tls example.com`
- **THEN** no completion list is shown

### Requirement: Each result is framed
A command that produces findings SHALL draw exactly one frame for its results:
a rounded border carrying the executed command as the title, one row per check
with its status glyph, word and check id, the evidence/detail/fix lines
indented inside the frame, and the passed/failed/warning/not-tested counters in
the closing border. The frame SHALL fit the available width, wrapping text
rather than eliding it, and SHALL fall back to ASCII corners when the terminal
cannot carry box drawing.

#### Scenario: A failing scan
- **WHEN** `/tls shop.example` returns a passing and a failing check
- **THEN** one frame appears with `/tls shop.example` in the title and `1 failed` in the footer

#### Scenario: Paper-thin terminal
- **WHEN** the frame is drawn in a 40-column terminal
- **THEN** every row is at most 40 columns wide and no evidence text is elided

#### Scenario: Plain output
- **WHEN** output is piped or `NO_COLOR` is set with `-c`
- **THEN** findings print as plain `[   + PASS]` rows without any frame
