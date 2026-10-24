# Spec Delta

## Purpose

Lets an operator take text out of an interactive SSL Doctor session — by
selecting it with the mouse or by copying a command's whole response — and put
it on the clipboard without re-running the command.

## ADDED Requirements

### Requirement: Dragging over the transcript selects text
While the composer is awaiting input in the full-screen shell, pressing the left
mouse button over a transcript row and dragging SHALL select the text between
the press and the current pointer position, in reading order, and SHALL
highlight it. The banner and the composer SHALL NOT be selectable.

#### Scenario: Drag across two rows
- **WHEN** the operator presses on the `•` of an evidence row and drags to the middle of the next row
- **THEN** the characters from the press point to the pointer are highlighted across both rows

#### Scenario: Drag outside the transcript
- **WHEN** the drag continues over the composer
- **THEN** the selection stops at the last transcript row and the composer is not highlighted

### Requirement: Releasing the selection copies it
Releasing the left button after a drag SHALL copy the selected text to the
clipboard as plain text — the characters shown, without colour codes and without
trailing padding — and the composer SHALL confirm how many lines and characters
were copied and by which route. A press and release without movement SHALL
clear any selection and copy nothing.

#### Scenario: Copy a fingerprint
- **WHEN** the operator drags over a SHA-256 fingerprint and releases
- **THEN** exactly the fingerprint characters are on the clipboard and the composer reports the copy

#### Scenario: Plain click
- **WHEN** the operator clicks without dragging
- **THEN** the selection is cleared and the clipboard is unchanged

### Requirement: `/copy` copies the previous response
`/copy` SHALL copy the complete plain-text output of the most recent command
other than `/copy` itself, in both the full-screen shell and the line REPL.
`/copy all` SHALL copy the whole session transcript. When there is nothing to
copy, the command SHALL say so and leave the clipboard unchanged.

#### Scenario: Copy a scan's response
- **WHEN** the operator runs `/tls shop.example` and then `/copy`
- **THEN** the clipboard holds that command's result frame and notes as plain text, including the frame borders as shown

#### Scenario: Nothing to copy
- **WHEN** `/copy` is the first command of a session
- **THEN** it reports that there is no previous response and copies nothing

### Requirement: Ctrl-Y copies the previous response from the composer
In the full-screen shell, `Ctrl-Y` in the composer SHALL perform the same copy as
`/copy` without adding a command to the transcript or the history, and SHALL
keep any text already typed in the composer.

#### Scenario: Copy while typing
- **WHEN** the composer holds `/diag` and the operator presses `Ctrl-Y`
- **THEN** the previous response is copied, the confirmation appears and the composer still holds `/diag`

### Requirement: Clipboard delivery is honest about its route
A copy SHALL be delivered through the terminal clipboard escape and, when one is
available on this machine, a local clipboard tool, without invoking a shell. The
confirmation SHALL name the route(s) used and SHALL NOT claim success when the
only route is the terminal escape, which a terminal may silently ignore.

#### Scenario: Remote session without a local tool
- **WHEN** the shell runs over SSH and no clipboard tool is installed
- **THEN** the text is sent with the terminal escape and the confirmation says it was sent to the terminal clipboard

#### Scenario: Local tool fails
- **WHEN** the local clipboard tool exits with an error
- **THEN** the session continues, and the confirmation reports the failure without exposing the copied text

### Requirement: Mouse capture never reaches a running command
Mouse button and drag reporting SHALL be enabled only while the composer or a
question is reading input and SHALL be disabled before any command runs and when
the shell exits. Wheel scrolling SHALL keep working while reporting is enabled.

#### Scenario: Selecting during a check
- **WHEN** a network check is running and the operator drags over the screen
- **THEN** no mouse bytes reach the check's input and the terminal's own selection applies

#### Scenario: Leaving the shell
- **WHEN** the session ends by `/exit`, `Ctrl-D` or an error
- **THEN** the terminal is left with mouse reporting off

### Requirement: Copied text never includes secrets
Masked input SHALL never be part of a copied selection, `/copy` or `/copy all`,
and the copied transcript SHALL contain only what the session displayed.

#### Scenario: Password entry
- **WHEN** the operator typed an SSH password and then runs `/copy all`
- **THEN** the clipboard contains no part of the password
