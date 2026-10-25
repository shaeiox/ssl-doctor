# terminal-interface Specification

## Purpose

Lets an operator take text out of an interactive SSL Doctor session — by
selecting it with the mouse or by copying a command's whole response — and put
it on the clipboard without re-running the command.

## Requirements

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

### Requirement: Interactive startup enters a full-screen application mode
When stdin and stdout are terminals and no colour/UI opt-out is set, the
interactive session SHALL switch to the terminal's alternate screen, hide the
cursor while drawing, and present a single composed frame instead of appending
lines to the scrollback. Batch (`-c`) runs, redirected output, and terminals
without the required capabilities SHALL keep the existing line-oriented REPL.

#### Scenario: Interactive launch
- **WHEN** `python3 ssldoctor.py` runs in a 100x30 terminal with no opt-out
- **THEN** the alternate screen is entered and one centred frame is drawn

#### Scenario: Piped or batch run
- **WHEN** stdout is redirected, or the tool runs with `-c`
- **THEN** no alternate-screen sequence is emitted and output is line-oriented as before

#### Scenario: Explicit opt-out
- **WHEN** `SSL_DOCTOR_TUI=0` or `--no-tui` is used
- **THEN** the line-oriented REPL runs

### Requirement: The transcript is left-aligned, never centred
Every transcript row SHALL start at the same left gutter, independent of its
width. The application column SHALL span the terminal width, capped for
readability, and SHALL NOT be horizontally centred. The header, the completion
menu and the composer SHALL share that gutter; only the startup banner is
centred.

#### Scenario: Short and long output
- **WHEN** a command prints a one-line version and a later command prints a long evidence line
- **THEN** both start at the same column and the long line wraps at the column's right edge

#### Scenario: Wide terminal
- **WHEN** the terminal is 200 columns wide
- **THEN** the column is capped (120) and still starts at the left edge

### Requirement: There is no panel around the transcript
The full-screen shell SHALL NOT draw a box, border or panel label around the
transcript as a whole; only each command's result carries its own frame.

#### Scenario: Empty session
- **WHEN** the shell opens before any command runs
- **THEN** no empty bordered region is drawn

### Requirement: The transcript begins directly under the banner
The transcript SHALL start immediately below the header block, separated by a
single blank line, and SHALL grow downward. The completion menu and the
composer SHALL follow the transcript, so a short session has no gap between
its output and the input.

#### Scenario: Short session
- **WHEN** one command has produced two lines of output on a 24-row terminal
- **THEN** the banner is at the top, the two lines follow it, and the composer comes next

#### Scenario: Long session
- **WHEN** the transcript exceeds the available rows
- **THEN** the newest lines are shown and the composer sits on the last rows

### Requirement: The header adapts to the available height
The header SHALL show the wordmark when the frame has room for it, and the
compact text header when vertical space is short. The header SHALL include the
application name and the creator credit in both forms.

#### Scenario: Tall terminal
- **WHEN** the frame is at least 24 rows tall
- **THEN** the header shows the five-row wordmark, the description and `creator: eleven`

#### Scenario: Short terminal
- **WHEN** the terminal is 16 rows tall
- **THEN** the header is the compact text form and the output panel still renders

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

### Requirement: Command output is captured into the transcript
Output produced by any command SHALL be captured and rendered from the
transcript rather than written directly to the screen. The transcript SHALL keep
a scrollback buffer of the whole session, wrap long lines to the column width
without dropping characters, and paint status rows by their status.

#### Scenario: Long output
- **WHEN** `/help` is executed in a 30-row terminal
- **THEN** its output appears in the transcript, wrapped to the column width, and the earlier transcript remains scrollable

#### Scenario: Status colouring
- **WHEN** a FAIL finding is printed
- **THEN** its status marker is painted with the error role and the text is unchanged

#### Scenario: Nothing is lost
- **WHEN** output longer than the screen is produced
- **THEN** every line is retained in the scrollback, reachable by scrolling

### Requirement: Commands are separated by one blank line
Each executed command SHALL be followed by a blank line in the transcript, so
consecutive commands form distinct blocks.

#### Scenario: Two commands in a row
- **WHEN** `/version` then `/timeout` run
- **THEN** their outputs are separated by exactly one blank line

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

### Requirement: Input is read in a rounded composer
On a terminal, input SHALL be read inside a rounded box: its top border carries
the composer label (or the current question or running check) and a muted
session summary — target, finding counts, SSH state — its input row starts
with a prompt mark, and its bottom border carries key hints. The full-screen
shell and the line REPL SHALL draw the same composer, as wide as the column
(in the line REPL: clamped to the terminal, at least 40 columns).

#### Scenario: Line REPL
- **WHEN** the line REPL waits for a command on a colour terminal
- **THEN** the input is framed by the rounded composer with the session summary in its top border

### Requirement: Plain mode prompts without a box
In plain mode the prompt SHALL be `ssl-doctor> ` with no composer box.

#### Scenario: Plain mode
- **WHEN** output is plain
- **THEN** the prompt is `ssl-doctor> ` and no box characters are printed

### Requirement: The line REPL stays line-oriented and non-invasive
In the line-oriented REPL (`--no-tui`, or when the full-screen shell is not
available) input SHALL be read with `input()`, keeping readline history and
editing; it SHALL NOT use raw mode, cursor addressing, an alternate screen or
any background write to stdout while a line is being read.

#### Scenario: Typing and history
- **WHEN** the operator types a command in the line REPL and presses the up arrow
- **THEN** readline recalls the previous command and no escape sequence has moved the cursor or overwritten the input line

#### Scenario: Pasted input
- **WHEN** a multi-line block is pasted at the line REPL prompt
- **THEN** the text arrives unmodified and no frame redraw interrupts it

### Requirement: The keyboard drives editing, history and scrolling
The composer SHALL support printable input, Left/Right, Home/End (cursor),
Backspace, Ctrl-U, Enter, Ctrl-C, Ctrl-D, Up/Down history recall, and
PageUp/PageDown scrolling of the transcript. Ctrl-C and Ctrl-D at the composer
SHALL end the session as they do in the line-oriented REPL.

#### Scenario: Scrolling back
- **WHEN** the operator presses PageUp
- **THEN** the transcript shows earlier lines and the composer keeps the text being typed

#### Scenario: History recall
- **WHEN** the operator presses Up at an empty composer
- **THEN** the previous command is inserted and remains editable

#### Scenario: Ending the session
- **WHEN** the operator presses Ctrl-D at an empty composer
- **THEN** the alternate screen is left, the cursor is restored, and the process exits with the same code as the line-oriented REPL

### Requirement: Questions and progress appear in the composer
Slash commands that ask a question SHALL ask it in the composer (the question
and its default in its top border) and accept exactly the same answers as
before. Indeterminate work SHALL show the spinner and its verb in the
composer's top border instead of writing progress text into the transcript.
Passwords SHALL be read with echo disabled and never rendered.

#### Scenario: SSH setup
- **WHEN** `/server connect` asks for a host, a port and an authentication method
- **THEN** each question is shown in the composer, answers are read there, and the accepted answer sets are unchanged

#### Scenario: Password entry
- **WHEN** the operator chooses password authentication
- **THEN** the typed password is not echoed or left in the transcript

#### Scenario: Running check
- **WHEN** a network check runs
- **THEN** the composer shows the spinner and verb, and the transcript gains no progress lines

### Requirement: Questions to the operator are visually distinct
Interactive questions (SSH connection setup, host-key trust, mode selection)
SHALL be presented in a single-line lavender frame whose header is the
question and whose body carries key hints such as `[Y]es  [N]o`. Defaults SHALL
stay visible in muted brackets.

#### Scenario: Host-key trust question
- **WHEN** an unknown host key is found during `/server connect`
- **THEN** the trust question is drawn in the lavender frame with `[Y]es  [N]o` hints and `no` as the visible default

### Requirement: Question handling is unchanged
The accepted answer sets, re-prompt loops and `EOFError`-returns-default
behaviour SHALL be identical to the current implementation.

#### Scenario: Same answers as before
- **WHEN** the operator answers `n` to the trust question
- **THEN** the connection is aborted with the existing note, exactly as before the restyle

#### Scenario: No input available
- **WHEN** stdin reaches EOF at a question with a default
- **THEN** the default is returned, unchanged

### Requirement: Indeterminate work uses the signature spinner
The system SHALL animate indeterminate work with the six-glyph reverse-mirror
cycle `· ✢ ✳ ✶ ✻ ✽` at approximately 120 ms per frame, painted in the primary
colour with the shimmer colour alternating, paired with a short
diagnostic-themed verb.

#### Scenario: Animated on a terminal
- **WHEN** `/tls shop.example` performs network checks on a terminal
- **THEN** a spinner plus a verb is drawn on one line and that line is fully cleared before the findings block is printed

### Requirement: The spinner never corrupts other output
The spinner SHALL clear its line before any other output, SHALL NOT start when
stdout is not a terminal, and SHALL stop on exceptions and interrupts. Plain
mode SHALL print a single muted progress line instead of animating.

#### Scenario: No animation when redirected
- **WHEN** the same command runs with stdout captured
- **THEN** one plain progress line is printed and no escape-driven animation occurs

#### Scenario: Interrupted check
- **WHEN** the operator presses Ctrl-C during a check
- **THEN** the spinner stops, its line is cleared, and the existing `interrupted` note is printed

### Requirement: Determinate progress uses counters
Determinate progress SHALL be shown as a counter such as `▸ Step 2/4`.
Progress bars SHALL NOT be used.

#### Scenario: Guided scan
- **WHEN** `/scan` runs three steps
- **THEN** each step header shows its index and total, and no bar is drawn

### Requirement: Colour is expressed as semantic roles
The system SHALL paint text through named semantic roles (`primary`, `shimmer`,
`tool`, `accent`, `success`, `warning`, `error`, `muted`, `subtle`, `surface`,
`inactive`, `foreground`) instead of literal ANSI codes. Every role SHALL
provide a TrueColor value, a 256-colour index, a 16-colour fallback and a plain
form, and no role SHALL be written as an escape code outside the theme table.

#### Scenario: Status text uses its role
- **WHEN** a PASS and a FAIL finding are printed on a TrueColor terminal
- **THEN** the PASS text is painted with the success role and the FAIL text with the error role, each using its TrueColor value

#### Scenario: One palette for every surface
- **WHEN** the interactive output and the HTML report are compared
- **THEN** both take their accent, tool and status colours from the same role values

### Requirement: Colour level is selected from terminal capability
The system SHALL select exactly one colour level per process: plain when
`NO_COLOR` is present, when `SSL_DOCTOR_COLOR` is `never` or `plain`, when
stdout is not a terminal, or when `TERM=dumb`; otherwise TrueColor when
`COLORTERM` is `truecolor` or `24bit`, otherwise 256-colour when `TERM`
contains `256color`, otherwise 16-colour.

#### Scenario: NO_COLOR wins over a TrueColor terminal
- **WHEN** `NO_COLOR=1` and `COLORTERM=truecolor` are both set and stdout is a terminal
- **THEN** the output contains no ANSI escape sequences

#### Scenario: Forced plain
- **WHEN** `SSL_DOCTOR_COLOR=never` is set and stdout is a TrueColor terminal
- **THEN** the output contains no escape sequences

#### Scenario: Piped output is plain
- **WHEN** stdout is a pipe with no colour environment overrides
- **THEN** the output is plain text with ASCII status markers

#### Scenario: 256-colour terminal
- **WHEN** stdout is a terminal, `COLORTERM` is unset and `TERM=xterm-256color`
- **THEN** status text is painted with the role's 256-colour index

### Requirement: Plain mode emits no escape sequences
In plain mode the system SHALL emit no ANSI escape sequences and SHALL use only
ASCII glyphs and rules.

#### Scenario: Redirected plain run
- **WHEN** any command is run with stdout captured and colour disabled
- **THEN** the captured text contains no ESC byte and no Unicode box character

### Requirement: Glyphs fall back to ASCII when the terminal cannot show them
The system SHALL choose between Unicode and ASCII glyphs by testing whether the
output encoding can represent them, not by platform name. The pairs are `✓`/`+`
for PASS, `✗`/`x` for FAIL, `⚠`/`!` for WARNING, `▸`/`>` for running and `•`/`-`
for bullets. A frame that cannot be drawn SHALL fall back to dashed ASCII rules
rather than mixing character sets.

#### Scenario: CP1252 stdout
- **WHEN** stdout's encoding cannot encode `✓` or `│`
- **THEN** the output uses `+`, `x`, `!` and dashed ASCII rules throughout, with no Unicode box characters

### Requirement: Status never depends on colour
The status word SHALL always be present, so colour SHALL never be the only
carrier of PASS, FAIL, WARNING or NOT TESTED.

#### Scenario: Monochrome capture
- **WHEN** the output is captured without colour
- **THEN** every finding still states PASS, FAIL, WARNING or NOT TESTED in words

### Requirement: Text hierarchy is applied consistently
Top-level titles SHALL be primary bold, section titles bold, body text the
default foreground, and captions, scope, timings and counts muted or dim.

#### Scenario: Startup banner
- **WHEN** the REPL starts
- **THEN** the banner is a primary bold title plus a one-line description and a muted read-only note, with no ASCII art and no centring

#### Scenario: Diagnosis output
- **WHEN** `/diagnose` finds two causes
- **THEN** both are printed with the same index, certainty, origin, evidence and recommendation text as before, with the new type hierarchy

### Requirement: Layout uses two-space indent and single-line gaps
Content SHALL be left-aligned with a two-space indent, and blocks SHALL be
separated by one blank line. Aside from the startup banner there SHALL be no
decorative art and no centred text.

#### Scenario: Two commands in sequence
- **WHEN** two checks run one after another on a terminal
- **THEN** the second block starts after exactly one blank line and is indented two spaces

### Requirement: Help listing keeps every command
`/help` SHALL list every command and description in their current order as an
aligned two-column listing, with commands in the primary colour and
descriptions muted.

#### Scenario: Help output
- **WHEN** `/help` is executed
- **THEN** every command and its description still appear, in the current order, as an aligned two-column listing

### Requirement: Diagnosis output keeps its content
`/diagnose` SHALL keep the existing ordering, certainty labels, evidence lines
and recommendations. Only the presentation SHALL change.

#### Scenario: Cause ordering
- **WHEN** three causes are correlated, one confirmed and two probable
- **THEN** they print in the same order with the same certainty words as before the restyle

### Requirement: Windows terminals are prepared or degraded
On Windows the system SHALL enable virtual-terminal processing before emitting
colour or box drawing, and SHALL fall back to plain output when that fails,
rather than printing escape sequences to a console that cannot interpret them.

#### Scenario: Modern Windows console
- **WHEN** the tool runs in a Windows console that accepts VT sequences
- **THEN** the warm palette and frames render as on other terminals

#### Scenario: VT enabling fails
- **WHEN** virtual-terminal processing cannot be enabled
- **THEN** the session continues in plain mode without escape sequences

### Requirement: Leaving the application restores the terminal
On exit, interrupt or an unhandled error the system SHALL leave the alternate
screen, restore the cursor and the terminal mode, and print a short closing line
on the normal screen.

#### Scenario: Normal exit
- **WHEN** the operator runs `/exit`
- **THEN** the normal screen returns with the prior scrollback intact and a one-line farewell

#### Scenario: Crash inside a command
- **WHEN** a command raises an unexpected exception
- **THEN** the error is shown in the panel, the terminal is still restored on exit, and the session continues

### Requirement: The full-screen shell is presentation only
Commands, flags, findings, verdicts, exit codes, the report and the findings
contract SHALL be unchanged by the full-screen mode. The same `execute()`
dispatch SHALL serve both presentations.

#### Scenario: Same answers, same verdicts
- **WHEN** `/scan example.com --client-only` runs in the TUI and in the line-oriented REPL
- **THEN** both produce the same findings, verdicts and exit code

#### Scenario: Batch is untouched
- **WHEN** `-c` commands run with the TUI available
- **THEN** no frame is drawn and output is byte-identical to the line-oriented run
