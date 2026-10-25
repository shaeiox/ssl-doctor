# Spec Delta

## Purpose

Defines the full-screen application mode: alternate screen, a centred fixed
width column holding a header, an output panel, a status line, a command bar and
a key-hint footer, with keyboard scrolling and in-place editing. It supersedes
the line-oriented REPL as the default interactive presentation; that REPL
remains the fallback whenever a full-screen terminal cannot be used.

## ADDED Requirements

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

### Requirement: The application layout is centred and fixed width
The frame SHALL be composed of a centred column no wider than 96 columns (and
never wider than the terminal), containing, top to bottom: the header, the
transcript, a status line, a command bar and a key-hint footer. Every drawn line
SHALL be exactly the terminal width so the column stays centred without relying
on terminal quirks. (The boxed output panel this requirement originally
specified is removed by `drop-output-frame`.)

#### Scenario: Centred on a wide terminal
- **WHEN** the terminal is 160 columns wide
- **THEN** the column is at most 96 columns and is centred, leaving equal margins

#### Scenario: Narrow terminal
- **WHEN** the terminal is 50 columns wide
- **THEN** the column fills the width minus two columns of margin and no line is clipped or wrapped by the terminal

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

### Requirement: The keyboard drives scrolling, history and editing
The command bar SHALL support printable input, Left/Right, Home/End,
Backspace, Ctrl-U, Enter, Ctrl-C, Ctrl-D, Up/Down history recall, and
PageUp/PageDown/Home/End scrolling of the output panel. Ctrl-C and Ctrl-D at the
command bar SHALL end the session as they do in the line-oriented REPL.

#### Scenario: Scrolling back
- **WHEN** the operator presses PageUp
- **THEN** the panel shows earlier transcript lines and the command bar keeps the text being typed

#### Scenario: History recall
- **WHEN** the operator presses Up at an empty command bar
- **THEN** the previous command is inserted and remains editable

#### Scenario: Ending the session
- **WHEN** the operator presses Ctrl-D at an empty command bar
- **THEN** the alternate screen is left, the cursor is restored, and the process exits with the same code as the line-oriented REPL

### Requirement: Questions and progress appear in the application chrome
Slash commands that ask a question SHALL ask it in the command bar (with the
question and its default shown in the status line) and accept exactly the same
answers as before. Indeterminate work SHALL show the spinner and its verb in the
status line instead of writing progress text into the panel. Passwords SHALL be
read with echo disabled and never rendered.

#### Scenario: SSH setup
- **WHEN** `/server connect` asks for a host, a port and an authentication method
- **THEN** each question is shown in the status line, answers are read from the command bar, and the accepted answer sets are unchanged

#### Scenario: Password entry
- **WHEN** the operator chooses password authentication
- **THEN** the typed password is not echoed or left in the transcript

#### Scenario: Running check
- **WHEN** a network check runs
- **THEN** the status line shows the spinner and verb, and the transcript gains no progress lines

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
