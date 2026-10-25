# Spec Delta

## Purpose

Defines how SSL Doctor presents itself in a terminal: semantic colour roles and
their degradation, the frames that distinguish machine work from questions to
the operator, the thinking indicator, the layout hierarchy, glyph fallbacks and
the interactive status line. It constrains presentation only — no command,
finding, verdict or exit code changes.

## ADDED Requirements

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
`NO_COLOR` is present, otherwise TrueColor when `COLORTERM` is `truecolor` or
`24bit`, otherwise 256-colour when `TERM` contains `256color`, otherwise
16-colour on a terminal and plain off a terminal.

#### Scenario: NO_COLOR wins over a TrueColor terminal
- **WHEN** `NO_COLOR=1` and `COLORTERM=truecolor` are both set and stdout is a terminal
- **THEN** the output contains no ANSI escape sequences

#### Scenario: Piped output is plain
- **WHEN** stdout is a pipe with no colour environment overrides
- **THEN** the output is plain text with ASCII status markers

#### Scenario: 256-colour terminal
- **WHEN** stdout is a terminal, `COLORTERM` is unset and `TERM=xterm-256color`
- **THEN** status text is painted with the role's 256-colour index

### Requirement: Colour can be forced for demos and captures
`SSL_DOCTOR_COLOR=never` SHALL select plain output. `always` SHALL select colour
whenever stdout is a terminal. `auto` or an unset value SHALL follow capability
detection.

#### Scenario: never overrides an interactive terminal
- **WHEN** `SSL_DOCTOR_COLOR=never` is set and stdout is a TrueColor terminal
- **THEN** the output contains no escape sequences

#### Scenario: always respects redirection
- **WHEN** `SSL_DOCTOR_COLOR=always` is set and stdout is redirected to a file
- **THEN** the file contains plain text and no escape sequences

### Requirement: Plain mode emits no escape sequences
In plain mode the system SHALL emit no ANSI escape sequences and SHALL use only
ASCII glyphs and rules.

#### Scenario: Redirected plain run
- **WHEN** any command is run with stdout captured and colour disabled
- **THEN** the captured text contains no ESC byte and no Unicode box character

### Requirement: One frame per command, findings as rows inside it
The system SHALL open a single-line box-drawing block for each executed command
and print that command's findings as rows inside it, with the existing counters
line as the block footer. Each row SHALL show a status glyph, the status word,
the check id and the human title; evidence, detail and recommendation SHALL
stay nested under their row. No evidence line SHALL be dropped or truncated to
fit a frame.

#### Scenario: A command with mixed results
- **WHEN** `/server nginx shop.test` returns one FAIL and two PASS findings
- **THEN** one block is printed whose header names the command, whose rows are the three findings in their original order, and whose footer repeats the existing passed/failed/warnings/not-tested counts

#### Scenario: Plain mode keeps today's format
- **WHEN** findings are printed with stdout redirected to a file or pipe
- **THEN** each finding keeps the current `[STATUS] title · scope` line plus its indented evidence, with no frames, using ASCII status markers

### Requirement: Interactive input uses a dashed ASCII frame
On a terminal the prompt SHALL be drawn inside a dashed ASCII frame using
hyphen rules and pipe sides, with a `>` prefix in the primary colour and the
input line in muted grey. Unicode box drawing SHALL NOT be used for the input
frame.

#### Scenario: Prompt on a terminal
- **WHEN** the REPL prompts on a 80-column terminal
- **THEN** a dashed rule no wider than the terminal is printed, followed by a `| > ` input line

### Requirement: The input frame adapts to the terminal width
The frame width SHALL be clamped to the terminal width and SHALL NOT be
narrower than 40 columns. Off a terminal the prompt SHALL fall back to
`ssl-doctor> `.

#### Scenario: Narrow terminal
- **WHEN** the terminal is 50 columns wide
- **THEN** the dashed rule and input line fit within 50 columns without wrapping

#### Scenario: Prompt off a terminal
- **WHEN** stdin is a pipe feeding `/help`
- **THEN** no dashed frame is printed and any prompt text is `ssl-doctor> `

### Requirement: Input stays line-oriented and non-invasive
The input path SHALL read a line with `input()` and keep readline history and
editing. It SHALL NOT use raw mode, cursor addressing, an alternate screen or
any background write to stdout while a line is being read.

#### Scenario: Typing and history
- **WHEN** the operator types a command and presses the up arrow
- **THEN** readline recalls the previous command and no escape sequence has moved the cursor or overwritten the input line

#### Scenario: Pasted input
- **WHEN** a multi-line block is pasted at the prompt
- **THEN** the text arrives unmodified and no frame redraw interrupts it

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
separated by one blank line. Aside from the startup banner (see the
`add-modern-banner` change, which supersedes this clause) there SHALL be no
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

### Requirement: The interactive prompt carries a muted status line
On a terminal the REPL SHALL print one muted status line before the prompt,
summarising the target, the session finding counts, the configured timeouts and
the SSH session state. The status line SHALL be omitted in batch (`-c`) runs,
when stdout is not a terminal, and in plain mode.

#### Scenario: Status line after a scan
- **WHEN** a `/scan` for `shop.example:443` produced 12 findings including 1 FAIL and no SSH session is open
- **THEN** the next prompt is preceded by a single muted line containing the target, `12 findings`, `1 fail` and the SSH state

#### Scenario: Batch mode
- **WHEN** the tool runs with `-c "/tls shop.example"`
- **THEN** no status line is printed

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
