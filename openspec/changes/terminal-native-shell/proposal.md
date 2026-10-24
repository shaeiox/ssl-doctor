# Proposal

## Why

The full-screen shell borrowed a magazine layout — a centred column with
centred blocks — when what operators want from a diagnostic prompt is a
terminal. Centring costs width on every wrapped evidence line, pushes the
prompt to a different column depending on the widest command, and makes
scrolling feel like a web page rather than a log.

Three concrete gaps remain against the Claude Code design language the rest of
the interface follows: the transcript cannot be scrolled with the mouse, `/`
offers no completion, and a command's findings arrive as loose rows instead of
the design system's framed tool block.

## What Changes

- **Left-aligned, terminal-like flow.** The transcript is no longer centred:
  every row starts at the same two-column gutter, the column spans the terminal
  (capped at 120 columns for readability), and the dashed input and hints run
  the full width. Output scrolls like a terminal log.
- **Mouse-wheel scrolling.** The shell reports mouse events only while the
  command bar has focus, so the wheel scrolls the transcript without leaking
  escape bytes into a running command.
- **`/` completion.** Typing `/` opens a three-row list of matching commands;
  `Tab` completes the highlighted one, `Up`/`Down` move the highlight, a space
  dismisses the list.
- **A framed block per result.** Each command that produces findings draws one
  rounded box: the command as the title, one row per check with its status
  glyph, the evidence/detail/fix lines indented inside the frame, and the
  counters in the closing border.

Everything else — commands, accepted answers, check ids, verdicts, exit codes,
the JSON report and the plain pipe format — is untouched.

## Capabilities

### New Capabilities
- None.

### Modified Capabilities
- `terminal-interface`: the centred-column requirement is replaced by a
  left-aligned, scrollable, mouse-aware transcript; the command bar gains
  completion; results gain a framed block.

## Impact

- **Code:** `ssl_doctor/tui.py` (layout, mouse reporting, completion menu),
  `ssl_doctor/cli.py` (shared command table, completion source, result frames).
- **Tests:** layout tests rewritten for left alignment; new tests for the wheel,
  the completion menu and the result frame.
- **Compatibility:** the ASCII/plain paths and every command contract are
  unchanged; the line-oriented REPL and pipes keep their current bytes except
  for the result frame, which is shared by both presentations.
