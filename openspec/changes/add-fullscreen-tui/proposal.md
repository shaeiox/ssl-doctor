# Proposal

## Why

Today the interface is a *log*: it opens with a wordmark, then appends findings
down the left margin. On a real terminal that wastes the window, and after one
`/scan` the opening screen has scrolled away. Nothing about it behaves like an
application — there is no fixed chrome, no scrolling, no status area, no
in-place command bar.

The design language is already in place (roles, frames, wordmark). What is
missing is the shell: an alternate screen, one centred column, a bounded output
panel with scrollback, a status line that shows progress and questions, and a
command bar with editing and history.

## What Changes

- **Full-screen application mode** on interactive start: alternate screen,
  hidden cursor while drawing, one composed frame redrawn in place.
- **Centred, fixed-width column** (≤ 96 columns, never wider than the
  terminal) with five regions: header, output panel, status line, command bar,
  key-hint footer.
- **Output panel** with a session scrollback: command output is captured into
  the panel, wrapped to its width, status rows painted by status, and scrollable
  with PageUp/PageDown/Home/End.
- **Command bar** with in-place editing (arrows, Home/End, Backspace, Ctrl-U),
  history (Up/Down) and masked password entry.
- **Status line** carries the scope summary, the spinner and its verb while a
  check runs, and the text of any question the command asks.
- **Graceful degradation**: batch runs, redirected output, `--no-tui`,
  `SSL_DOCTOR_TUI=0`, or a terminal without the needed capabilities keep the
  current line-oriented REPL byte-for-byte.

## Capabilities

### New Capabilities
- None.

### Modified Capabilities
- `terminal-interface`: adds the full-screen shell requirements (alternate
  screen, centred layout, panel capture, keyboard model, in-application
  questions/progress, terminal restoration) and makes the line-oriented REPL the
  documented fallback rather than the default interactive presentation.

## Impact

- **Code:** a new `ssl_doctor/tui.py` (screen, transcript, layout, key reader,
  command bar) and focused changes in `ssl_doctor/cli.py` (capture flag,
  TUI-aware `prompt()`/`Spinner`, frame renderer, `repl()` dispatch, `--no-tui`).
  No check, correlation rule, report or contract change.
- **Dependencies:** stdlib only — `termios`/`select` on POSIX, `msvcrt` on
  Windows, with the line-oriented REPL when neither is usable.
- **Compatibility:** no command, flag, answer set, verdict or exit code changes.
  `-c` batch output stays byte-identical. The TUI is a presentation layer over
  the same `execute()` dispatch.
- **Docs:** README gains a screenshot-style capture and a "keys" table;
  CHANGELOG notes the mode and the opt-outs; Project Brain records the layout.
- **Out of scope:** mouse support, tabs, a settings screen, multiple panes,
  live log streaming between commands, and any change to the web dashboard.
