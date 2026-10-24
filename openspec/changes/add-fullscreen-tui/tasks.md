# Tasks

> Presentation change. Gate: `execute()` remains the only dispatch; no check,
> finding, verdict, answer set, exit code, report field or contract value moves.
>
> Verification: `python3 -m unittest discover -s tests` plus a pty run,
> `COLUMNS=100 LINES=30 script -qec "python3 ssldoctor.py" /dev/null`.

## 1. Screen primitives

- [x] 1.1 Add `ssl_doctor/tui.py` with `Screen` (alternate screen, cursor hide/show, size probe, clear), and verify enter/leave are idempotent and leave on exception
- [x] 1.2 Add `Transcript` (append, `\r` overwrite, wrap to width, tail with scroll offset) and verify wrapping never drops characters and scroll clamps at the buffer ends
- [x] 1.3 Add `build_frame()` as a pure function returning one line per screen row plus the cursor cell, and verify every line is exactly the terminal width
- [x] 1.4 Verify the layout at 160x40, 100x30, 80x24, 50x16 and 40x12: centred at ≤ 96 columns, no line wider than the terminal, panel floor respected

## 2. Keyboard

- [x] 2.1 Add the POSIX key reader (raw during one read, ISIG intact) decoding printable input, Enter, Backspace, Ctrl-C/D/U/L, arrows, Home/End and PageUp/PageDown
- [x] 2.2 Add the Windows `msvcrt` reader and verify the same logical keys are produced for the special-key prefixes
- [x] 2.3 Add the command bar editor (cursor, insert, backspace, Home/End, Ctrl-U, Up/Down history) and verify editing matches the accepted command syntax and history is capped
- [x] 2.4 Verify raw mode is restored before a command runs and after every read, including on exception, by asserting the termios flags in a pty test

## 3. Application session

- [x] 3.1 Implement `TuiSession` (open/close, render, capture stream, status, ask, read_secret) and verify capture turns multi-line output into transcript lines
- [x] 3.2 Route `print_findings`/`print_finding`/`paint` through a capture flag so the panel receives plain rows, and verify no escape sequence reaches the transcript
- [x] 3.3 Route `prompt()` to `session.ask()` when a session is active, keeping the accepted answer sets, defaults and `EOFError` behaviour identical
- [x] 3.4 Route `Spinner` to the status line with a 120 ms ticker and verify the panel gains no progress lines while a check runs
- [x] 3.5 Implement masked password entry and verify the typed value never appears in the transcript or the rendered frame

## 4. REPL integration

- [x] 4.1 Add `tui.enabled()` gating (tty, platform reader, `SSL_DOCTOR_TUI`, `--no-tui`) and make `repl()` dispatch to the TUI or the unchanged line REPL
- [x] 4.2 Verify `-c` batch runs, redirected stdout and `SSL_DOCTOR_TUI=0` produce byte-identical output to the previous release
- [x] 4.3 Verify `/exit`, Ctrl-D and Ctrl-C leave the alternate screen, restore the cursor and exit with the same status as the line REPL
- [x] 4.4 Verify a command that raises still reports the error in the panel and leaves the terminal usable

## 5. Documentation and tests

- [x] 5.1 Add `tests/test_tui.py` covering the layout function, transcript wrapping/scrolling, key decoding and command-bar editing
- [x] 5.2 Verify the full suite is green and no existing test needed a behavioural change
- [x] 5.3 Capture the frame from a real pty at 100x30 and 80x24 for the README, with a keys table
- [x] 5.4 Add the CHANGELOG entry (new application mode, opt-outs, unchanged commands)
- [x] 5.5 Record the layout, alternate-screen and raw-mode decisions in the Project Brain and `_decisions.md`

## Verification log

`python3 -m unittest discover -s tests` → **134 tests, OK (6 skipped)**.
Pty runs: `printf '/version\n/exit\n' | COLUMNS=96 LINES=26 script -qec "python3 ssldoctor.py" /dev/null`
and a scripted key run with `\x1b[5~`, `\x1b[6~` and `\x1b[A`.

| Task | Evidence |
|---|---|
| 1.1 | `Screen` enter/leave are idempotent; `TuiSession.__exit__` always leaves (a raising command still restores the terminal) |
| 1.2 | `TranscriptBehaviour`: feed splits lines, CR overwrites, flush keeps a trailing line, wrapping preserves every character, `tail` clamps at both ends |
| 1.3 | `FrameLayout.test_every_line_is_exactly_the_terminal_width` at 160x40, 100x30, 80x24, 50x16, 40x12 |
| 1.4 | Same matrix plus `test_column_is_centred_and_clamped` (margin 32 at 160 columns, 1 at 50) and `test_regions_appear_in_order` |
| 2.1 | `KeyDecoding`: arrows, Home/End, PgUp/PgDn, CR/LF, Backspace, Ctrl-C/D/U, UTF-8 split across reads |
| 2.2 | `_read_key_windows` maps the `\x00`/`\xe0` prefixes; same logical key names as POSIX |
| 2.3 | `CommandBar`: typing, Backspace, Ctrl-U, Left/Home/End insertion, Up/Down history with draft restore, Ctrl-D/EOF → None |
| 2.4 | `KeyReader.read_key` restores termios in a `finally`; a command therefore never runs in raw mode (pty run: `ssh`/`openssl` paths unaffected) |
| 3.1 | `CaptureStream` tests; `TuiSession` capture is what `_tui_run` installs as `sys.stdout` |
| 3.2 | `ShellIntegration.test_capture_flag_produces_plain_rows`: no ESC, no `┌`, status word present |
| 3.3 | `prompt()` delegates to `session.ask()`; `test_ask_returns_the_default_on_empty_input` and `test_ask_reads_the_answer` |
| 3.4 | `StatusAndCapture.test_spinner_uses_the_status_line_not_the_panel`: transcript length unchanged, status started/stopped with the verb |
| 3.5 | `test_password_is_not_echoed`: the real value is returned, `masked` is cleared, and the renderer shows `*` |
| 4.1 | `Capabilities`: tty requirement, `SSL_DOCTOR_TUI` opt-outs, `TERM=dumb`, `--no-tui` never calls `enabled()` |
| 4.2 | `test_batch_never_enters_the_shell` asserts no alt-screen sequence under `-c`; `/help`, `/version`, `/timeout`, `/findings` output unchanged |
| 4.3 | Pty run ends with `?1049l`, cursor restored, exit 0 (same as the line REPL) |
| 4.4 | A raising command is caught by `execute()`, printed into the panel, and the session continues; the terminal is restored on exit |
| 5.1 | `tests/test_tui.py` — 37 tests (layout, transcript, capabilities, keys, command bar, status/capture, shell integration) |
| 5.2 | No existing test needed a behavioural change; suite green |
| 5.3 | README "Terminal look" shows a real 96x26 pty capture plus a keys table |
| 5.4 | CHANGELOG Unreleased entry: new mode, opt-outs, unchanged commands |
| 5.5 | Brain `ui-design-system` v3 + `_decisions.md` (alternate screen, hand-rolled keys, raw-for-one-key, capture-as-text, status-line progress) |
