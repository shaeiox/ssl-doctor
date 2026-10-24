# Tasks

## 1. Clipboard delivery

- [x] 1.1 Add `ssl_doctor/clipboard.py` with `copy(text, stream, env, run)` returning the routes used: OSC 52 to the terminal (tmux passthrough when `TMUX` is set, skipped above 100 kB of base64) and the first available local tool from a fixed argv list, `shell=False`, 2 s timeout; verify with unit tests that inject `stream`/`env`/`run` (OSC 52 bytes and base64, tmux wrapping, tool selection per environment, tool failure and timeout reported, size cap) — no real clipboard touched
- [x] 1.2 Add a confirmation formatter (`copied N lines · M chars · <routes>`, failure wording, never the copied text); verify with unit tests for each route combination

## 2. Response recording and `/copy`

- [x] 2.1 Record each command's colourless output in the shell (slice of `Transcript.lines` from its echo line) and in the line REPL (ANSI-stripping tee around `execute()`), excluding `/copy`; verify with tests that two commands record two responses and `/copy` does not replace the previous one
- [x] 2.2 Add `cmd_copy` (`/copy`, `/copy all`, "nothing to copy" message) using the clipboard helper, plus its `/help` row and `COMMANDS` completion entry; verify with tests for both presentations, the empty-session case, and that masked password input never appears in `/copy all`
- [x] 2.3 Document `/copy` in README's command table and CHANGELOG Unreleased; verify the documented commands match `/help`

## 3. Mouse selection in the full-screen shell

- [x] 3.1 Switch reporting to `?1002h` + `?1006h` (still only inside `read_line()`, off on exit) and decode SGR press/drag/release into mouse events while keeping wheel up/down; verify with `KeyReader` decoding tests for `ESC[<0;10;5M`, `ESC[<32;12;5M`, `ESC[<0;12;5m`, wheel 64/65, and the existing mouse-on/off ordering tests
- [x] 3.2 Record the layout map (first body screen row, gutter) from `build_frame()` and map screen cells to transcript row/column, clamped to transcript rows; verify with layout tests at several terminal sizes and with a scrolled transcript
- [x] 3.3 Keep the selection (anchor/head in transcript coordinates) on the session and render it as reverse video in `build_frame()`; verify with frame tests that only the selected cells carry `SGR 7` and that row widths stay exact
- [x] 3.4 On release after movement, copy the selected text (trailing spaces trimmed, rows joined by `\n`) and show the confirmation in the composer; a click without movement clears the selection; verify with scripted-key session tests (drag across two rows, click-only, drag into the composer)
- [x] 3.5 Add `Ctrl-Y` to copy the previous response from the composer without changing `input` or history, and add it to the key hints and README keys table; verify with a scripted-key test and a frame test of the hint

## 4. Integration

- [x] 4.1 Run the full suite (`venv/bin/python -m unittest discover -s tests`) and verify it passes with the new tests
- [x] 4.2 Drive the real shell in a pty: drag over a result row and release, then `/copy`, with a stub clipboard tool on `PATH`; verify the tool received exactly the selected text and the response, and that the terminal is restored on exit
