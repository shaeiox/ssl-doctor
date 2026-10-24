# Design

## Context

`warm-terminal-ui` deliberately stayed line-oriented: no alternate screen, no raw
mode, no cursor addressing, because that keeps pipes, CI capture and Windows
consoles working. The request now is an application shell, so those decisions are
revisited — but only for the *interactive* path.

Constraints:

- **Stdlib only.** `termios`/`select` on POSIX, `msvcrt` on Windows. No `curses`
  (its color/box capability database is not worth the dependency and it breaks
  the Windows story), no `rich`, no `textual`.
- **One dispatch.** The TUI must not own command logic. `execute()` stays the
  only entry point; the shell is a presentation adapter.
- **Batch and pipes are sacred.** `-c`, redirected stdout and captured tests
  must produce byte-identical output with no escape sequences.
- **Answers must not change.** SSH setup, host-key trust and mode questions keep
  their accepted answer sets and defaults.

## Screen model

```
                       ┌──────────────────────── application ───────────────────────┐
   (blank row)
        ════════════════════════════════════════════════════════════════════
          ██████ ██████ ██       █████  ██████ ██████ ██████ ██████ ██████
          ...                                                    (centred wordmark)
          offline ssl/tls diagnostics · creator: eleven
        ════════════════════════════════════════════════════════════════════
        ┌─ output ───────────────────────────────────────────────────────────┐
        │ [   + PASS] Chain sent by server  - network                        │
        │           - 2 certificate(s), linked (shop.test -> ...)            │
        │ [   x FAIL] Chain sent by server                                  │
        └────────────────────────────────────────────────────────────────────┘
          shop.example:443 · 12 findings · 1 fail · timeout 8s · ssh off
        ┌─ command ──────────────────────────────────────────────────────────┐
        │ > /scan shop.example_                                              │
        └────────────────────────────────────────────────────────────────────┘
          ↑↓ history · PgUp/PgDn scroll · /help · /exit
```

Column width: `min(columns - 2, 96)`, never below 40. Left margin:
`(columns - width) // 2`. Every emitted line is padded to the full terminal
width, so the composition is centred regardless of the terminal's own idea of
right margins.

## Decisions

### D1 — Alternate screen, drawn from a pure layout function
`build_frame()` takes the terminal size, header spans, transcript lines, status
text, command-bar text, cursor position and hints, and returns the exact lines to
write plus the cursor cell. It performs no I/O, which makes the whole visual
contract testable without a terminal.

Painting happens per span, after padding is computed from the *plain* text, so
colour never disturbs centring.

*Alternative:* `curses`. Rejected: colour/box capability differences across
TERM values, no TrueColor role table, awkward Windows support, and it would take
over stdout in ways that make the batch path harder to guarantee.

### D2 — Command output is captured, then re-rendered
While a command runs, `sys.stdout` is replaced by a capture stream that turns
writes into transcript lines. `paint()` returns its input unchanged during
capture, so the transcript stores plain text with no nested escape codes;
`print_findings()` therefore uses its plain row format and the panel — not a box
— is the frame. Status colouring is re-applied at render time from the leading
`[   + PASS]` marker.

This keeps wrapping, scrolling and centring exact, and means a check that prints
something unexpected still lands in the panel.

*Alternative:* store ANSI and pad by stripped width. Rejected: wrapping ANSI text
correctly requires a terminal emulator, and a mis-measured line breaks centring.

### D3 — Raw mode only while reading the command bar
The session enters raw mode for the duration of one keystroke read, then restores
`ICANON`/`ECHO` before running the command, so:

- `Ctrl-C` still raises `KeyboardInterrupt` (ISIG stays on),
- a crash inside a check cannot leave the terminal wedged,
- `getpass`-style reads and subprocesses (`ssh`, `openssl`) see a normal tty.

`ISIG` is deliberately left enabled; the alternative (raw all the time, catching
`\x03` ourselves) would hide SIGINT from child processes.

### D4 — Questions move to the status line, answers to the command bar
`prompt()` keeps its signature; when a session is active it delegates to
`session.ask()`, which renders the question plus default in the status line and
reads the answer in the command bar. Accepted answer sets live in `cli.py` and are
untouched. Passwords use a masked reader, so nothing sensitive is echoed into the
panel or left in the transcript.

### D5 — Spinner lives in the status line
During a command, the panel must not gain progress lines. The session starts a
120 ms ticker that redraws the frame with the next spinner glyph and the verb;
the transcript is untouched. Rendering is lock-protected because the ticker
thread and the capturing command both touch session state.

### D6 — Degradation is a first-class path, not an error path
`tui.enabled()` requires: stdout and stdin are terminals, `SSL_DOCTOR_TUI` is not
a falsey value, `--no-tui` was not passed, and a key reader exists for the
platform. Anything else runs the existing `repl()` unchanged. The TUI is entered
through a context manager, so an exception still leaves the alternate screen.

### D7 — Height budget is computed, not hard-coded
Rows are allocated in priority order: command bar (3), status (1), panel (≥ 3),
header (5 or 2), hints (1). When rows are short the hints go first, then the
wordmark collapses to the compact header, then the panel shrinks to its floor.
Nothing is ever drawn past the last row.
