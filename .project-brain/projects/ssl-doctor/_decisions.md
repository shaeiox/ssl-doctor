---
project: ssl-doctor
topic: decisions
tags: [decisions, adr]
status: verified
trust: ai-inferred
last_done: 2026-10-24
version: 1
---

# Decisions

One line per settled choice: `YYYY-MM: chosen > rejected — why`.

2026-10: semantic colour roles + `paint(text, role)` > raw ANSI constants — one place to add the warm palette, testable degradation, no call-site churn. No `rich`/`colorama`: the stdlib-only install story for locked-down customer machines outranks convenience.
2026-10: one frame per **command**, findings as rows > one box per finding — a `/scan` emits 20–30 findings; boxing each roughly triples transcript height and turns the frame into noise.
2026-10: static dashed input frame > shimmering input border — `input()` blocks stdin, so a background shimmer would corrupt typed text, paste and readline history; shimmer stays on the spinner, which owns stdout for its lifetime.
2026-10: `NO_COLOR` checked before `SSL_DOCTOR_COLOR` > the reverse — the user-level "no colour at all" signal must win over a demo flag.
2026-10: glyph choice by stream encoding probe > platform check — cp1252 Windows consoles are the real constraint, not the OS name.
2026-10: plain mode is ASCII-only and glyph-substituted (`+ x ! > -`) > keeping `·`/`✓` — plain means "safe in any pipe or log", and the diff against v0.3.0 stays limited to glyphs.
2026-10: report pills use dark text on role-colour backgrounds > white text — white on `#4eba65` is 2.3:1; dark text clears 4.5:1 while keeping the palette.
2026-10: startup banner uses a hand-drawn five-row wordmark > a figlet/pyfiglet font — stdlib-only install story, exact control of the two-stroke look, and widths that can be measured and tested.
2026-10: banner has a compact text form below 68 columns > dropping every other column of the art — half-scale letters stop being legible at 40 columns, and the name/description/credit must survive a narrow terminal.
2026-10: `creator: eleven` is a fixed constant > a flag or env override — the credit is part of the banner requirement and a cosmetic switch is not worth the surface area.
2026-10: alternate screen + composed frame > scrollback-only output — a diagnostic session is an app: fixed chrome, bounded panel, scrollback you can revisit, and a command bar that does not scroll away.
2026-10: hand-rolled termios/msvcrt key reader > curses/prompt_toolkit/rich — stdlib-only, no TERM database, and one predictable code path for the batch fallback.
2026-10: host keys via ssh probes (accept-new into a scratch file, auth off) as a fallback > replacing ssh-keyscan outright or a Python SSH library — keyscan stays the fast single-connection path; ssh negotiates exactly like the real session; stdlib-only.
2026-10: redraw result frames from transcript text at layout time (`tui.reflow_frame`) > storing findings objects in the transcript — keeps the colourless text model that colorize, selection, /copy and the response recorder already share; frames are our own regular output, so parsing them is reliable.
2026-10: own `textcells` (unicodedata) > the `wcwidth` package — the CLI stays stdlib-only; ambiguous-width box glyphs count as one cell.
2026-10: Windows keys via ReadConsoleInputW (ctypes) > msvcrt.getwch — UCRT `_getwch` forces input mode 0 and drops non-key records, so VT mouse input could never arrive; reading records ourselves keeps the mode we set and also gets native MOUSE_EVENTs.
2026-10: raw mode for a single keystroke > raw for the whole session — a crashing check or a child process (`ssh`, `openssl`) must never inherit a raw terminal, and ISIG keeps Ctrl-C a real signal.
2026-10: capture command output as plain text and recolour at render time > storing ANSI — wrapping/padding by visible width needs no terminal emulator, so centring stays exact.
2026-10: questions and spinner in the status line > drawing them in the panel — the panel stays results-only, so evidence is never interleaved with progress.
2026-10: transcript flows under the banner with the chrome right after it > a footer pinned to the last row — a short session reads as one centred block instead of leaving a dead gap and moving the input as output arrives.
2026-10: centre each command's output as its own block > centring every line (breaks evidence/table alignment) or the whole transcript (earlier commands shift when a longer one arrives).
2026-10: no output frame around results > the boxed panel — the frame competed with the banner and implied a fixed viewport; only the dashed input keeps a frame-like affordance.
2026-10: remote command timeout stored as `command_timeout` > `cmd_timeout` — the attribute shadowed the `/timeout` handler, so the command either crashed (before) or would have to be renamed.
2026-10: left-aligned, full-width column over a centred one — centring spent width on both sides of every evidence line and moved the prompt as output width changed; a terminal reads from one left edge.
2026-10: mouse reporting only inside read_line() > leaving SGR mouse mode on all session — the wheel bytes produced during a five-second TLS handshake would queue in the tty and be typed into the next command.
2026-10: a three-row completion menu with a ▸ cursor > inline ghost text — the design language has framed lists, not inline hints, and three rows never cover the transcript.
2026-10: result frames drawn by the text printer, re-coloured by the renderer > drawing them inside the TUI only — the line REPL, the shell and the tests then share one box, and the transcript stays a colourless text model.
2026-10: stream findings into an open result frame > bare streamed rows or no streaming in the shell — the box is the shell's unit of output, and a finding should appear the moment its check completes; one `_results()` phase helper replaces a dozen copied `if _STREAM_OUTPUT` branches.
2026-10: reconcile emitted with returned findings per phase > trusting every check to emit everything — a check that returns a finding without emitting it is still drawn, and one that does both is drawn once.
2026-10: centred classic two-stroke banner > new half-block wordmark or a boxed card (offered as mockups; the operator chose the classic form) — the wordmark is centred as one block so the indented S stroke keeps its place.
2026-10: rounded chat-style composer (label + status in the top border, hints + send in the bottom) > dashed `| > ` bar or a minimal underline — a visible label and a distinct input affordance; supersedes "only the dashed input keeps a frame-like affordance".
2026-10: a separate screen painter (`paint_screen()`) > one capture-gated `paint()` for both transcript text and screen drawing — the renderer runs during capture (spinner, streaming), so the gate stripped the screen's colours.
