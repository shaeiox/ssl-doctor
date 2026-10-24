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
2026-10: raw mode for a single keystroke > raw for the whole session — a crashing check or a child process (`ssh`, `openssl`) must never inherit a raw terminal, and ISIG keeps Ctrl-C a real signal.
2026-10: capture command output as plain text and recolour at render time > storing ANSI — wrapping/padding by visible width needs no terminal emulator, so centring stays exact.
2026-10: questions and spinner in the status line > drawing them in the panel — the panel stays results-only, so evidence is never interleaved with progress.
2026-10: transcript flows under the banner with the chrome right after it > a footer pinned to the last row — a short session reads as one centred block instead of leaving a dead gap and moving the input as output arrives.
2026-10: centre each command's output as its own block > centring every line (breaks evidence/table alignment) or the whole transcript (earlier commands shift when a longer one arrives).
2026-10: no output frame around results > the boxed panel — the frame competed with the banner and implied a fixed viewport; only the dashed input keeps a frame-like affordance.
2026-10: remote command timeout stored as `command_timeout` > `cmd_timeout` — the attribute shadowed the `/timeout` handler, so the command either crashed (before) or would have to be renamed.
