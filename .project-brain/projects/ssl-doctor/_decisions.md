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
