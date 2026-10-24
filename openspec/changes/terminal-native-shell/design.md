# Design

## Context

`drop-output-frame` removed the transcript panel and centred each command's
output as a block. Fitting a block into a centred column costs horizontal room
on both sides of every evidence line, and the shift changes with each command's
width, which is the opposite of how a terminal behaves.

## Layout

```
  ██████ ██████ ██       █████  ██████ ██████ ██████ ██████ ██████
  ██     ██     ██       ██  ██ ██  ██ ██       ██   ██  ██ ██  ██
  ██████ ██████ ██       ██  ██ ██  ██ ██       ██   ██  ██ ██████
      ██     ██ ██       ██  ██ ██  ██ ██       ██   ██  ██ ██  ██
  ██████ ██████ ██████   █████  ██████ ██████   ██   ██████ ██  ██
  offline ssl/tls diagnostics · client · server · chain · nginx
  creator: eleven  ·  read-only checks

  ssl-doctor> /tls shop.example
  ╭─ /tls shop.example ───────────────────────────────────────────╮
  │ ✓ PASS    tls.version   negotiates TLS 1.3                    │
  │ ✓ PASS    cert.valid    valid for another 74 days             │
  │ ✗ FAIL    chain.order   the server sends only the leaf        │
  │             • 1 certificate presented                         │
  │             fix: append the intermediate to ssl_certificate   │
  ╰─ 2 passed · 1 failed · 0 warnings · 0 not tested ────────────╯

  timeout 8s · ssh off
 ────────────────────────────────────────────────────────────────
  > /sc
  ▸ /scan    full workflow: domain -> client -> server -> diagnosis
    /scan    …                     ← one row per match, Tab accepts
    /server  interactive SSH setup for authorized server-side checks
 ────────────────────────────────────────────────────────────────
  Tab complete · up/down history · wheel scroll · Ctrl-D quit
```

## Decisions

### D1 — Left edge, capped width, no centring
The column starts at column 1 and spans the terminal up to 120 columns. Beyond
120 the eye loses the row while reading a long evidence sentence; below it the
terminal gets every column back, which is the point of removing the centred
block. The rule is "same left edge for everything", so a short and a long block
never disagree about where they begin.

### D2 — Mouse reporting only while reading a line
`?1000h`/`?1006h` are enabled in `read_line()` and disabled before the session
returns to cooked mode. If they stayed on, wheel bytes produced during a
five-second TLS handshake would sit in the tty buffer and be typed into the next
command. Enabling them per prompt costs two escape sequences per keystroke loop
and removes that class of bug entirely.

### D3 — A completion menu, not inline ghost text
The design language has no dim-inline-suggestion precedent; it has framed lists
with a `▸` cursor. Three rows keep the menu from covering the transcript, and
matching is prefix-first over the same command table `/help` renders, so the two
can never drift. `Tab` completes with a trailing space because every command
takes an argument.

### D4 — One frame per command's results
The frame is drawn by the plain-text printer, not by the renderer, so the same
box reaches the line-oriented REPL and the full-screen transcript, and piped
output keeps its `[   + PASS]` rows. The full-screen renderer re-applies colour
by recognising the border glyphs, which keeps the transcript a colourless text
model (what the tests, the report and the pipes rely on).

### D5 — Border colour encodes the role, text carries the status
The frame border uses the `tool` (hot pink) role from the design system, the
title is `primary`, the glyph+status word carry their status role, and the
footer counts are coloured per counter. Nothing is encoded in the border alone,
so a colourless terminal loses no information.

### D6 — The chrome still follows the transcript
A short session puts the input bar right under its output rather than pinning it
to the last row, so the screen has one thing to read and no dead gap. Long
sessions fill the region and end up at the bottom anyway, which is when the
scroll keys matter.
