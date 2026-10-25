# Design

## Context

`add-fullscreen-tui` introduced a boxed `output` panel because a frame is the
design system's way of marking "machine work". In practice the panel became the
dominant shape on screen: it duplicated the column's own edges, competed with the
wordmark and the input frame, and made short sessions look like a form with an
empty field.

The request: no output box, content directly below the banner, neatly centred.

## Layout

```
                ██████ ██████ ██       █████  ██████ ██████ ██████ ██████ ██████
                ██     ██     ██       ██  ██ ██  ██ ██       ██   ██  ██ ██  ██
                ██████ ██████ ██       ██  ██ ██  ██ ██       ██   ██  ██ ██████
                    ██     ██ ██       ██  ██ ██  ██ ██       ██   ██  ██ ██  ██
                ██████ ██████ ██████   █████  ██████ ██████   ██   ██████ ██  ██
                 offline ssl/tls diagnostics · client · server · chain · nginx
                              creator: eleven  ·  read-only checks

                                      ssl-doctor> /version
                                      SSL Doctor v0.3.0

    ssl-doctor> /tls shop.example
    [   + PASS] TLS handshake with shop.example:443  - network
              - negotiated protocol: TLSv1.3
    [   x FAIL] Chain sent by server  - network
              - the server sends only the leaf certificate

                                      timeout 8s · ssh off
 ──────────────────────────────────────────────────────────────────────────────
   > /scan shop.example
 ──────────────────────────────────────────────────────────────────────────────
            up/down history  ·  PgUp/PgDn scroll  ·  /help commands  ·  Ctrl-D quit
```

## Decisions

### D1 — Grow downward, not a pinned footer
The transcript is top-aligned under the banner and the chrome follows it. With
few lines the whole composition reads as one centred block; with many it fills
the screen and the input naturally reaches the bottom. A footer pinned to the
last row would leave a large dead gap under a short transcript and make the
input jump as output arrives.

*Alternative:* transcript at the top plus input always at row `rows - 4`.
Rejected for the dead gap and the jumpiness.

### D2 — Centre per block, not per line and not per frame
Three options were considered for "centred" text:

1. *Per line* — every line centred on its own width. Trivial, but it destroys
   the alignment of evidence continuations and the two-column `/help` table.
2. *Whole transcript as one block* — stable within one frame, but every earlier
   command shifts sideways as soon as a longer one arrives.
3. *Per block, split on blank lines* (chosen) — each command's output is centred
   on its own width, so internal alignment survives and earlier blocks only move
   when their own content changes.

Blocks wider than the column are left at zero shift; they are never clipped or
re-wrapped by the layout.

### D3 — Commands are separated by a blank line
Block centring needs block boundaries. One blank line after each command gives
that, and matches how a conversation reads.

### D4 — The frame budget shrinks by two rows
Removing the panel's top and bottom borders returns two rows to the transcript,
and the header no longer adds its own trailing blank (the layout adds exactly one
under the banner). `content_height()` accounts for the chrome — status, two
dashed rules, input and hints — and keeps a floor of one row.

### D5 — The dashed input survives
Only the output box was removed. The dashed rule pair still marks the editable
line, which keeps the "input is special" affordance from the design system
without reintroducing a box around the results.
