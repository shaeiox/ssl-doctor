# Design

## Context

`warm-terminal-ui` deliberately chose a clean-text banner ("no figlet, no ASCII
art") because generic figlet art clashes with the content-forward language. The
explicit request now is the opposite: a full, modern, designed banner.

Constraints that shape this design:

- **Stdlib only.** No `pyfiglet`, no font files: the wordmark is a small table in
  `cli.py`.
- **Width honesty.** A 64-column wordmark cannot be printed on a 40-column
  terminal. Everything must fit `terminal_width()`.
- **Plain mode is ASCII-only and escape-free** (contract from
  `warm-terminal-ui`), so the wordmark has a `#` form and the rules an `=`
  form.
- **The banner is not a command.** It must not alter any exit code, finding or
  report field.

## The wordmark

Eight glyphs plus a word space, five rows tall, every stem two characters wide,
so each letter reads as paired straight lines:

```
██████ ██████ ██       █████  ██████ ██████ ██████ ██████ ██████
██     ██     ██       ██  ██ ██  ██ ██       ██   ██  ██ ██  ██
██████ ██████ ██       ██  ██ ██  ██ ██       ██   ██  ██ ██████
    ██     ██ ██       ██  ██ ██  ██ ██       ██   ██  ██ ██  ██
██████ ██████ ██████   █████  ██████ ██████   ██   ██████ ██  ██
```

Glyph table (6 columns each, `#` = stroke, trailing spaces trimmed per row):

| Letter | Row 1 | Row 2 | Row 3 | Row 4 | Row 5 |
|---|---|---|---|---|---|
| S | `######` | `##` | `######` | `    ##` | `######` |
| L | `##` | `##` | `##` | `##` | `######` |
| D | `#####` | `##  ##` | `##  ##` | `##  ##` | `#####` |
| O | `######` | `##  ##` | `##  ##` | `##  ##` | `######` |
| C | `######` | `##` | `##` | `##` | `######` |
| T | `######` | `  ##` | `  ##` | `  ##` | `  ##` |
| R | `######` | `##  ##` | `######` | `##  ##` | `##  ##` |

Total width for `SSL DOCTOR`: 64 columns.

## Layout

```
══════════════════════════════════════════════════════════════════════
  ██████ ██████ ██       █████  ██████ ██████ ██████ ██████ ██████
  ██     ██     ██       ██  ██ ██  ██ ██       ██   ██  ██ ██  ██
  ██████ ██████ ██       ██  ██ ██  ██ ██       ██   ██  ██ ██████
      ██     ██ ██       ██  ██ ██  ██ ██       ██   ██  ██ ██  ██
  ██████ ██████ ██████   █████  ██████ ██████   ██   ██████ ██  ██

  offline ssl/tls diagnostics · client · server · chain · nginx
  creator: eleven  ·  v0.3.0
  all checks are read-only; credentials are never logged
══════════════════════════════════════════════════════════════════════
```

Rules: `═` (box) / `=` (ASCII), painted with `primary`. Wordmark `█` / `#`,
`primary` + bold. Description and note `muted`. `creator: eleven` `accent` +
bold.

Compact form, used below ~72 columns:

```
════════════════════════════════════════════
  SSL DOCTOR  ·  v0.3.0
  offline ssl/tls diagnostics
  creator: eleven
════════════════════════════════════════════
```

## Decisions

### D1 — Hand-drawn table instead of a figlet dependency
Seven glyphs and a word space are all the tool needs. A table keeps the
stdlib-only install story, gives exact control over the two-stroke look, and
makes the banner testable without a subprocess.

*Alternative:* `pyfiglet` — rejected on dependency policy and unpredictable
widths.

### D2 — Two-stroke stems, five rows, 64 columns
Stems are exactly two characters wide, which is what makes every letter read as
paired straight lines while staying small enough to fit an 80-column terminal
with margins. Taller fonts (ANSI Shadow, 6–8 rows) push the opening screen past
the point where the command history is still visible.

### D3 — Three tiers, chosen from measured width
`full` when `columns - 2 >= wordmark + 6`, otherwise `compact`. The rules are
sized to the widest content line and clamped to `columns - 2`, so nothing wraps.
No truncation, no ellipsis, no half-drawn letters.

*Alternative:* scale the wordmark down by dropping every other column — the
letters stop being legible at 32 columns.

### D4 — Credit is fixed text, not configuration
`creator: eleven` is printed verbatim from a module constant in every mode and
width. A `--no-banner` flag or `SSL_DOCTOR_CREDIT` override would add surface
area to a cosmetic feature, and the requirement explicitly wants the credit
visible.

### D5 — Banner stays inside `cli.py`
The wordmark is presentation, and `cli.py` already owns the theme and layout
helpers. Adding a module for one table and one function would spread the design
system across files for no gain.
