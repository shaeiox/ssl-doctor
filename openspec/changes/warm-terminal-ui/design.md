# Design

## Context

The reference design system is Claude Code's terminal UI
(`awesome-tui-design/designs/claude-code/DESIGN.md`). Its rules, extracted:

| Rule | What the reference actually specifies |
|---|---|
| Mood | Warm, playful, content-forward. No corporate chrome. |
| Density | Balanced: clean conversation flow, minimal chrome. |
| Colour source | Semantic roles first (primary/tool/accent/success/warning/error/muted/surface), hex second, terminal index last. TrueColor recommended; 256 acceptable. |
| Signature accent | Terracotta `#d77757`, with a lighter shimmer `#eb9f7f`. |
| Frames encode role | Hot pink `#fd5db1` = machine work (tool/bash); lavender `#b1b9f9` = a question back to the human; muted gray `#888888` = the input line; `#505050` = separators only. |
| Input | Dashed **ASCII** (`-` and `|`), never Unicode box drawing. Deliberately casual. |
| Type scale | H1 bold + primary; body default foreground; captions muted + dim; code values highlighted; user input `>` prefixed. |
| Banner | No figlet, no ASCII art; clean text. Centring allowed only for the startup logo. |
| Motion | One signature indicator: six glyphs `· ✢ ✳ ✶ ✻ ✽` cycling outward and back at 120 ms, in primary, paired with a random whimsical verb. No animated transitions. |
| Progress | Counters only ("(3/12)"), never progress bars; spinner for indeterminate waits. |
| Layout | Min width 80, ideal 120; 2-space indent; 1 blank line between messages; 1 char padding inside blocks; left aligned; persistent bottom status line. |
| Icons | Always paired with an ASCII fallback (`✓`/`+`, `✗`/`x`, `⚠`/`!`, `▸`/`>`, `•`/`-`). |
| Colour is never alone | Glyph + word + colour, in that order of priority. |

Constraints this repository adds:

- Python 3.10+, stdlib only. No `rich`, no `colorama`, no `wcwidth`.
- `input()`-based REPL today; no raw mode, no alternate screen, no cursor
  addressing. Pipes, redirects, `readline` history and CI capture all work and
  must keep working.
- The test suite captures stdout with `contextlib.redirect_stdout(io.StringIO())`,
  so `isatty()` is false there; that path must stay deterministic.
- Windows consoles need explicit VT enabling and are not guaranteed UTF-8.
- Reports are shared as files: self-contained, printable, no remote assets.

## Goals / Non-Goals

**Goals**
- A single theme/token layer, testable at each capability level.
- Output that is scannable at 20–30 findings without truncating evidence.
- Distinct visual treatment for *machine worked* vs *we need an answer from you*.
- Zero behavioural change: same commands, same findings, same verdicts, same
  exit codes, same JSON.

**Non-Goals**
- A full-screen TUI, mouse support, keybindings, live streaming redraw.
- The web dashboard, the agent's stdout, or the HTML report's information
  architecture.
- New diagnostic content, new check ids, or wording changes to evidence.

## Design System As Applied

### Palette (semantic role → value)

| Role | TrueColor | 256 | 16 | Used for in ssl-doctor |
|---|---|---|---|---|
| `foreground` | `#ffffff` | `15` | bright white | body text, evidence |
| `primary` | `#d77757` | `173` | yellow | H1, section titles, `>`, spinner, active step |
| `shimmer` | `#eb9f7f` | `216` | yellow | spinner highlight frame |
| `tool` | `#fd5db1` | `206` | bright magenta | command block frames |
| `accent` | `#b1b9f9` | `147` | bright blue | questions to the operator, `fix:` advice |
| `success` | `#4eba65` | `71` | green | PASS |
| `warning` | `#ffc107` | `220` | yellow | WARNING |
| `error` | `#ff6b80` | `204` | red | FAIL, hard errors |
| `muted` | `#888888` | `245` | bright black | captions, `·` bullets, input frame, scope |
| `subtle` | `#505050` | `239` | black | dividers, block interiors |
| `surface` | `#373737` | `237` | black | highlighted row background (only when background colours are reliable) |
| `inactive` | `#999999` | `246` | bright black | disabled hints |

Status mapping: PASS → `success`, FAIL → `error`, WARNING → `warning`,
NOT TESTED → `muted`. Scope stays `muted`; the check id stays `muted`/dim so
the human title wins. Auto-accept purple is unused: ssl-doctor has no mode that
runs without asking.

### Glyphs

`✓` PASS (`+`) · `✗` FAIL (`x`) · `⚠` WARNING (`!`) · `▸` running/step (`>`) ·
`•` bullet (`-`) · `>` prompt. The ASCII fallback is chosen by testing whether
stdout's encoding can represent the glyph, not by platform name.

### Type hierarchy

| Level | Style | ssl-doctor use |
|---|---|---|
| H1 | bold + primary | `SSL Doctor v0.3.0`, section titles |
| H2 | bold | `/help` group titles, block headers |
| Body | foreground | evidence, diagnosis prose |
| Code | mono, muted-bright | check ids, paths, fingerprints, cipher names |
| Caption | muted + dim | scope, timings, counts, `next: …` hints |
| Prompt | primary `>` on dashed frame | REPL input |

Two-space indent for body content; one blank line between blocks; no
centred text and no ASCII art anywhere, including startup.

### Border grammar

```
- - - - - - - - - - - - - - - -      dashed ASCII  → input (muted)
| > shop.example:443_          |
- - - - - - - - - - - - - - - -

  ┌─ /scan shop.example ────────────────────── combined
  │ ✓ tls.handshake   TLS 1.3 · TLS_AES_256_GCM_SHA384
  │ ✗ tls.chain       server sends only the leaf
  └─ 4 passed · 1 failed · 0 warnings · 0 not tested

  ┌─ Run authorized server-side checks (SSH)? ─────
  │  [Y]es  [N]o
  └──────────────────────────────────────────────
```

Single-line box drawing for blocks; `┌ ─ ┐ │ └ ┘` only. No double lines, no
shadows, no nested boxes (a nested box would need a second border colour role).

## Decisions

### D1 — Four-level theme with semantic roles, not raw ANSI

A `Theme` table maps each role to `(truecolor, 256, 16, plain)` sequences. A
`ColorMode` is resolved once per process:

1. `NO_COLOR` set (any value, per no-color.org) → `plain`.
2. `SSL_DOCTOR_COLOR=never|always|auto` → override (`always` still respects a
   non-tty target).
3. `COLORTERM` in `truecolor|24bit` → `truecolor`.
4. `TERM` contains `256color` → `256`.
5. tty → `16`; otherwise `plain`.

`paint(text, role)` replaces `paint(text, *ansi_codes)`. Code never names a
colour again; it names a role. A module-level `_USE_COLOR` stays as a
backwards-compatible alias so nothing that peeks at it breaks.

*Alternative:* keep the 16-colour constants and add terracotta. Rejected — it
cannot express the warm palette on modern terminals and leaves no way to test
degradation.

*Alternative:* adopt `rich`. Rejected — breaks the stdlib-only install story
for locked-down customer machines.

### D2 — One block per command; findings are rows

The "tool call" in ssl-doctor is a command run: `/tls`, `/local`,
`/server nginx`, one `/scan` step. So the block is opened once per command
with the command as its header label, findings print as rows, and the existing
counter line closes the block. Evidence, `detail` and `fix:` stay indented
under their row; nothing is dropped or truncated.

*Why not one box per finding:* a full `/scan` produces 20–30 findings; boxing
each one roughly triples transcript height and turns the frame into noise,
which is the opposite of the reference's "minimal chrome".

*Why not drop the frames:* without them, PASS and FAIL rows differ only by a
colour and a word; the frame is what makes a command's output a unit when the
transcript is scrolled back.

Plain mode renders exactly today's text (`[PASS] title · scope`, evidence
lines, counters) with ASCII glyphs and no frame, so captured logs, tests and
`-c` batch output are unchanged.

### D3 — Static dashed input frame; shimmer lives on the spinner only

The reference shimmers the input border. That is not implementable with
`input()`: while stdin blocks, any background write to stdout corrupts the
typed line and breaks paste, `Ctrl-R` history and readline on every platform we
support. Adopting a raw-mode redraw loop to get the shimmer would cost pipes,
CI capture, screen readers and Windows consoles.

Therefore: the input frame is static and honest — a dashed rule, then
`| > ` in primary, then the operator's line; the closing rule is printed when
the command returns, so the transcript reads as a box. Shimmer is kept where it
is safe: the thinking indicator, which owns stdout for its whole lifetime.
Width is `clamp(columns - 4, 40, 72)` using `shutil.get_terminal_size` with an
80-column fallback.

*Alternative:* prompt-toolkit or curses. Rejected — dependency and
non-stdlib terminal handling for a cosmetic animation.

### D4 — Questions back to the operator are lavender, and change nothing else

`prompt()` keeps its call sites, default handling and `EOFError` behaviour. It
gains a lavender frame, `[Y]es [N]o`-style key hints derived from the call's
accepted answers, and a muted default. Accepted answer sets (`yes/y`, `no/n`,
`1/2`) and re-prompt loops stay byte-for-byte identical; only the presentation
changes. This makes the one thing a busy engineer must not miss — "the tool is
waiting for you" — visually unlike machine output.

### D5 — Signature spinner with TLS verbs

Frames: `· ✢ ✳ ✶ ✻ ✽ ✻ ✶ ✳ ✢` at 120 ms, in `primary` with every other frame
in `shimmer`. One verb picked per invocation from a diagnostic-flavoured list
(`handshaking`, `chaining`, `ciphering`, `pinning`, `tracing`, `sniffing`,
`untangling`, `auditing`, `decoding`, `percolating`, `ruminating`, `noodling`),
rendered as `✳ Chaining certificates…`. The spinner still clears its line before
any other output, never starts off-tty, and stops on exceptions. Plain mode
prints `… chaining certificates` once and moves on. No progress bars anywhere;
`/scan` progress is the existing `Step 2/4` counter, which becomes `▸ Step 2/4`.

### D6 — A muted status line above the interactive prompt

`shop.example:443 · 12 findings · 1 fail · timeout 8s · ssh off`, dim, one
line, printed with the prompt on a tty only. It gives the operator the three
things they otherwise re-type commands to discover. It is suppressed for `-c`
batch runs, off-tty, and whenever the REPL is not interactive. Not implemented
as a persistent bottom bar: reserve/scroll-region tricks break pipes and
scrollback.

### D7 — Report adopts the palette, keeps its structure

`report._CSS` is restyled: terracotta rule under the title, hot-pink monospace
check ids, semantic status pills (`success`/`error`/`warning`/`muted`), dashed
`border-top` separators, the same 2-space-equivalent rhythm (8/16 px). The
document stays light-background and printable (reports are attached to tickets
and printed), self-contained (inline CSS only, no fonts, no scripts, no remote
assets) and content-identical: same sections, same order, same badge labels,
same payload. Contrast for every pill and body text stays at or above 4.5:1.

### D8 — Presentation-only seams

Work happens in `cli.py`'s presentation helpers and `report.py`'s CSS/markup
attributes. Nothing in this change reaches a check, a correlation rule, a
contract field or an exit path. Verdict text, check ids and evidence strings
are treated as data owned by the diagnostic layer and are only *styled*.

Consequence: any future check automatically gets the new look, and this change
cannot alter a diagnosis. Tests that assert verdicts through
`SSLDoctorCLI.execute()` continue to pass unchanged because plain mode keeps
the old text format.

*Alternative:* restyle by changing status strings (`PASS` → `✓ pass`). Rejected
— that is a data change: JSON, HTML and downstream consumers all read those
strings.

## Risks / Trade-offs

- **Box drawing on legacy Windows consoles.** Mitigated by the encoding probe:
  if `✓`/`│` cannot be encoded, the whole UI drops to ASCII fallbacks and
  dashed frames, not a partial box.
- **Very narrow terminals (< 60 columns).** Frames shrink to the 40-column
  floor; evidence wraps with a hanging indent under the row rather than being
  truncated. `NO_COLOR`/plain mode is always available for pathological
  terminals.
- **Colour-blind operators.** Status is glyph + word first; `PASS`/`FAIL` text
  is always present, never colour alone.
- **Golden-output tests.** Only plain mode is asserted; interactive colour output
  is tested by unit-testing the token resolver and the glyph fallback, not by
  snapshotting escapes.
- **Screenshot/docs drift.** The README example output is regenerated in the
  same task that changes the layout, using `SSL_DOCTOR_COLOR=never` for the
  plain block and a checked TrueColor capture for the framed block.
