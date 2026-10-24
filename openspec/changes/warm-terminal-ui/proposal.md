# Proposal

## Why

The diagnostic core is now trustworthy (v0.3.0), but the terminal presentation
still reads like a generic script: 16-colour ANSI constants, a braille spinner,
a bare `ssl-doctor>` prompt, and findings printed as a flat wall of
`[PASS]/[FAIL]` lines. Nothing in the output says "this tool was designed".

The Claude Code TUI design system (reference:
`https://github.com/cola-runner/awesome-tui-design/blob/master/designs/claude-code/DESIGN.md`)
is a good model for a diagnostic CLI because it is *content-forward*: no ASCII
art, no chrome for its own sake, warm terracotta accent, dashed ASCII input,
hot-pink frames around machine work, lavender frames around questions put back
to the operator, and a whimsical spinner for indeterminate waits. Applying that
language makes a 20–30 finding scan transcript scannable, and makes the moment
the tool asks a human something visually unmistakable.

The change is presentation only. Check ids, statuses, evidence text, command
names, answer sets, exit codes, the findings contract and report content are
untouched.

## What Changes

- **Semantic theme layer.** Replace raw ANSI constants with named roles
  (`primary`, `tool`, `accent`, `success`, `warning`, `error`, `muted`,
  `subtle`, `surface`) resolved per terminal capability: TrueColor → 256 →
  16 → plain. `NO_COLOR` always wins; `SSL_DOCTOR_COLOR=always|never` exists
  for demos and screenshots.
- **One frame per command.** A run of checks is drawn as a single box-drawing
  block — the "tool call" analogue — with findings as rows inside it and the
  existing counter line as the block footer. Status is carried by glyph, word
  and colour, in that order of priority.
- **Dashed input, framed questions.** The REPL prompt becomes a dashed ASCII
  frame with a `>` prefix, and questions put back to the operator (SSH mode,
  host-key trust, run server-side checks?) become lavender frames with
  `[Y]es [N]o` key hints. Static frames only: no alternate screen, no raw mode.
- **Signature thinking indicator.** Six-glyph reverse-mirror spinner in
  terracotta with a TLS-flavoured verb replaces the braille spinner. Plain
  output prints one muted line instead.
- **Hierarchy pass.** Banner, `/help`, step headers and `/diagnose` get the
  documented type scale (primary bold H1, muted dim captions, 2-space indent,
  one blank line between blocks), and the interactive prompt gains a muted
  status line (`target · findings · timeouts · ssh`).
- **Report re-skin.** The self-contained HTML report adopts the same palette
  and dashed-rule motif. Structure, ordering and the contract payload do not
  change; CSS only.
- **Explicit plain-mode guarantee.** Non-tty stdout, `NO_COLOR`, `TERM=dumb`
  and encodings that cannot represent the glyphs keep today's exact
  `[PASS]`/`[FAIL]` text output. Piped logs and captured test output stay
  stable.

## Capabilities

### New Capabilities
- `terminal-interface`: theme tokens, capability detection and degradation,
  command blocks, prompts and questions, spinner, layout hierarchy, glyph
  fallbacks, interactive status line.
- `report-presentation`: the visual treatment of the self-contained HTML report
  and the promise that its content and contract are unchanged.

### Modified Capabilities
- None. There are no existing specs in `openspec/specs/`.

## Impact

- **Code:** `ssl_doctor/cli.py` (presentation helpers only: `C`, `paint`,
  `_STATUS_COLOR`, `print_finding(s)`, `Spinner`, `banner`, `prompt`, `error`,
  `note`, `cmd_help`, `cmd_diagnose`, the REPL prompt, batch echo) and
  `ssl_doctor/report.py` (`_CSS` and presentational class attributes). No
  changes to `findings.py`, `analyze.py`, `netchecks.py`, `certs.py`,
  `local.py`, `server.py`, `contract.py`, `agent.py`, `service/`.
- **Dependencies:** none. Stdlib only, no new packages, no width/colour
  library — matching the existing constraint.
- **Compatibility:** no command, flag or answer changes. Batch (`-c`) output,
  JSON reports and the findings schema are byte-stable. The only intended
  differences are interactive-presentation text, icons and colour.
- **Docs:** README gets a short "terminal look" section and refreshed example
  output; CHANGELOG notes the restyle under an "Unreleased" heading.
- **Out of scope:** the web dashboard (`service/ssldoctor_service/ui.py`), the
  agent's log output, Apache/IIS presentation, any new command, any new flag,
  and any change to diagnostic wording.
