---
project: ssl-doctor
topic: ui-design-system
tags: [ui, terminal, colour, accessibility, claude-code, cli]
status: verified
trust: ai-inferred
last_done: 2026-10-24
version: 1
---

**Problem:** The CLI looked like a generic script (16-colour ANSI constants, braille spinner, bare `ssl-doctor>` prompt, flat `[PASS]/[FAIL]` wall). Long `/scan` transcripts were hard to scan and a pending question was easy to miss.

**Solution (v1):** Applied the Claude Code TUI design language (`awesome-tui-design/designs/claude-code/DESIGN.md`) to `ssl_doctor/cli.py` + `ssl_doctor/report.py`. No diagnostic code touched.

- **Roles, not codes.** `ROLES` maps 12 semantic roles to `(truecolor rgb, 256 index, 16 SGR)`; `paint(text, role, bold, dim)` is the only colour entry point. `resolve_color_mode()` picks one level: `NO_COLOR` → `SSL_DOCTOR_COLOR` → tty → `TERM=dumb` → Windows VT → `COLORTERM` → `TERM` → 16. `set_color_mode()` re-resolves (tests, embedding).
- **Glyphs.** `Glyphs` holds `✓✗⚠▸•·?` with `+x!> -?` fallbacks; `resolve_glyphs()` tests the stream encoding (not the platform). `Glyphs.h`/`corner()` switch frames to `+-+`/`|` so a cp1252 console never sees a box character.
- **One frame per command.** `execute()` calls `set_block_label(line)`; `print_findings()` draws `┌─ <command> ─┐`, one row per finding (`glyph status check title`), nested evidence/detail/`fix:` (wrapped, never elided), and `└─ counts ┘`. Below 40 usable title columns the title drops to its own line.
- **Questions are lavender.** `prompt()` keeps its signature and answer sets; `_answer_hints()` derives `[Y]es [N]o` / `[1] password [2] private key` from the label and default. `EOFError` still returns the default.
- **Spinner.** `SPINNER_CYCLE` = `· ✢ ✳ ✶ ✻ ✽ ✻ ✶ ✳ ✢`, 120 ms, primary/shimmer alternating, one verb from `SPINNER_VERBS`. Clears with `\r\033[K`; plain mode prints one line and no CR.
- **Report.** `report._CSS` uses the same palette; status pills use dark text (`#1a1a1a`) on the role colour so every badge clears 4.5:1. Check ids wrapped in `<code class="check">`.

**Invariants (verified):**
- Plain mode (non-tty, `NO_COLOR`, `TERM=dumb`, cp1252) emits **no** escape sequences, only ASCII.
- `/help`, `/version`, `/timeout`, `/findings` plain output is byte-identical to v0.3.0.
- JSON payload identical apart from timestamps/fingerprints; no presentation data in the contract.
- 89 tests pass (`tests/test_terminal_ui.py` adds 35).

**Notes:** `_USE_COLOR` remains as a compatibility alias for `_MODE != plain`. Frames are static: no alternate screen, no raw mode, no cursor addressing, no background writes while `input()` is blocked.
