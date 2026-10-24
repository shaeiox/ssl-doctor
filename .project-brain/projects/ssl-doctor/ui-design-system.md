---
project: ssl-doctor
topic: ui-design-system
tags: [ui, terminal, colour, accessibility, claude-code, cli, banner, wordmark, tui]
status: verified
trust: ai-inferred
last_done: 2026-10-24
version: 3
---

**Problem:** The CLI looked like a generic script (16-colour ANSI constants, braille spinner, bare `ssl-doctor>` prompt, flat `[PASS]/[FAIL]` wall). Long `/scan` transcripts were hard to scan and a pending question was easy to miss. v1 still opened with an anonymous clean-text line, with no product mark and no author credit.

**Solution (v2):** Applied the Claude Code TUI design language (`awesome-tui-design/designs/claude-code/DESIGN.md`) to `ssl_doctor/cli.py` + `ssl_doctor/report.py`, then added the wordmark banner (`add-modern-banner`). No diagnostic code touched.

- **Banner (`wordmark()` / `banner_lines()`).** Five-row table, seven glyphs (`S L D O C T R`) plus a word space, every stem exactly two characters wide so each letter reads as paired straight lines; `SSL DOCTOR` is 64 columns. Full form = double rule → art → blank → description → `creator: eleven · vX` → read-only note → double rule. Below `wordmark + 4` usable columns it switches to the compact form (name, description, credit). Rules are `═` / `=` and strokes `█` / `#`; nothing exceeds the terminal width.
- **Roles, not codes.** `ROLES` maps 12 semantic roles to `(truecolor rgb, 256 index, 16 SGR)`; `paint(text, role, bold, dim)` is the only colour entry point. `resolve_color_mode()` picks one level: `NO_COLOR` → `SSL_DOCTOR_COLOR` → tty → `TERM=dumb` → Windows VT → `COLORTERM` → `TERM` → 16. `set_color_mode()` re-resolves (tests, embedding).
- **Glyphs.** `Glyphs` holds `✓✗⚠▸•·?` with `+x!> -?` fallbacks, plus `h`/`double`/`block`/`vert`/`corner()` for frames and the banner. `resolve_glyphs()` tests the stream encoding (not the platform), so a cp1252 console never sees an unencodable character.
- **One frame per command.** `execute()` calls `set_block_label(line)`; `print_findings()` draws `┌─ <command> ─┐`, one row per finding (`glyph status check title`), nested evidence/detail/`fix:` (wrapped, never elided), and `└─ counts ┘`. Below 40 usable title columns the title drops to its own line.
- **Questions are lavender.** `prompt()` keeps its signature and answer sets; `_answer_hints()` derives `[Y]es [N]o` / `[1] password [2] private key` from the label and default. `EOFError` still returns the default.
- **Spinner.** `SPINNER_CYCLE` = `· ✢ ✳ ✶ ✻ ✽ ✻ ✶ ✳ ✢`, 120 ms, primary/shimmer alternating, one verb from `SPINNER_VERBS`. Clears with `\r\033[K`; plain mode prints one line and no CR.
- **Report.** `report._CSS` uses the same palette; status pills use dark text (`#1a1a1a`) on the role colour so every badge clears 4.5:1. Check ids wrapped in `<code class="check">`.

- **Full-screen shell (`ssl_doctor/tui.py`, v3).** Interactive start enters the alternate screen and draws one composed frame: centred column `min(columns-2, 96)`, header (wordmark or compact), output panel with scrollback, status line, command bar, key hints. `build_frame()` is pure (size + spans in, exact lines + cursor cell out), so layout is tested without a terminal. `Transcript` wraps to panel width and scrolls; `CaptureStream` turns command stdout into panel lines (`_CAPTURE` makes `paint()` a no-op and `print_findings()` use plain rows, so the panel — not a box — is the frame). `KeyReader` enters raw mode for one keystroke only (ISIG kept), decoding arrows/PgUp/Home/End/Ctrl keys; `TuiSession` adds command-bar editing, history, masked password entry and a status-line spinner ticker. `tui.enabled()` gates on tty + platform + `SSL_DOCTOR_TUI` + `--no-tui`; everything else runs the old line REPL.

**Invariants (verified):**
- Plain mode (non-tty, `NO_COLOR`, `TERM=dumb`, cp1252) emits **no** escape sequences and only ASCII, banner included.
- `creator: eleven` appears at every width and in every mode; no flag hides it.
- `/version`, `/help`, `/timeout`, `/findings`, `/tls`, `/cert inspect` output is unchanged apart from the banner and the earlier glyph substitutions; exit codes identical.
- JSON payload identical apart from timestamps/fingerprints; no presentation data in the contract.
- 134 tests pass (`tests/test_terminal_ui.py` 43, `tests/test_tui.py` 37).
- `-c` batch output, redirected output and `--no-tui` are untouched; the shell never runs unless both stdin and stdout are terminals.

**Notes:** `_USE_COLOR` remains as a compatibility alias for `_MODE != plain`. Frames are static: no alternate screen, no raw mode, no cursor addressing, no background writes while `input()` is blocked. Banner art is the only decorative element; the design system's "no ASCII art" rule was narrowed to "no art outside the startup banner".
