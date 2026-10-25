# Proposal

## Why

The v0.4 interface treats the startup banner as clean text — a title, one line of
description and a note. It is honest but anonymous: nothing marks the tool as a
designed product, and the author credit is missing entirely.

The tool deserves a front door. A modern, compact wordmark built from
two-character-wide strokes (so each stem reads as a pair of straight lines),
framed by double rules, carries the app name, what it does, the version, the
read-only guarantee and the creator credit in about ten lines — and degrades to
plain ASCII and to a narrow-terminal form without changing a single command.

## What Changes

- **A wordmark banner on startup**: double rule → five-row block wordmark
  spelling `SSL DOCTOR` → description → version → read-only note →
  `creator: eleven` → closing double rule.
- **Width-aware**: the full wordmark is used when it fits; narrower terminals get
  a compact three-line form with the same information, never clipped.
- **Theme-aware**: rules and wordmark in the primary role, description and note
  muted, creator credit in the accent role. Plain mode uses `#` and `=`
  exclusively and emits no escape sequences.
- **Nothing else changes**: `/version`, `/help`, every command, every finding,
  the exit codes, the report and the findings contract are untouched.

## Capabilities

### New Capabilities
- None.

### Modified Capabilities
- `terminal-interface`: the "no ASCII-art banner" clause of `warm-terminal-ui`
  no longer applies to the startup banner, and the banner requirement is
  replaced by the wordmark/credit requirements below. The
  `warm-terminal-ui` delta is amended in place because it is not yet archived.

## Impact

- **Code:** `ssl_doctor/cli.py` only — a wordmark table, `banner_lines()` and
  `SSLDoctorCLI.banner()`. No other module.
- **Tests:** `tests/test_terminal_ui.py` gains banner coverage (full, compact,
  plain, coloured, width invariant); the one assertion that expected the old
  banner text is updated.
- **Docs:** README "Terminal look" shows the banner; CHANGELOG gains an entry;
  the Project Brain `ui-design-system` topic records the wordmark.
- **Compatibility:** the banner is the only changed output. `-c` batches keep
  their exit codes; no command output, report field or contract value moves.
- **Out of scope:** branding inside the HTML report, the agent's stdout, a
  `--no-banner` flag, and any configurable credit.
