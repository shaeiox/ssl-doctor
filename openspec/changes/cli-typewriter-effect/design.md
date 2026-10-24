# Design

## Context

The CLI prints via `print()` and `print_finding()`/`print_findings()` in
`cli.py`. There is no central writer, so a typewriter effect needs a single
chokepoint. See `proposal.md` for motivation and `specs/...` for requirements.

## Goals / Non-Goals

**Goals:**
- Render all CLI output character-by-character at a configurable rate when
  enabled.
- Provide runtime toggle and speed configuration.
- Auto-disable outside an interactive terminal or in batch mode.

**Non-Goals:**
- Changing findings contract, diagnosis, or streaming behavior.
- Animating the service/agent side.

## Decisions

### D1: Central `_write` helper
Route all output through `self._write(text)` which, when typewriter mode is
enabled, prints char-by-char with `time.sleep(1/cps)` and flushes; otherwise
uses normal `print`. `out()`, `error()`, `note()`, `print_finding`, and
`print_findings` call `_write`.

### D2: State stored on CLI instance
`self._typewriter_enabled` (bool) and `self._typewriter_cps` (float). Default
off, 40 cps. `/typewriter` command mutates these. Startup flags set them
before the REPL starts.

### D3: tty/batch gating
`_typewriter_active` property returns `enabled and stdout.isatty() and not batch_mode`.
Even if enabled by flag, inactive outside tty.

### D4: Speed floor
Clamp cps to a minimum (e.g., 1) to avoid division by zero / huge delays.

## Risks / Trade-offs

- [Slow output] → Default off; user opts in. Cap minimum delay.
- [Tests timing] → Tests disable typewriter; use fast speeds.

## Migration Plan

Additive. No breaking change.

## Open Questions

None.
