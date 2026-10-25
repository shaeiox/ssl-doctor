# Proposal

## Why

SSL Doctor's output appears all at once, which feels abrupt and gives no sense of
progress while long scans run. A typewriter effect — printing characters
gradually with a configurable speed — would make the CLI feel more alive and
give a visual cue that work is happening, while staying opt-in so scripted and
piped usage remain fast and machine-readable.

## What Changes

- New CLI output mode: print text character-by-character with a configurable
  delay (characters per second), applied to all CLI output on a terminal.
- A `/typewriter [on|off|speed <cps>]` command to toggle the effect and set
  its speed at runtime; default off, default speed 40 cps.
- A `--typewriter` / `--typewriter-speed` startup flag for one-shot enabling.
- The effect is automatically disabled when stdout is not a tty or in batch
  mode (`-c`), so piped/redirected output stays fast and byte-identical.
- A shared output helper routes all `print`/finding/diagnosis output through
  the typewriter when enabled, so no command needs per-site changes.

## Capabilities

### New Capabilities
- `cli-typewriter-effect`: the interactive CLI can render its output with a
  configurable character-by-character typewriter animation, toggled at runtime
  or via flags, and automatically disabled in non-interactive mode.

### Modified Capabilities
- None. `cli-findings-streaming` is unaffected; streaming and typewriter
  compose (streamed findings can be typed out as they arrive).

## Impact

- **Code:** `cli.py` (output helper, `/typewriter` command, flags, tty gating);
  possibly a small shared writer used by `print_finding`/`print_findings`.
- **Tests:** add tests for toggle, speed, and non-tty auto-disable.
- **Dependencies:** none new — stdlib only.
- **Security:** unchanged.
