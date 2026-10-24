# Proposal

## Why

The interactive CLI currently buffers every finding for a phase and dumps them all at
once when the phase completes. During long scans (network checks with up to 8s
timeouts, SSH commands, multi-step `/scan` flows) the user stares at a spinner and
gets no feedback until everything is done. Surfacing each finding as its check
finishes gives immediate, progressive feedback and makes long scans far easier to
follow and interrupt.

## What Changes

- New CLI output behavior: print each finding as soon as its check completes,
  instead of buffering the whole phase and dumping it at the end.
- Spinner handling: keep the spinner for indeterminate work, transition to
  incremental line output once findings start arriving (tty only).
- Affected commands: `/scan` (all phases), `/tls`, `/cert`, `/local`,
  and `/server *` subcommands.
- Check modules (`netchecks`, `certs`, `local`, `server`) gain optional emit
  hooks so findings can be streamed without breaking their existing
  return-value contracts.
- Batch / non-interactive mode (`-c`, piped or non-tty stdout) keeps the
  current buffered output so exit codes and machine-readable behavior stay
  stable.
- No change to the findings contract, diagnosis, or service/agent protocol.

## Capabilities

### New Capabilities
- `cli-findings-streaming`: the interactive CLI surfaces each finding to the
  terminal as its check completes, with progressive feedback during long scans,
  while preserving buffered output in non-interactive mode.

### Modified Capabilities
- None. There are no existing specs in `openspec/specs/`.

## Impact

- **Code:** `cli.py` (output/streaming logic and spinner transition),
  `netchecks.py`, `certs.py`, `local.py`, `server.py` (optional emit hooks).
- **Tests:** `tests/test_scan_e2e.py` may need output expectations updated;
  add unit tests for the streaming/emit helper and tty-vs-piped gating.
- **Dependencies:** none new — stdlib only, consistent with the CLI's
  standard-library-only constraint.
- **Security:** unchanged — read-only checks, no credentials logged.
