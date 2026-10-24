# Design

## Context

The CLI is a single Python package (`ssl_doctor/cli.py` plus check modules
`netchecks.py`, `certs.py`, `local.py`, `server.py`). Today every check
function builds a `List[F.Finding]` internally and returns it whole; the CLI
wraps each call in a `Spinner`, then calls `print_findings(items)`. There is
no incremental delivery path. See `proposal.md` for motivation.

## Goals / Non-Goals

**Goals:**
- Deliver each finding to the terminal as soon as its check produces it, in
  interactive (tty) mode.
- Keep check modules' return contracts intact so agents and the service are
  unaffected.
- Preserve buffered output and exit codes in non-interactive / batch mode.

**Non-Goals:**
- Changing the findings contract, diagnosis, or service/agent protocol.
- Adding async/concurrency to checks (they stay sequential).
- Streaming raw network bytes or LLM tokens (no LLM in this codebase).

## Decisions

### D1: Optional `emit` callback on check functions
Check functions (`run_remote_diagnostics`, `inspect_cert_file`,
`match_cert_key`, `run_local_for_remote`, and `ServerSession` methods) gain an
optional `emit: Optional[Callable[[F.Finding], None]] = None` parameter.
Internally, every `out.append(f)` becomes a small helper that appends AND calls
`emit(f)` when provided. Return value is unchanged.

- *Why over alternatives:* Threading a callback is the smallest change that
  keeps return contracts and lets the CLI decide how (or whether) to render.
  Alternatives considered: generators (would change every caller and the
  agent/service), or post-hoc chunking (defeats the purpose).

### D2: Streaming gated on tty + interactive mode
A single flag `_STREAM_OUTPUT = sys.stdout.isatty() and not _BATCH_MODE` (batch
mode is set when `-c` is used or stdin is not a tty) decides the path. In
streaming mode the CLI passes `emit=self._emit_finding`; in buffered mode it
passes `emit=None` and calls `print_findings(items)` as today.

### D3: Spinner replaced by a single progress line in streaming mode
In streaming mode a phase prints one gray line (`… <phase text>`) at start and
then streams findings; the animated `Spinner` is not used, avoiding `\r`
conflicts with incremental output. In buffered mode the `Spinner` is retained.

- *Why:* Interleaving spinner animation with printed lines produces garbled
  output. A static progress line is simpler and still signals activity.

### D4: Centralized phase runner in the CLI
A helper `_run_phase(text, fn, *args, **kwargs)` encapsulates the
streaming/buffered branching so every command site stays consistent and the
spinner/emit logic lives in one place.

### D5: Emit callback flushes
`_emit_finding` calls `print_finding(f)` then `sys.stdout.flush()` so output
appears promptly even when stdout is block-buffered.

## Risks / Trade-offs

- [Missed append site] → A check that appends without calling emit would stream
  incompletely. Mitigation: mechanical conversion plus a parity test comparing
  streamed vs. buffered output for the same input.
- [Double printing] → If both emit and a trailing `print_findings` run. Mitigation:
  strict branching in `_run_phase`; never both.
- [Regression in agent/service] → They call check functions without emit.
  Mitigation: `emit` defaults to `None`, preserving current behavior; add a
  regression test invoking without emit.

## Migration Plan

Additive and backward compatible. No data migration. Rollback is a revert of
the change; no persistent state depends on it.

## Open Questions

None.
