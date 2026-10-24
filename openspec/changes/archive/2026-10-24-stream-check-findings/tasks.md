# Tasks

## 1. Emit-hook plumbing in check modules

- [x] 1.1 Add optional `emit` parameter to `netchecks.run_remote_diagnostics` and route every `out.append(...)` through a helper that appends and calls `emit(f)` when provided; verify unit test passes finding count parity for a sample host.
- [x] 1.2 Add the same `emit` hook to `certs.inspect_cert_file` and `certs.match_cert_key`; verify each finding is delivered when a hook is supplied and none when it is not.
- [x] 1.3 Add the `emit` hook to `local.run_local_for_remote`; verify parity between streamed and returned findings.
- [x] 1.4 Add the `emit` hook to `ServerSession.overview`, `webserver_detection`, `nginx_scan`, `scan_cert`, `tls_config_scan`, `log_scan`, and `compare_configured_vs_presented`; verify each emits in production order.
- [x] 1.5 Keep `emit=None` as the default in every changed function and verify existing agent/service callers (no emit) still return identical results.

## 2. CLI streaming mode and phase runner

- [x] 2.1 Add `_STREAM_OUTPUT` flag (tty and not batch mode) and `_BATCH_MODE` tracking in `SSLDoctorCLI`/`main`; verify flag is False when stdout is piped.
- [x] 2.2 Implement `_emit_finding` (print + flush) and `_run_phase(text, fn, *args, **kwargs)` branching between streaming (gray progress line + emit) and buffered (Spinner + print_findings); verify both paths produce identical finding output for a recorded fixture.
- [x] 2.3 Ensure interrupted scans (KeyboardInterrupt) leave already-emitted findings visible and return to the prompt; verify manually with a slow target.

## 3. Convert commands to streamed output

- [x] 3.1 Convert `_gather_remote` to use `_run_phase` for the remote diagnostics; verify `/tls` streams findings on a tty.
- [x] 3.2 Convert `cmd_cert` (inspect and match) to use `_run_phase`; verify findings stream.
- [x] 3.3 Convert `cmd_local` to use `_run_phase`; verify findings stream.
- [x] 3.4 Convert `_scan_server_side` (identity, nginx scan, log scan) to use `_run_phase`; verify findings stream per sub-phase.
- [x] 3.5 Convert `/server` subcommands (overview, nginx, cert, config, logs, compare) to use `_run_phase`; verify findings stream.

## 4. Tests and verification

- [x] 4.1 Add a parity test asserting streamed output equals buffered output for `/scan` against the TLS test fixture.
- [x] 4.2 Add a test asserting non-tty (piped) invocation keeps buffered output and exit code 1 on FAIL diagnosis.
- [x] 4.3 Add a regression test calling a check module without `emit` and asserting no console output and identical return value.
- [x] 4.4 Run the full test suite (`python -m pytest`) and confirm all tests pass.

## Workflow follow-up

- Archive the change after review requirements are satisfied.
- Verify the archived result.
