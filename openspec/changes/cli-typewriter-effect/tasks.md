# Tasks

## 1. Core typewriter writer

- [x] 1.1 Add `_typewriter_enabled`, `_typewriter_cps` state and `_typewriter_active` property to `SSLDoctorCLI`; verify defaults (off, 40 cps) and non-tty auto-disable.
- [x] 1.2 Implement `_write` helper that types characters when active else prints normally; route `out`, `error`, `note`, `print_finding`, `print_findings` through it; verify identical final text.
- [x] 1.3 Add speed clamping (min 1 cps) and flush handling; verify no ZeroDivisionError.

## 2. Runtime command and flags

- [x] 2.1 Implement `/typewriter [on|off|speed <cps>]` command with validation; verify toggle and speed changes and invalid-arg error.
- [x] 2.2 Add `--typewriter` and `--typewriter-speed` startup flags in `main()`; verify one-shot enable.

## 3. Tests and verification

- [x] 3.1 Add tests for toggle, speed, non-tty auto-disable, and byte-identical output.
- [x] 3.2 Run the full test suite and confirm all tests pass.

## Workflow follow-up

- Archive the change after review requirements are satisfied.
- Verify the archived result.
