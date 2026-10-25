# Tasks

## 1. Path resolution core (`ssl_doctor/nginx_discovery.py`)

- [ ] 1.1 Add `conf_prefix(discovery)` and `resolve_cert_path(value, conf_prefix)` per D1/D3 (absolute unchanged, relative under the configuration prefix, `$…` / `data:` → not resolvable); verify with tests for the custom install (`-p /opt/pvm/nginx/ -c conf/nginx.conf` → `/opt/pvm/nginx/conf/ssl/fullchain.pem`), main config at the prefix root (→ `/opt/pvm/nginx/ssl/fullchain.pem`), prefix ≠ configuration directory, absolute paths, variables and `data:`
- [ ] 1.2 Directive provenance per D2 (`file:line`, "inherited from http{}", "line unknown"); verify with a nested-include graph and an `http{}`-level key
- [ ] 1.3 `discover()` accepts `conf_override` / `prefix_override` per D9 (operator-specified label, runtime-associated only when equal to the runtime-resolved main config); verify with a no-master host and with a master whose `-c` differs from the override

## 2. File states and gated validation (`ssl_doctor/server.py`)

- [ ] 2.1 Probe primitive `file_states(paths)` (D4) in `_SshNginxProbe` and the in-memory host; verify the real script under `/bin/sh` for readable, missing, not-a-file, unreachable parent and unsafe paths (denied skipped when running as root)
- [ ] 2.2 `nginx.path_resolution` finding (D6): configured value, provenance, resolved path, method, state, origin; status rules; prefix-relative observation (D5); `/server config set` recommendation in automatic mode; verify the brief's regression (`ssl/fullchain.pem` + `ssl/private.key`), missing certificate, missing key, root-only key, and the prefix-relative file
- [ ] 2.3 Gate `nginx.chainfile`, `srv.cert`, `srv.keymatch` on the file states (NOT TESTED with the reason; invalid PEM FAIL distinct from incomplete chain); verify missing file → NOT TESTED (not FAIL), invalid PEM, leaf-only chain, unreadable key → pairing NOT TESTED
- [ ] 2.4 `/server cert <file> [key]` checks file states first; verify missing and unreadable paths give NOT TESTED, and an existing valid file behaves as before (existing tests)
- [ ] 2.5 Contract 1.6: `SCHEMA_VERSION`, `schemas/findings-1.6.schema.json`, `CHECK_IDS["nginx.path_resolution"]`, docs table; update version assertions; verify `tests/test_contract.py`, `tests/test_agent_report.py` and a document from a custom-install scan validate

## 3. Per-server settings (`ssl_doctor/profiles.py`, `ssl_doctor/server.py`)

- [ ] 3.1 Profile fields `nginx_mode`, `nginx_cert`, `nginx_key`, `nginx_conf`, `nginx_prefix` with validation (D8) and per-field drop-with-warning on load; verify round trip, invalid values refused, an invalid stored value dropped while the profile is kept, and old files without the fields loading as `auto`
- [ ] 3.2 `NginxSettings` on the session and its use in `nginx_scan` (manual paths validated, discovery still runs, disagreement reported, failing manual path kept) and in `discover_nginx` (overrides; cache invalidated on change); verify manual-only (discovery fails), manual vs automatic disagreement, and overrides

## 4. Commands and reuse (`ssl_doctor/cli.py`)

- [ ] 4.1 `/server config show|set|clear [name]` with target selection, flags and prompts, validation, `_persist()`, session-only fallback, bare `/server config` unchanged; verify set while connected, set for a named server while disconnected, set for an unremembered server (remember vs session-only), clear → auto, show output, invalid relative path refused
- [ ] 4.2 Load settings on connect (profile → session) with a note; verify reconnect after a simulated restart (new CLI, same store) uses saved paths with no prompt, server B does not inherit server A's paths, saved password still used, password expiry keeps the settings, updating A leaves B unchanged, no password in `profiles.json`
- [ ] 4.3 Help rows, completion (`show|set|clear`, profile names) and the batch path (`-c "/server config set web --cert …"` → session-only message when remembering is off); verify with `command_completions` and a batch run

## 5. Documentation and integration

- [ ] 5.1 Document the resolution rule (with the nginx source reference), the new finding, the commands and precedence in README, `docs/command-used.md`, `docs/execution-flow.md`, `docs/findings-contract.md`, CHANGELOG (incl. the older-version profile note) and an ADR-001 implementation note; verify documented commands match `/help`
- [ ] 5.2 Run the full suite and verify it passes; run a before/after comparison for the regression configuration and record it
- [ ] 5.3 Update the project brain (topics `server-ssh-nginx`, `remembered-servers`; decision: conf_prefix rule over prefix) and verify `brain-check` passes

## Workflow follow-up

- Archive the change with `/openspec-archive-change` after review.
- Merge to `master`, bump the version and push, as for previous changes.
