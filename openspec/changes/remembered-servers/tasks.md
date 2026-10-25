# Tasks

## 1. Profile store (`ssl_doctor/profiles.py`)

- [ ] 1.1 Add the `Profile` dataclass and field validators (name charset, port 1–65535, auth `password|key`, host, username, key path, TLS target, `password_saved`, fingerprints, ISO timestamps, `schema: 1`); verify with unit tests that valid profiles round-trip and each invalid value is rejected
- [ ] 1.2 Add `ProfileStore.load()` that drops unknown fields, skips invalid entries with a warning and treats an unparsable file as an empty, read-only store; verify with tests for an injected `proxy_command` field, a bad port, and a non-JSON file that is left untouched
- [ ] 1.3 Add atomic `save()` (serialise fully, `profiles.json.tmp` at `0600`, `fsync`, `os.replace`, read-modify-write per profile; corrupt file renamed to `profiles.json.bad-<timestamp>` on the next explicit save); verify with tests for file mode on POSIX, a simulated failure between write and replace leaving the old file intact, and two stores saving different profiles without losing either
- [ ] 1.4 Add `get(name)`, `closest(name)`, `recent(n)`, `match_domain(domain)` (TLS target first, then host) and `forget(name)`; verify with unit tests for each lookup, including no match

## 2. Credential vault (`ssl_doctor/vault.py`)

- [ ] 2.1 Define the `SecretVault` interface (`name`, `available() -> (bool, reason)`, `get(target, fingerprints)`, `put(target, secret, fingerprints)`, `delete(target)`), the `ssl-doctor:ssh:<user>@<host>:<port>` target builder, `NullVault`, and an in-memory fake; write the shared contract tests (put/get/delete, missing entry, wrong fingerprint returns nothing, `put` refused when unavailable) and verify they pass for the fake and `NullVault`
- [ ] 2.2 Implement the Windows Credential Manager backend over `ctypes` (`CredWriteW`/`CredReadW`/`CredDeleteW`/`CredFree`, `CRED_TYPE_GENERIC`, `CRED_PERSIST_LOCAL_MACHINE`, UTF-8 blob ≤ 2560 bytes, fingerprints in `Comment`, buffers cleared, `CredFree` always called); verify with the contract tests running for real on the `windows-latest` CI job using a `ssl-doctor-test:<uuid>:` prefix cleaned up after each test, and skipped elsewhere
- [ ] 2.3 Implement the Secret Service backend over `secret-tool` (store with the secret on stdin, lookup per fingerprint via the `hostkey` attribute, clear; argv lists, `shell=False`, 10 s timeout, stderr summarised); verify with the contract tests against a fake `secret-tool` on `PATH` that fails the test if the secret ever appears in its argv, plus a real run skipped unless `secret-tool` and `DBUS_SESSION_BUS_ADDRESS` are present
- [ ] 2.4 Add `open_vault(policy)` choosing Windows / Secret Service / `NullVault` (service session, agents, batch, disabled remembering, missing tools → `NullVault` with a reason); verify with tests for each selection branch using injected platform and environment
- [ ] 2.5 Add `ProfileStore.expire(vault, now)` deleting saved passwords unused for 90 days and clearing `password_saved`; verify with tests at 89 and 91 days using the fake vault

## 3. Connect pipeline (`ssl_doctor/cli.py`, `ssl_doctor/server.py`)

- [ ] 3.1 Add a helper that extracts `SHA256:` fingerprints from `HostKeyInfo.fingerprints`; verify with unit tests on real `ssh-keygen -l` line shapes (ED25519, ECDSA, RSA, `[host]:port`)
- [ ] 3.2 Split `_server_connect()` into settings → host key → secret → session → outcome, moving the password prompt after a `trusted` host key; verify with scripted-prompt tests that a changed or unknown-and-declined key never prompts for the password and never reads the vault, and that the existing first-connect flow still asks the same questions
- [ ] 3.3 Read the saved password only when the host key is trusted and matches a saved fingerprint; on mismatch prompt and offer re-save; on authentication failure with a vault password delete it, tell the operator, prompt once and retry once; verify with tests using fake `ServerSession` and fake vault for the changed-key, re-trusted-key, edited-profile-host and rejected-password scenarios in `specs/credential-vault/spec.md`
- [ ] 3.4 After a successful first connection offer *profile only* (pre-selected) / *save password too* (password login with an available vault only) / *no*, then update `last_used` on later connections; verify with tests for key login (no password choice), unavailable vault (reason shown), and that a failed connection saves nothing
- [ ] 3.5 Pre-fill the prompts from a profile when the typed host matches one; verify with a scripted-prompt test that defaults equal the saved values
- [ ] 3.6 Add `remember_enabled()` (`--no-remember`, `SSL_DOCTOR_REMEMBER=off`, `-c`, agents, service) and wire it to `open_vault`; verify with tests that batch `-c "/server connect files"` neither asks to remember nor reads the vault
- [ ] 3.7 Show the password source ("password from Windows Credential Manager" / "… Secret Service") without value or length; verify with a transcript assertion

## 4. Commands, `/scan` and completion

- [ ] 4.1 Add `/servers` (frame with name, `user@host:port`, auth, password saved, last used, key-login advice for password profiles; empty-state message); verify with output tests in plain and framed modes that no secret is printed
- [ ] 4.2 Add `/server connect <name>` and the recent-servers pick for `/server connect` with no argument, plus the unknown-name message with closest names; verify with scripted tests for each scenario in `specs/server-profiles/spec.md`
- [ ] 4.3 Make `/scan <domain>` offer `match_domain(domain)` at its server step before the prompts; verify with a scripted `/scan` test that an accepted profile connects without connection prompts and a declined one falls back to them
- [ ] 4.4 Add `/server forget <name>`, `/server forget --all` (explicit confirmation) and `/server forget-password <name>`, always calling `vault.delete`; verify with tests that both profile and vault entry are removed and that an unconfirmed `--all` deletes nothing
- [ ] 4.5 Add the new commands to `COMMANDS`, `/help` and the completion menu (profile names after `/server connect ` and `/server forget `); verify with `command_completions()` tests

## 5. Security regression and documentation

- [ ] 5.1 Add end-to-end leak tests: connect with a saved password through the fake vault, then `/copy all`, `/report both` and `/report agent`, and assert the password appears in no transcript line, copied text or written file, and in no recorded subprocess argv
- [ ] 5.2 Document remembered servers in `README.md` (commands table, security section incl. vault per platform, headless behaviour, `--no-remember`, `SSL_DOCTOR_REMEMBER`), `docs/execution-flow.md` (new connect pipeline), both command inventories (`secret-tool` calls) and `CHANGELOG.md` Unreleased; verify the documented commands match `/help` and the documented `secret-tool` argv matches the code
- [ ] 5.3 Update ADR-001 status to Accepted (or record changes made during implementation) and the project-brain topic; verify `brain-check` passes

## 6. Integration

- [ ] 6.1 Run the full suite (`python -m unittest discover -s tests`) and verify it passes on Linux and on the `windows-latest` CI job
- [ ] 6.2 Manually verify on a Linux desktop (GNOME Keyring) and on Windows: save a password for a real server, reconnect without prompts, see the entry in Seahorse / Credential Manager, `/server forget` it and confirm the entry is gone

## Workflow follow-up

- Archive the change with `/openspec-archive-change` after review and the manual checks in 6.2.
- Merge to `master`, bump the version and push, as for previous changes.
