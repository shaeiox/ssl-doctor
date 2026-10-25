# Proposal

## Why

Every `/server connect` — and every `/scan` that reaches its server step — asks
again for host, port, user, authentication method, TLS target and, for password
logins, the password. Operators reconnect to the same few servers many times a
day, so these prompts are now the main friction in the tool. Remembering them
must not weaken the guarantees the SSH layer already gives: passwords never on
disk in a form the tool can read, never on a command line, never in output, and
never sent to a server whose host key is not trusted.

## What Changes

- **Server profiles.** After a successful connection the operator can save a
  named profile (host, port, user, auth method, key path, TLS target). Profiles
  are non-secret and live in `~/.ssl-doctor/profiles.json`, validated against an
  allowlisted schema and written atomically.
- **Optional saved passwords in the OS vault.** For password logins the operator
  may also save the password. It is stored only in the operating system's
  credential vault — Windows Credential Manager (through `ctypes`) or the Linux
  Secret Service (through `secret-tool`, secret on stdin). Where no vault exists
  the password is asked every time; there is no file fallback.
- **Host-key binding.** A saved password is released only after the host key has
  been verified as trusted and matches the fingerprint it was saved against. A
  changed, unknown or different key never releases it; an authentication
  failure deletes it.
- **New commands:** `/servers` (list), `/server connect <name>` (connect without
  prompts), `/server forget <name>` / `--all`, `/server forget-password <name>`.
  `/scan <domain>` offers the profile whose host or TLS target matches.
- **Consent and opt-out:** nothing is remembered before a connection succeeds;
  the pre-selected answer is *profile only*. `--no-remember` and
  `SSL_DOCTOR_REMEMBER=off` disable remembering; batch (`-c`), agents and the
  service never remember.
- **Retention:** saved passwords unused for 90 days expire; forgetting removes
  both the profile and its vault entry.
- No change for a new server: today's prompts remain, pre-filled where a
  profile exists. Not **BREAKING**.

## Capabilities

### New Capabilities
- `server-profiles`: remembering SSH server connection settings — what a
  profile holds, how it is saved, listed, used for connecting (including from
  `/scan`), and forgotten, and when remembering is offered or disabled.
- `credential-vault`: storing SSH passwords in the operating system's credential
  vault — supported backends per platform, behaviour without a vault, when a
  saved secret may be released (host-key binding), expiry, deletion, and the
  guarantee that secrets never reach disk files, command lines or output.

### Modified Capabilities
<!-- none: no existing spec covers SSH connections; agent-report redaction is
     unchanged because saved passwords are fed through the same known_secrets()
     path as typed ones. -->

## Impact

- **Code:** new `ssl_doctor/profiles.py` (profile store) and
  `ssl_doctor/vault.py` (vault interface + Windows, Secret Service and null
  backends); `ssl_doctor/cli.py` (`_server_connect`, `cmd_server`, `cmd_scan`
  server step, `/servers`, completions, `--no-remember`); `ssl_doctor/server.py`
  only exposes the presented host-key fingerprint to the connect flow.
- **Dependencies:** none added. Windows uses `ctypes` (advapi32); Linux uses the
  optional `secret-tool` program (libsecret-tools) when present.
- **Files on disk:** new `~/.ssl-doctor/profiles.json` (non-secret). Vault
  entries named `ssl-doctor:ssh:<user>@<host>:<port>`.
- **Docs:** `README.md` (remembered servers, security section), command
  references (`/servers`, `/server forget…`), `docs/execution-flow.md`,
  `CHANGELOG.md`; decision recorded in `docs/decisions/ADR-001-remembered-servers.md`.
- **Tests/CI:** vault contract tests against an in-memory fake; Windows backend
  exercised for real on the `windows-latest` job; Secret Service backend against
  a fake `secret-tool` (and the real one when a D-Bus session exists).
