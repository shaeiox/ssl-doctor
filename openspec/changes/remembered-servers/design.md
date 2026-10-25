# Design

## Context

See `proposal.md` for motivation and `docs/decisions/ADR-001-remembered-servers.md`
for the decision record and rejected alternatives. Current state that shapes the
approach:

- `cli._server_connect()` prompts host → port → user → auth → **password** →
  TLS target, *then* calls `server.host_key_status()` (trust prompt,
  `store_host_key()`), then builds `ServerSession(cfg, password)` whose
  `connect()` re-checks the key and runs `ssh … true`. `/scan` calls the same
  `_server_connect()` with no arguments.
- `HostKeyInfo` carries `status` and `ssh-keygen -l` lines
  (`256 SHA256:… host (ED25519)`), one per presented key type.
- Passwords reach `ssh` only through the askpass helper + `SSL_DOCTOR_PW`;
  `ServerSession.known_secrets()` feeds report/agent redaction.
- The CLI is standard-library only; the state directory is `~/.ssl-doctor`
  (`0700`) on every platform.

## Goals / Non-Goals

**Goals:**
- One connect pipeline for typed and remembered settings, with the vault read
  placed after host-key verification.
- Vault backends behind one small interface, each testable without the real OS
  store, and the Windows one testable for real in CI.
- No change to the trust store, askpass, redaction or report formats.

**Non-Goals:**
- macOS Keychain, the Linux kernel keyring, key passphrases, syncing profiles
  between machines, profiles for the service/agents.
- Encrypting `profiles.json` (it holds no secret by design).

## Decisions

### D1. Two modules, one boundary each
`ssl_doctor/profiles.py` (`Profile` dataclass, `ProfileStore.load/save/get/
forget/match_domain/expire`) and `ssl_doctor/vault.py` (`SecretVault` protocol:
`name`, `available() -> (bool, reason)`, `get(target, fingerprints)`,
`put(target, secret, fingerprints)`, `delete(target)`), plus `open_vault()` that
picks a backend. Not `secrets.py`: it would shadow the stdlib module.
*Alternative:* one module — rejected; profiles are plain data and must stay
usable (and testable) where no vault exists.

### D2. Windows backend: Credential Manager via `ctypes`
`advapi32.CredWriteW` / `CredReadW` / `CredDeleteW` / `CredFree` with a
`CREDENTIALW` structure: `Type=CRED_TYPE_GENERIC`, `TargetName=
ssl-doctor:ssh:<user>@<host>:<port>`, `UserName=<user>`, `CredentialBlob` = the
password as UTF-8 (cap: `CRED_MAX_CREDENTIAL_BLOB_SIZE`, 2560 bytes — longer
passwords are not saved), `Persist=CRED_PERSIST_LOCAL_MACHINE` (DPAPI per user,
not roaming like `ENTERPRISE`), `Comment=hostkey=<fp>[,<fp>…]`. Blob buffers are
overwritten after use and `CredFree` always runs. `available()` is false in the
service session and when `advapi32` cannot be loaded.
*Alternatives:* `win32cred` (pywin32 dependency in the CLI), DPAPI
`CryptProtectData` into a file (same protection, but no OS UI to inspect or
delete) — rejected.

### D3. Linux backend: Secret Service via `secret-tool`
- store: `secret-tool store --label "SSL Doctor: <user>@<host>:<port>"
  application ssl-doctor kind ssh-password target <target> hostkey <fp>` with the
  secret on **stdin**;
- lookup: `secret-tool lookup application ssl-doctor target <target> hostkey <fp>`
  once per presented trusted fingerprint — the host-key binding is enforced by
  the store's own attribute match, so a different key simply finds nothing;
- delete: `secret-tool clear application ssl-doctor target <target>`.
All calls: argv list, `shell=False`, `stdin` pipe, 10 s timeout, stderr captured
and summarised (never echoed raw). `available()` requires `secret-tool` on
`PATH`, `DBUS_SESSION_BUS_ADDRESS` set and a successful harmless `search`; any
failure → not available, with the reason shown to the operator.
*Alternatives:* a pure-Python D-Bus client (large, error-prone), `keyring`
(dependency, silent plaintext fallbacks) — rejected.

### D4. `NullVault` is a real backend, not a special case
`available()` returns `(False, reason)`; `get` returns nothing; `put` refuses.
The CLI chooses it on Linux without Secret Service, inside agents/service/batch,
and when remembering is disabled — so every caller has one code path.

### D5. Connect pipeline
`_server_connect(name=None)` becomes:
1. **settings** — from `ProfileStore.get(name)`, the recent-servers pick, the
   `/scan` domain match, or today's prompts (pre-filled from a matching profile);
   the password is *not* prompted here any more;
2. **host key** — `host_key_status()` + the existing trust prompt (unchanged);
   anything but `trusted` stops here;
3. **secret** — for password logins: `vault.get(target, trusted_fps)` when the
   profile says a password is saved; else prompt (TUI masked / `getpass`);
4. **session** — `ServerSession(cfg, password).connect()` (unchanged);
5. **outcome** — success: update `last_used`, offer to remember (first time) or
   re-save (password came from a prompt while `password_saved` was true); auth
   failure with a vault password: `vault.delete(target)`, mark profile, one
   prompt, retry once.
`server.py` gains only a helper that extracts `SHA256:` tokens from
`HostKeyInfo.fingerprints`. Moving the password prompt after the host-key check
is a deliberate improvement for typed passwords too: no secret is collected for
a host that will be refused.

### D6. Profile file format and integrity
`{"schema": 1, "profiles": [ … ]}`; field allowlist and validators in
`profiles.py`; unknown fields dropped; invalid entries skipped with a warning;
unparsable file → empty store, flagged read-only until the next explicit save
(the corrupt file is renamed to `profiles.json.bad-<timestamp>` then).
Writes: serialise fully, write `profiles.json.tmp` (`0600`), `fsync`,
`os.replace`. Read-modify-write per save so two CLI instances do not drop each
other's new profiles (last writer wins per profile).

### D7. Expiry and retention
`ProfileStore.expire(vault, now)` runs on load: a profile with `password_saved`
and `last_used` older than 90 days triggers `vault.delete` and clears the flag.
`/server forget*` always calls `vault.delete` even when the flag says no
password, so a vault entry orphaned by a crash is cleaned up.

### D8. Policy switch
`remember_enabled()` = interactive TTY session ∧ not `-c` ∧ not agent/service ∧
not `--no-remember` ∧ `SSL_DOCTOR_REMEMBER` not `off/0/no/false`. When false,
profiles may still be *read* for pre-filling only in interactive mode; the vault
is replaced by `NullVault`.

### D9. Commands and completion
`/servers`, `/server connect [name]`, `/server forget <name>|--all`,
`/server forget-password <name>` in `COMMANDS` and the help; the completion menu
offers profile names after `/server connect ` and `/server forget `. Output uses
the existing result-frame printers (no new presentation code).

## Risks / Trade-offs

- [Same-user malware can read the vault] → documented limit (ADR); `/servers`
  recommends key logins for password profiles; secrets expire after 90 days.
- [Secret Service unlock dialog blocks the shell] → 10 s timeout on every
  `secret-tool` call; on timeout the CLI falls back to the password prompt.
- [Windows CI leaves test credentials behind] → tests use a unique
  `ssl-doctor-test:<uuid>:` target prefix and delete in `tearDown`/`addCleanup`.
- [Re-ordering prompts surprises existing users] → same questions, same
  wording; only the password moves after the host-key confirmation.
- [Corrupt profile file loses servers] → never overwritten silently; renamed
  aside on the next save.
- [Long passwords on Windows] → over 2560 bytes are not saved; the operator is
  told and still connects.

## Migration Plan

Additive: new file and vault entries only; existing installs keep working with
no profiles. Rollback: `/server forget --all` before downgrading (older
versions ignore `profiles.json`; leftover vault entries are visible and
deletable in Credential Manager / Seahorse).
