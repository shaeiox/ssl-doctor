# ADR-001: Remembered servers — profiles on disk, passwords only in the OS vault

- **Status:** Accepted (2026-10-25; implemented on `feat/remembered-servers`)
- **Deciders:** eleven (owner)
- **Change:** `openspec/changes/remembered-servers/`

## Context

Every `/server connect` (and every `/scan` that reaches the server step) asks
again for the host, port, user, authentication method, TLS target and — for
password logins — the password. Operators reconnect to the same few servers many
times a day, so the prompts are the main friction in the tool.

Constraints that shape the answer:

- **The CLI is standard-library only.** `pywin32` is used by the Windows service,
  not by the CLI; `requirements.txt` is not needed to run it.
- **It runs on Windows and Linux**, interactively (full-screen shell or line
  REPL) and headless (scan agents, `-c` batch, the Windows service).
- **Existing security properties must hold:** passwords never on a command line
  (askpass + environment), never displayed or written to the transcript or
  reports (`known_secrets()` redaction), host keys verified against
  `~/.ssl-doctor/known_hosts` before any authentication, changed keys refused.
- **Threat to design against:** a saved password is only safe if it can never be
  handed to the wrong server (DNS hijack, man-in-the-middle, an edited profile),
  never leaks through output, and never sits on disk in a form the tool itself
  can decrypt.

## Decision

Split what is remembered into two stores with different protection:

1. **Server profiles are non-secret and live in `~/.ssl-doctor/profiles.json`**
   (`0600` inside the `0700` state directory on POSIX; the user-profile ACL on
   Windows). A profile holds name, host, port, username, auth method, key path,
   TLS target, `password_saved` hint, the host-key fingerprint at save time,
   created/last-used timestamps and a schema version. The file is written
   atomically (temp + `os.replace`), read against an allowlisted schema
   (unknown fields dropped, invalid file ignored with a warning) and never holds
   raw `ssh` options, so it cannot inject `ProxyCommand` or similar.
2. **Passwords live only in the operating system's credential vault**, behind a
   `SecretVault` interface (`available`, `get`, `put`, `delete`):
   - **Windows:** Credential Manager, generic credential, `CRED_PERSIST_LOCAL_MACHINE`
     (DPAPI-protected per user, does not roam), through `ctypes`
     (`CredWriteW`/`CredReadW`/`CredDeleteW`/`CredFree`).
   - **Linux desktop:** Secret Service (GNOME Keyring, KWallet) through
     `secret-tool`, the secret passed on stdin and read from stdout, never argv.
   - **No vault available** (headless Linux, SSH sessions, agents, service):
     `NullVault` — profiles are remembered, the password is asked every time.
   Entries are named `ssl-doctor:ssh:<user>@<host>:<port>` and carry the host-key
   fingerprint they were saved against.
3. **Connect order is security-critical:** load profile → verify the host key →
   compare it with the fingerprint the password was saved against → only then
   read the vault → existing askpass → `ssh`. A changed or unknown key stops the
   connection before the vault is read; a key that differs from the saved
   fingerprint makes the saved password stale (asked again, offered for
   re-save). An authentication failure deletes the saved password, so a stale
   secret never retries into a lockout.
4. **Consent:** nothing is remembered until a connection has succeeded; the
   operator then chooses *profile only* (default), *save password too*, or *no*.
   Key logins remember only the key path; passphrases stay with
   `ssh-agent`/Pageant. `--no-remember` / `SSL_DOCTOR_REMEMBER=off` disable the
   offer, and it is always off for agents, batch and service runs.
5. **Lifecycle:** `/servers` lists profiles (never secrets); `/server connect
   <name>` connects without prompts; `/server forget <name>`, `/server forget
   --all` and `/server forget-password <name>` delete. Saved passwords unused for
   90 days expire.

### Defaults (accepted with the change)

| Question | Proposed default |
|---|---|
| Answer pre-selected by "Remember this server?" | profile only; saving the password is opt-in |
| Linux without a Secret Service | ask every time (`NullVault`); no session-keyring cache |
| Expiry of unused saved passwords | 90 days |
| macOS Keychain | out of scope for this change (later: `security -i` over stdin) |

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Plaintext or "obfuscated" password file | Anyone or anything that reads the file has the password. |
| Password file encrypted by the tool (master passphrase) | The standard library has no authenticated encryption; it would need a crypto dependency or a home-made cipher, and adds a second secret to remember. |
| The `keyring` package | A dependency in a stdlib-only CLI, and its fallback backends can store plaintext silently. |
| `pywin32` `win32cred` on Windows | Already present for the service, but would make the CLI depend on it; `ctypes` reaches the same API. |
| Linux kernel keyring (`keyctl`) as fallback | Lives only for the login session and is not available everywhere; deferred, possibly as an opt-in later. |
| Store secrets in the profile file encrypted with DPAPI (`CryptProtectData`) on Windows | Workable, but Credential Manager gives the same protection plus a UI where the operator can see and delete entries. |
| Remember the password by default | Saving a secret should be a deliberate choice; most value comes from the profile alone. |

## Consequences

- **Good:** reconnecting to a known server is one command and no prompts (when
  the password is saved) or one password prompt (profile only). No new runtime
  dependency. Secrets are protected by the OS, inspectable and removable with OS
  tools, and bound to the host key, so a hijacked name or edited profile cannot
  harvest them.
- **Cost:** two vault backends to maintain and test (the Windows one runs for
  real on the `windows-latest` CI job; the Linux one is tested against a fake
  `secret-tool` and against the real one when a D-Bus session is available).
- **Limits:** malware running as the same OS user can ask the vault for the
  password, as it could read SSH keys; for high-value servers key-based login
  with an agent remains the recommendation, and `/servers` says so for password
  profiles. Headless Linux gets no password caching.
- **Compatibility:** existing prompts stay as the path for a new server; the
  trust store, askpass helper and redaction are unchanged.

## Implementation notes (2026-10-25)

Recorded while implementing; none changes the decision.

- The profile stores **all** `SHA256:` fingerprints the trusted server
  presented (`hostkey_fingerprints`, up to 8), not one; any match releases the
  password, as any matching key type makes the host trusted.
- Windows keeps the fingerprints in the credential's `Comment`
  (`hostkey=<fp>,<fp>`); the Secret Service keeps one item per fingerprint
  with a `hostkey` attribute, so the keyring's own attribute match enforces
  the binding.
- Profile values that `ssh` would read as an option (a leading `-` in host,
  user or key path) are rejected on load, in addition to the field allowlist.
- Every interactive `/scan` asks which server to use (current session,
  remembered servers with domain matches first, or new; Enter = most likely),
  so an open session is never reused silently for another domain. A new
  connection replaces the current session only once it is up.
- Windows passwords longer than 2560 bytes (the Credential Manager limit) are
  not saved; the operator is told and still connects.

## Addendum (2026-10-25): per-server nginx settings

Openspec change `nginx-cert-path-resolution` extends the profile with
`nginx_mode` (`auto` | `manual`), `nginx_cert`, `nginx_key`, `nginx_conf` and
`nginx_prefix` — paths only, validated as untrusted input (absolute, safe
characters), never secrets. They live with the connection settings in
`profiles.json` and follow the profile's lifecycle, not the password's: a
saved password's expiry or `/server forget-password` leaves them in place;
`/server forget` removes them with the profile. The decision itself is
unchanged.

