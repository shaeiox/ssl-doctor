# SSL Doctor — Program Execution Flow

This document follows SSL Doctor from process start to process exit: entry
points, argument handling, the command loop, what each command does internally,
how findings become a diagnosis and a report, and how the session shuts down.
File names are included at every step.

Version covered: `0.10.0` (`ssl_doctor/__init__.py`).

---

## 1. High-level shape

SSL Doctor has three executable surfaces that share the diagnostic library:

| Surface | Entry point | Purpose |
|---|---|---|
| Interactive / batch CLI | `ssldoctor.py` → `ssl_doctor.cli.main` | The main program described below |
| Scan agent | `ssldoctor.py agent ...` → `ssl_doctor.agent.main` | Long-polls a control plane for scan jobs |
| Control-plane server | `packaging/entry_server.py` → `ssldoctor_service.server_main.main` | Web UI/API, database, monitoring, agents |

The CLI is the primary flow. The agent and server flows are summarized in
[section 10](#10-alternate-entry-points-agent-and-server).

```text
ssldoctor.py
   │  imports
   ▼
ssl_doctor/cli.py :: main()
   │
   ├─ argv[0] == "agent" ──────────────► ssl_doctor/agent.py :: main()
   │
   ├─ -h / --help ─────────────────────► banner + help, exit 0
   │
   ├─ -c ... or a bare /command ───────► batch mode: execute each command
   │                                      then exit 0 or 1
   │
   └─ otherwise ───────────────────────► REPL mode: prompt until /exit
                                          then disconnect, print "bye", exit 0
```

---

## 2. Starting the process

### 2.1 Entry points

- **`ssldoctor.py`** — development/source entry point. It imports
  `main` from `ssl_doctor/cli.py` and calls
  `raise SystemExit(main())`.
- **`pyproject.toml`** — declares the installed console script
  `ssl-doctor = "ssl_doctor.cli:main"`.
- **`packaging/entry_cli.py`** — PyInstaller/frozen-build equivalent; it calls
  the same `ssl_doctor.cli.main`.

`ssl_doctor/cli.py` is imported first. At import time it:

1. Imports the diagnostic modules:
   - `ssl_doctor/findings.py` — findings model and session store
   - `ssl_doctor/analyze.py` — correlation rules
   - `ssl_doctor/certs.py` — certificate parsing, chain assessment, key matching
   - `ssl_doctor/local.py` — checks on the local/client machine
   - `ssl_doctor/netchecks.py` — remote DNS/TCP/TLS/HTTPS checks
   - `ssl_doctor/report.py` — HTML/JSON rendering
   - `ssl_doctor/server.py` — SSH transport and nginx analysis
   - `ssl_doctor/nginx_discovery.py` — which configuration the running nginx uses
   - `ssl_doctor/profiles.py` — remembered server profiles
   - `ssl_doctor/vault.py` — saved passwords in the OS credential vault
   - `ssl_doctor/textcells.py` — text measured in terminal cells
   (`ssl_doctor/tui.py` and `ssl_doctor/clipboard.py` are imported when the
   full-screen shell or a copy needs them.)
2. Resolves one colour level (`resolve_color_mode()`: `NO_COLOR`,
   `SSL_DOCTOR_COLOR`, tty, `TERM=dumb`, Windows VT, `COLORTERM`, `TERM`) and
   the glyph set for the stream's encoding; `_USE_COLOR` remains as an alias.
3. On Windows, issues an empty `os.system("")` to enable ANSI escape handling
   in modern consoles.

### 2.2 `main(argv)` — argument parsing

`ssl_doctor/cli.py :: main()` performs these steps in order:

1. Copies `sys.argv[1:]` (or an injected `argv`).
   - **Askpass helper:** when `SSL_DOCTOR_ASKPASS=1` is set (a frozen Windows
     build started by `ssh` as its `SSH_ASKPASS` helper), `server.askpass_reply()`
     prints the password from the environment and `main()` returns `0` at once.
2. **Agent branch:** if the first argument is exactly `agent`, imports
   `ssl_doctor/agent.py` and returns `agent.main(argv[1:])`. An
   `agent.AgentError` is printed in red and converted to exit code `1`.
3. Creates one `SSLDoctorCLI` instance. Its constructor initializes:
   - `store = findings.FindingStore()` — all findings for this session
   - `net_timeout = 8.0`
   - `command_timeout = 20.0`
   - `server = None` — no SSH session yet
   - `remote_facts = {}` — structured facts from the last remote scan
   - `_diagnosis = None` — cached correlation result
   - `_running = True`
   - `use_tui = None` (decide from the terminal), `no_remember = False`
   - `_profile_store` / `_secret_vault = None` — remembered servers, loaded on
     first use (`profiles.ProfileStore`, `vault.open_vault()`)
4. Scans the remaining arguments left to right:
   - `-c <command>` — appends the command to the **batch list**
   - `--timeout <seconds>` — sets only `cli.net_timeout` (invalid values are
     ignored)
   - `--no-tui` / `--plain` — line REPL instead of the full-screen shell
   - `--no-remember` — never remember servers or use saved passwords
   - `--typewriter`, `--typewriter-speed <cps>` — gradual output on a terminal
   - `-h` / `--help` — prints the banner and help, returns `0`
   - an argument starting with `/` — joins that argument and **all remaining
     arguments** into one batch command and stops parsing
   - anything else — silently skipped (`i += 1`)
5. If the batch list is non-empty, runs **batch mode** (section 4).
6. Otherwise starts the **REPL** (section 5).

---

## 3. Session state and the finding model

Every check returns one or more `Finding` objects from
`ssl_doctor/findings.py`:

```text
Finding
  check          machine name, e.g. "tls.handshake"
  title          human-readable title
  status         PASS | FAIL | WARNING | NOT TESTED
  scope          local | remote-net | server
  evidence       list of human-readable evidence lines
  detail         optional longer explanation
  recommendation optional remediation
  target         host:port or file path
  ts             timestamp
```

`FindingStore` is an ordered, append-only collection with:

- `add()` / `extend()` — record findings
- `all()` — snapshot used by diagnosis and reports
- `by_scope(scope)` — used by `/findings <scope>`
- `clear()` — used by `/clear`
- `counts()` and `__len__()` — summary helpers

Diagnostic commands **do not print and discard** results. Each handler adds its
findings to `FindingStore`, then prints them with `print_findings()` (also in
`ssl_doctor/cli.py`). This is what makes later `/diagnose` and `/report` possible.

---

## 4. Batch mode

Batch mode is selected by one or more `-c` arguments or by a bare `/command`.

`ssl_doctor/cli.py :: main()`:

1. Prints the banner (`SSLDoctorCLI.banner`).
2. For each batch line:
   - echoes `ssl-doctor> <line>`
   - calls `cli.execute(line)`
   - stops early if `execute()` returns `False` (i.e. the command was
     `/exit` or `/quit`)
3. If no diagnosis was produced but findings exist, it runs
   `diagnose(cli.store.all(), {})` inside a `try/except`; failures are ignored.
4. Returns:
   - `1` if the diagnosis exists and `diagnosis.overall == "FAIL"`
   - `0` otherwise (including no findings, or a WARNING/PASS result)

This makes batch mode usable as a CI/smoke-test gate. Note that command
exceptions are caught inside `execute()`, so a failing check does not
automatically produce a non-zero exit code; the diagnosis does.

---

## 5. REPL mode — the command loop

On an interactive terminal `repl()` first starts the **full-screen shell**
(`SSLDoctorCLI._repl_tui()`, presentation in `ssl_doctor/tui.py`) unless
`--no-tui`, `SSL_DOCTOR_TUI=0`, `TERM=dumb` or a missing key reader rules it
out; any error there falls back to the line loop below.

- The shell enters the alternate screen and redraws one frame per event:
  centred banner, the transcript (each command's captured, colourless output),
  then the rounded composer (label and session summary in its top border, key
  hints in its bottom border). `_tui_run()` executes a line with `sys.stdout`
  captured into the transcript; the spinner and questions live in the composer.
- Mouse reporting (`?1002h ?1006h`) is on only while the composer reads:
  the wheel scrolls, a drag selects transcript text and the release copies it;
  `Ctrl-Y` copies the previous response.
- Result frames are captured as text, but `Transcript.wrapped(width)` redraws
  each one (`tui.reflow_frame`) at `width - FRAME_MARGIN` every time the screen
  is laid out, so a resize never breaks a border. Widths are terminal cells
  (`ssl_doctor/textcells.py`): CJK and emoji count two, combining marks zero.
- On Windows, `KeyReader` reads `ReadConsoleInputW` records under its own raw
  VT input mode for one key, then restores the mode. It decodes VT mouse
  reports and native `MOUSE_EVENT` records. `msvcrt.getwch()` is not used: the
  UCRT resets the input mode to 0 while it reads and drops non-key records, so
  no mouse report would arrive.
- Copies go through `ssl_doctor/clipboard.py`: the native OS clipboard (Win32,
  or an X11 helper process), a clipboard tool as fallback, and the OSC 52
  terminal escape.

The line-oriented loop (`--no-tui`, pipes, batch fallback):

```text
banner()
while self._running:
    line = input("ssl-doctor> ")
    on EOFError / KeyboardInterrupt:
        break
    if line is /exit, /quit, exit, or quit:
        cmd_exit(); break
    self.execute(line)

if self.server: server.disconnect()
print("bye")
return 0
```

Important details:

- The loop condition is `_running`. Only `/exit` (or its alias `/quit`) sets it
  to `False`.
- `exit` / `quit` without a slash are recognized by the REPL before dispatch.
- Ctrl-C at the prompt exits the session cleanly. Ctrl-C **during** a command
  is caught inside `execute()` and prints `interrupted`; the session continues.
- Any other exception from a command is caught there too: a file or process
  error prints `/<command>: <path>: <reason>`, a bug prints
  `internal error in /<command>: …`; the session continues either way.
- At shutdown the SSH session is disconnected (which wipes the in-memory
  password and removes the temporary askpass helper) and the process returns
  `0`.

---

## 6. Executing one command

`ssl_doctor/cli.py :: SSLDoctorCLI.execute(line)` is the single dispatch path
for both REPL and batch input:

1. Trim whitespace; an empty line returns `True`.
2. If the line does not start with `/`:
   - `help` or `?` (case-insensitive) is rewritten to `/help`
   - anything else prints `error: commands start with '/'. Try /help` and
     returns `True`
3. Remove the leading `/` and split the rest with `shlex.split()`. A quoting
   error is reported and returns `True`.
4. If no arguments remain, return `True`.
5. Lower-case the command name and look up a handler with
   `getattr(self, f"cmd_{cmd}", None)`.
6. Unknown command → `error: unknown command /<cmd>. Try /help`, return `True`.
7. Call the handler with the remaining arguments inside two guards:
   - `KeyboardInterrupt` → prints `interrupted`
   - any other `Exception` → prints `TypeError: ...` style error
8. Return `self._running`.

This design means a bug in one check cannot terminate the session, and command
handlers communicate “stop the program” solely by setting `_running = False`.

Aliases are ordinary class attributes:

- `cmd_quit = cmd_exit` — `/quit`
- `cmd_remote = cmd_tls` — `/remote`

---

## 7. Command handlers in detail

All handlers live in `ssl_doctor/cli.py` unless noted. Most follow the same
pattern: run a library function under a `Spinner`, add findings to
`self.store`, print them.

| Command | Handler | What happens | Files involved |
|---|---|---|---|
| `/help` | `cmd_help` | Prints the static command table. | `ssl_doctor/cli.py` |
| `/version` | `cmd_version` | Prints app name and version. | `ssl_doctor/__init__.py` |
| `/timeout [net] [cmd]` | `cmd_timeout` | Shows or sets `net_timeout` and optionally `cmd_timeout`. | `ssl_doctor/cli.py` |
| `/findings [scope]` | `cmd_findings` | Prints all findings, or filters by `local`, `remote-net`, `server`. | `ssl_doctor/findings.py` |
| `/clear` | `cmd_clear` | Empties the store and clears the cached diagnosis. | `ssl_doctor/findings.py` |
| `/cert inspect <file> [host]` | `cmd_cert` | Parses a PEM/DER certificate or chain file, checks dates/SANs/fingerprints and chain order. | `ssl_doctor/certs.py` → `inspect_cert_file` |
| `/cert match <cert> <key>` | `cmd_cert` | Compares public-key digests only; never reads out key material. | `ssl_doctor/certs.py` → `match_cert_key` |
| `/tls <host\|URL> [--sni name]` | `cmd_tls` | Full remote TLS/HTTPS suite. | `ssl_doctor/netchecks.py` → `run_remote_diagnostics` |
| `/local [cert]` | `cmd_local` | Checks the machine running SSL Doctor. | `ssl_doctor/local.py` → `run_local_for_remote` |
| `/scan ...` | `cmd_scan` | Guided multi-step workflow (section 7.2). | `cli.py`, `netchecks.py`, `local.py`, `server.py`, `analyze.py` |
| `/server connect` | `cmd_server` → `_server_connect` | Interactive SSH setup and verification. | `ssl_doctor/server.py` |
| `/server status` | `cmd_server` | Shows the current SSH/TLS target state. | `ssl_doctor/server.py` |
| `/server overview` | `cmd_server` | Remote OS identity plus web-server/OpenSSL detection. | `ssl_doctor/server.py` |
| `/server nginx [domain[:port]]` | `cmd_server` | Resolves the nginx vhost and audits its TLS configuration. | `ssl_doctor/server.py` → `nginx_scan` |
| `/server cert <file> [key]` | `cmd_server` | Remote certificate inspection, key pairing, file permissions. | `ssl_doctor/server.py` |
| `/server config` | `cmd_server` | Read-only scan of web-server TLS/vhost configuration. | `ssl_doctor/server.py` |
| `/server logs` | `cmd_server` | Recent TLS-related service log entries, when readable. | `ssl_doctor/server.py` |
| `/server compare` | `cmd_server` | Configured nginx certificate vs certificate served on the network. | `ssl_doctor/server.py` |
| `/server disconnect` | `cmd_server` | Closes SSH and drops the session object. | `ssl_doctor/server.py` |
| `/diagnose` | `cmd_diagnose` | Correlates all findings into ranked root causes. | `ssl_doctor/analyze.py` |
| `/report [html\|json\|both] [path]` | `cmd_report` | Writes a report. | `ssl_doctor/report.py`, `ssl_doctor/contract.py` |
| `/report agent [dir]` | `cmd_report` → `_report_agent` | Writes `agent-report.md` + `agent-report.json` (both or neither) from the redacted findings document. | `ssl_doctor/report.py` (`agent_meta`, `agent_markdown`, `write_agent_report`) |
| `/copy [all]` | `cmd_copy` | Copies the previous recorded response, or the whole session, to the clipboard. | `ssl_doctor/clipboard.py` |
| `/exit`, `/quit` | `cmd_exit` / `cmd_quit` | Disconnects SSH, sets `_running = False`. | `ssl_doctor/cli.py` |

### 7.1 `/tls` — remote diagnostics

`cmd_tls` parses positional arguments, accepts either a second positional port
or `host:port` / URL syntax, and calls
`netchecks.parse_target()` to normalize to `(host, port, scheme_hint, error)`.
It then calls `_gather_remote()`:

1. `netchecks.run_remote_diagnostics(host, port, sni, timeout)`.
2. If a certificate was presented, inserts a `netchecks.domain_profile()`
   finding at the front.
3. Adds every finding to the store.
4. Replaces `self.remote_facts` with the returned structured facts.
5. Clears the cached `_diagnosis` (the findings changed).
6. Prints the findings and suggests `/diagnose` or `/report html`.

### 7.2 `/scan` — the guided workflow

`cmd_scan` is the orchestration layer over the other commands:

1. Target resolution:
   - first positional argument, or an interactive prompt
   - `netchecks.parse_target()` for `host`, `host:port`, or URL
   - `--sni` is read by `_sni_arg()`
2. Mode selection:
   - `--server-only` → server side only
   - `--client-only` → client side only
   - otherwise combined
   - in combined mode, unless `--with-server` was passed, it asks
     `run authorized server-side checks too (SSH)? (yes/no)` (default `no`)
3. Step count is chosen (`steps_total`): 3 for client-only, 2 for server-only,
   3 combined-without-SSH, 4 combined-with-SSH.
4. **Client phase** (modes `client` and `combined`):
   - prints `Step N: domain identification + network checks`
   - `_gather_remote()` → `netchecks.run_remote_diagnostics()`
   - prints `Step N: client machine checks`
   - `cmd_local([])` → `local.run_local_for_remote()`
5. **Server phase** (mode `server`, or combined with SSH):
   - `_scan_server_side(host, port, sni)`:
     - if no presented certificate is known yet, measures the public endpoint
       with `netchecks.check_dns()` and `netchecks.check_tls_basic()`, adds a
       domain profile, and updates `remote_facts`
     - interactive: `_choose_scan_server(host)` asks which server to use —
       the current session, remembered servers (domain matches first), or
       `n` = new — with Enter on the most likely one; nothing to choose from
       goes straight to `_server_connect()`, an unrecognised answer skips the
       server step
     - batch: uses the open session, else runs `_server_connect()`
     - a new connection replaces the current session only once it is up; if it
       fails, the server step stops (the old session stays open)
     - `ServerSession.overview()` + `webserver_detection()`
     - `ServerSession.nginx_scan(domain, port)`: `discover_nginx()` (cached per
       connection) runs `nginx_discovery.discover()` through `_SshNginxProbe` —
       A running master (`ps`, `/proc/<pid>`), B its systemd unit, C trusted
       executable `-V` / `-T`, D bounded search only without a runtime main
       configuration, E the include graph — and the findings are qualified by
       the resulting evidence level; then `_certificate_checks()` resolves the
       selected block's `ssl_certificate` / `ssl_certificate_key` against
       nginx's configuration prefix (`nginx_discovery.resolve_cert_path`) or
       takes the saved manual paths (`ServerSession.nginx_settings`), checks
       the files (`file_states`), reports `nginx.path_resolution`, and runs
       `nginx.chainfile` / `srv.cert` / `srv.keymatch` only on opened files
     - `ServerSession.compare_configured_vs_presented(presented_sha256)`
     - `ServerSession.log_scan()`
   - in combined mode without SSH, prints a note explaining how to run the
     server side later
6. **Diagnosis phase:** calls `cmd_diagnose([])`.

All server-side findings are scoped `server`; network findings are
`remote-net`; local checks are `local`. This lets the correlation rules reason
about origin correctly.

### 7.3 `/server connect` — SSH setup

`_server_connect(name="", profile=None)` in `ssl_doctor/cli.py` runs five
steps (ADR-001); no password is asked for, or read from the vault, before the
host key is trusted:

1. **Settings** — `/server connect <name>` takes the remembered profile
   (`ssl_doctor/profiles.py`, `~/.ssl-doctor/profiles.json`); without a name and
   with profiles present it offers the recent servers (`n` = new); `/scan`
   passes the server chosen in `_choose_scan_server()`. Otherwise it prompts
   for host, port (`22`), user (`getpass.getuser()`), auth method
   (`1=password`, `2=private key`), key path, TLS target host and port, with
   defaults pre-filled from a profile for the same host.
2. **Host key** — `server.host_key_status()`: `unreachable` and `changed`
   record a FAIL and stop; `unknown` shows the fingerprints and asks for
   explicit trust (`server.store_host_key()` on "yes"); `trusted` proceeds.
3. **Secret** — for password logins: when the profile has a saved password,
   the vault (`ssl_doctor/vault.py`: Windows Credential Manager, Secret
   Service, or `NullVault`) is read with the presented `SHA256:` fingerprints;
   it is skipped when they do not match the ones the password was saved with.
   Otherwise `getpass.getpass()` / the shell's masked input asks for it; an
   empty or blank answer is refused and asked again (at most three times),
   and Ctrl-C cancels (`server.password_problem()` is the one rule, also
   applied by `ServerSession.connect`, the vault and the askpass helpers).
4. **Session** — `server.ServerSession(cfg, password).connect()` re-verifies
   the host key, runs `ssh ... true`, and reports `ssh.hostkey` / `ssh.auth`.
   A saved password the server rejects is deleted from the vault and asked
   once.
5. **Outcome** — a remembered server's nginx settings (`nginx_mode`,
   certificate, key, main configuration, prefix) become the session's
   `NginxSettings`. First successful connection: *Remember this server?
   [P]rofile only · [S]ave password too · [N]o*; later ones update
   `last_used` (and offer to re-save a password that could not be used).
   Remembering is off for `-c`, non-interactive sessions, `--no-remember` and
   `SSL_DOCTOR_REMEMBER=off`; the vault is then a `NullVault`.

`ServerSession.run()` invokes the system `ssh` binary with:

- `StrictHostKeyChecking=yes`
- a private known-hosts file at `~/.ssl-doctor/known_hosts`
- public-key or password-only authentication as configured
- a command timeout (`command_timeout`)
- for passwords, a temporary `SSH_ASKPASS` helper in the private state
  directory, fed through an environment variable: `askpass.sh` on POSIX,
  `askpass.cmd` (runs the interpreter) on Windows, or the frozen exe itself
  (`SSL_DOCTOR_ASKPASS=1` makes `cli.main()` print the password and exit)

The password is held only in memory, returned by `known_secrets()` solely for
report redaction, and cleared by `disconnect()`.

### 7.4 `/diagnose` — findings to causes

`cmd_diagnose` calls `ssl_doctor/analyze.py :: diagnose(items, ctx)`. The
correlation rules:

- group findings by scope (`remote-net`, `server`, `local`)
- start with transport failures: DNS → TCP → TLS handshake
- then protocol/cipher negotiation
- then the chain the server actually sent (`tls.chain`), nginx chain-file and
  vhost findings, and root-only validation
- then client trust-store/root-CA, clock skew, proxy, and Windows-specific
  evidence
- add expiry, hostname, multi-IP, SNI, weak-cipher, and HTTPS observations
- sort causes by rank and classify certainty as `confirmed`, `probable`, or
  `possible`

The result is a `Diagnosis`:

```text
Diagnosis
  causes: list[Cause]
  notes:  list[str]
  overall: "FAIL"    if any cause is confirmed
           "WARNING" if any non-confirmed cause exists
           "PASS"    if there are no causes
```

`cmd_diagnose` caches the result in `self._diagnosis` and prints the overall
verdict, each cause with evidence and a fix, and any notes.

### 7.5 `/report` — serializing the session

`cmd_report`:

1. Parses arguments: `html` (default), `json`, or `both`, plus an optional path.
2. Refuses to write if the store is empty.
3. Reuses `_diagnosis`; if it is `None`, computes one from the store.
4. Builds `meta` from `_meta()`: target, timeouts, and whether SSH is connected.
5. Collects secrets from `ServerSession.known_secrets()` for redaction.
6. If a certificate was seen, calls `netchecks.export_facts()` to include the
   structured leaf/chain facts.
7. Chooses file names:
   - JSON default: `ssl-doctor-report-<YYYYmmdd-HHMMSS>.json`
   - HTML default: `ssl-doctor-report-<YYYYmmdd-HHMMSS>.html`
   - an explicit path gets `.json` / `.html` appended when needed
8. `report.write_json()` or `report.write_html()`.

Both writers go through `report.build_payload()` in `ssl_doctor/report.py`,
which:

- counts PASS/FAIL/WARNING/NOT TESTED
- builds the `schema_version`, tool/version, `generated_utc`, `meta`,
  `summary`, `diagnosis`, `findings`, disclaimer, and optional `facts`
- passes the document through `contract.redact()` in `ssl_doctor/contract.py`,
  which scrubs private-key blocks and every supplied secret in raw, URL-encoded,
  base64, and hex forms

`write_html()` renders the already-redacted document with
`report.html_from_payload()` into one self-contained HTML file.

### 7.6 Command side effects on cached state

- `/tls` (and therefore `/scan`'s client phase) **replaces**
  `remote_facts` and **invalidates** `_diagnosis`.
- `/clear` empties the store and invalidates `_diagnosis`.
- Other commands append findings but do not invalidate a previously cached
  diagnosis; `/diagnose` recomputes it explicitly, and `/report` only computes
  one when the cache is empty. Run `/diagnose` again after adding checks if you
  want the printed diagnosis to reflect them.

---

## 8. The remote diagnostic suite in order

`ssl_doctor/netchecks.py :: run_remote_diagnostics()` is the core network
pipeline used by `/tls` and `/scan`. It returns `(findings, facts)`.

```text
1. parse / record host, port, SNI
2. check_dns()                      ─┐
3. check_tcp()                       │ early exit on DNS/TCP failure:
4. check_tls_basic()                 │ add NOT TESTED handshake finding
   └─ read presented certificate      │ and return
      and chain (read_presented_chain│
      / _chain_via_s_client)         │
5. certificate validity              │
6. hostname match (SAN only)         │ early exit if handshake FAIL:
7. check_presented_chain()           │ add protocol matrix, return
8. check_tls_validation()            │
9. check_tls_rootonly_validation()   │
10. check_protocol_matrix()          │
11. check_sni_difference()           │
12. check_multi_ip()                 │
13. check_weak_ciphers()             │
14. check_https()                    │
    └─ redirect chain, final URL,     │
       server time                    │
15. return findings + facts ─────────┘
```

The `facts` dictionary carries the parsed certificate, IPs, SNI, chain status,
anchor, redirect hops, final URL, server time, `handshake_ip` and
`handshake_failure`. It is stored in `SSLDoctorCLI.remote_facts` and reused for
local clock comparison and reports.

### Handshake failure flow

`check_tls_basic(host, port, sni, timeout, connect_ip=<address net.tcp verified>)`
splits the probe into two observable phases:

```text
_connect()    → socket          raises _ConnectTimeout     → failure_kind "connect-timeout"
_negotiate()  → ssl.SSLSocket   raises _NegotiationTimeout → failure_kind "negotiation-timeout"
                                ssl.SSLError/OSError       → "tls-alert" or "network-error"
```

1. A timeout-class failure is retried once on a fresh connection; a rejection or
   reset is not retried, because retrying cannot change a deterministic answer.
2. Both attempts fail → `FAIL`. The first attempt completes → `WARNING` with the
   stall recorded, and every certificate fact still captured, so validity,
   hostname, chain and validation checks keep running.
3. `facts["handshake_ip"]` and `facts["handshake_attempts"]` record the address
   and the number of attempts; `facts["handshake_failure"]` keeps the
   classification for consumers.
4. On `FAIL`, the protocol matrix runs and then `_note_handshake_coherence()`
   appends the accepted versions to the handshake evidence, so the two findings
   cannot contradict each other silently.
5. `check_protocol_matrix()` pins the same address, classifies every row
   (accepted / refused / timed out / network error), and sets `failure_kind` to
   `no-version-accepted` or `no-version-answered`. A timeout is never a refusal.

### Endpoint comparison and SNI observation

`check_multi_ip(host, port, ips, timeout, sni=…, facts=…)` probes up to four
addresses and records one state per address in `facts["endpoints"]`
(`negotiated`, `tls-rejected`, `tcp-unreachable`, `timed-out`,
`probe-unavailable`). Only `negotiated` endpoints whose server name matches the
requested one are compared, and only over leaf fingerprint, hostname coverage and
chain status. `< 2` comparable endpoints ⇒ `NOT TESTED` with
`observation="endpoint-comparison-inconclusive"`; a measured difference ⇒
`WARNING` with `observation="endpoint-certificate-difference"`.

`check_sni_difference()` reports one of: same certificate (PASS, no observation),
a different certificate without SNI (PASS, `observation="sni-certificate-differs"`,
explicitly described as legitimate default-vhost behaviour), the no-SNI probe
failing (NOT TESTED, `observation="sni-without-probe-failed"`), or a failing
handshake for the requested name (FAIL). It never recommends a virtual-host
change on the strength of a fingerprint difference.

### Protocol matrix

`check_protocol_matrix(..., negotiated=<primary protocol>, facts=...)` probes each
version and classifies it per version: `default` (accepted with the default cipher
policy), `relaxed-only` (TLS 1.0/1.1 answered only under `ALL:@SECLEVEL=0` and the
default-policy probe was refused), `relaxed-only-unverified` (relaxed answer but
the default-policy probe was client-limited or timed out), `rejected`, or
`inconclusive`. TLS 1.3 is probed under the default policy only; relaxed-policy
acceptance of TLS 1.0/1.1 proves only that the server's stack can still negotiate
the version when legacy suites are offered, so it never becomes a claim about
ordinary clients. A version the primary handshake negotiated is never reported as
refused; an inconclusive row is retried once inside a budget of
`timeout × PROBE_BUDGET_FACTOR × (versions + 3)`. The finding's observation is
`legacy-accepted-default`, `legacy-accepted-relaxed-only`,
`legacy-accepted-unverified`, `tls12-relaxed-only` or `probe-inconclusive`;
`legacy-accepted-default`, `legacy-accepted-relaxed-only` and
`tls12-relaxed-only` raise a server cause (the last two with a listed limitation),
`legacy-accepted-unverified` and `probe-inconclusive` produce a diagnosis note. When TLS 1.2 is
accepted under the relaxed policy, a default-policy probe adds an interoperability
line (a modern client can connect, or only the lowered security level can).
`_is_local_probe_limitation()` separates `NO_PROTOCOLS_AVAILABLE`,
`NO_CIPHERS_AVAILABLE`, `CA MD TOO WEAK` and local context errors from a server
answer, so a client that cannot build the offer is never reported as a refusal.

`analyze.diagnose()` attributes from `failure_kind`, not from the status:
timeouts and resets are probable **network** causes whose advice is to repeat the
measurement and inspect the path; only `tls-alert` can produce a server
protocol/cipher-mismatch cause; an unclassified failure falls back to network.

---

## 9. Shutdown and exit codes

### Interactive mode

1. `/exit`, `/quit`, `exit`, `quit`, EOF, or Ctrl-C at the prompt ends the loop.
2. `cmd_exit` disconnects SSH if a session exists.
3. `repl()` disconnects again defensively, prints `bye`, returns `0`.
4. `ssldoctor.py` raises `SystemExit(0)`.

### Batch mode

1. Stops after the last command or after a command sets `_running = False`.
2. Optionally computes a diagnosis.
3. Returns `1` only when the diagnosis overall is `FAIL`; otherwise `0`.
4. `ssldoctor.py` raises `SystemExit` with that value.

### Agent mode

- `enroll` success → `0`; failed enrollment raises `AgentError` and the CLI
  returns `1`.
- `run --once` → `0` on a successful poll/job, `1` on service/network error.
- a revoked/unknown agent during `run` → `2`.
- usage error → `64`.

---

## 10. Alternate entry points: agent and server

### 10.1 Scan agent — `ssl_doctor/agent.py`

Selected when the CLI receives `agent` as its first argument.

```text
ssl_doctor/cli.py :: main()
  └─ ssl_doctor/agent.py :: main()
       ├─ "enroll <url> <token>" → AgentClient.enroll()
       │                           save_state(~/.ssl-doctor/agent.json, 0600)
       └─ "run [--once]"         → load_state()
                                   serve()
                                     └─ long-poll /v1/agent/jobs/next
                                        handle_job()
                                          ├─ client role → run_client_checks()
                                          │                 netchecks + local + report
                                          └─ server role → run_server_checks()
                                                            server.LocalSession + nginx + netchecks
                                        upload result document
```

Key properties:

- Outbound HTTPS only; the agent listens on nothing.
- A job declares only a kind and target; nothing from the service is executed.
- Jobs for the other role are declined.
- Uploaded documents are built by `report.build_payload()` and therefore obey
  the same redaction and findings contract.
- Backoff doubles from 1 s to 60 s on transient failures.

### 10.2 Control-plane server — `service/ssldoctor_service/`

`packaging/entry_server.py` imports `ssldoctor_service.server_main.main()`.
Subcommands are `init`, `run`, `upgrade`, `backup`, `verify-audit`, and
`version`.

- `server_main.cmd_init` creates the data directory, embedded PostgreSQL
  cluster, config (`0600`), migrations, application role, and owner API token.
- `server_main.cmd_run` starts PostgreSQL, starts a monitor scheduler thread,
  creates the FastAPI app with `app.create_app(Database(...))`, and runs
  Uvicorn. It stops PostgreSQL in a `finally` block.
- `app.py` serves the member API and agent API; tenant isolation is enforced by
  database row-level security through `db.org(org_id)`.
- `monitor.py` schedules and dispatches recurring scans and evaluates expiry.
- `audit.py`, `identity.py`, `scim.py`, `ui.py`, `render.py`, `db.py`, and the
  SQL files in `migrations/` support auditing, SSO/SCIM, the HTML UI, schema,
  and persistence.

Packaging glue lives in `packaging/build.py`, `packaging/entry_agent.py`,
`packaging/entry_cli.py`, `packaging/entry_server.py`, `packaging/release.py`,
and `packaging/winsvc.py`.

---

## 11. End-to-end sequence diagram

```text
User                cli.py                  netchecks/local/server      analyze        report
 │                    │                            │                       │             │
 │ python ssldoctor.py│                            │                       │             │
 ├───────────────────►│ main()                     │                       │             │
 │                    │ parse argv                 │                       │             │
 │                    │ REPL / batch               │                       │             │
 │  /scan example.com │                            │                       │             │
 ├───────────────────►│ execute()                  │                       │             │
 │                    │ shlex + dispatch            │                       │             │
 │                    ├─ cmd_scan ─────────────────►│                       │             │
 │                    │                            │ run_remote_diagnostics│             │
 │                    │                            ├──────────────────────►│             │
 │                    │                            │<── findings + facts ──┤             │
 │                    │                            │ run_local_for_remote  │             │
 │                    │                            ├──────────────────────►│             │
 │                    │                            │<── findings ──────────┤             │
 │                    │                            │ (optional SSH/nginx)  │             │
 │                    │ store.extend()             │                       │             │
 │                    ├─ cmd_diagnose ─────────────┼──────────────────────►│             │
 │                    │<── Diagnosis ──────────────┼───────────────────────┤             │
 │  /report html      │                            │                       │             │
 ├───────────────────►│ cmd_report ────────────────┼───────────────────────┼────────────►│
 │                    │                            │                       │  redact +   │
 │                    │                            │                       │  write file │
 │  /exit             │                            │                       │             │
 ├───────────────────►│ cmd_exit                   │                       │             │
 │                    │ server.disconnect()        │                       │             │
 │                    │ break loop, "bye", return 0│                       │             │
 │◄───────────────────┤                            │                       │             │
```

---

## 12. File map

| File | Role in the execution flow |
|---|---|
| `ssldoctor.py` | Source entry point; calls `ssl_doctor.cli.main()` |
| `pyproject.toml` | Declares the `ssl-doctor` console script and package |
| `ssl_doctor/__init__.py` | Version (`0.10.0`) and application name |
| `ssl_doctor/cli.py` | Argument parsing, batch mode, REPL, dispatch, all command handlers, spinner/colors, result frames, `/scan` orchestration, the `/server connect` pipeline and remembered-server commands |
| `ssl_doctor/tui.py` | Full-screen shell: layout, transcript (frames redrawn per width), composer, completion menu, mouse selection, key reader (termios / Windows console records) |
| `ssl_doctor/textcells.py` | Width, clipping and wrapping in terminal cells (CJK/emoji = 2, combining = 0) |
| `ssl_doctor/clipboard.py` | Copy to the clipboard: Win32, X11 helper, tools, OSC 52 |
| `ssl_doctor/nginx_discovery.py` | Which configuration the running nginx uses: process/unit/`-V` parsing, nginx path semantics, include graph (expanded), evidence levels; pure, driven through a probe |
| `ssl_doctor/profiles.py` | Remembered server profiles in `~/.ssl-doctor/profiles.json` (validated, atomic, owner-only) |
| `ssl_doctor/vault.py` | Saved passwords: Windows Credential Manager, Secret Service (`secret-tool`), or none; host-key binding, expiry |
| `ssl_doctor/findings.py` | `Finding` model, statuses/scopes, `FindingStore` |
| `ssl_doctor/netchecks.py` | Target parsing, domain profile, DNS/TCP/TLS/HTTPS suite, presented-chain reading |
| `ssl_doctor/certs.py` | PEM/DER parsing, chain assessment, hostname matching, cert/key digest matching |
| `ssl_doctor/local.py` | Local machine checks: OS, clock skew, proxy, Windows stores, certutil, Schannel |
| `ssl_doctor/server.py` | SSH config/session, host-key trust store (with the `ssh` probe fallback when `ssh-keyscan` cannot negotiate), askpass helper (POSIX script, Windows `.cmd` or the frozen exe), nginx config parsing and vhost resolution, remote checks |
| `ssl_doctor/analyze.py` | Correlation rules producing ranked causes and overall verdict |
| `ssl_doctor/report.py` | Findings-contract payload, JSON writer, self-contained HTML renderer |
| `ssl_doctor/contract.py` | Schema version, validation, and secret/private-key redaction |
| `ssl_doctor/agent.py` | Agent enroll/run, job polling, role-bound check execution |
| `service/ssldoctor_service/server_main.py` | `ssldoctor-server` CLI, embedded PostgreSQL lifecycle, init/run/upgrade/backup/verify-audit |
| `service/ssldoctor_service/app.py` | FastAPI member and agent API |
| `service/ssldoctor_service/monitor.py` | Scheduled scans, dispatch, expiry evaluation |
| `service/ssldoctor_service/db.py` | Database access and tenant-scoped queries |
| `service/ssldoctor_service/audit.py` | Audit-log verification |
| `service/ssldoctor_service/identity.py` | Identity/SSO support |
| `service/ssldoctor_service/scim.py` | SCIM provisioning |
| `service/ssldoctor_service/ui.py` | Server-rendered UI |
| `service/ssldoctor_service/render.py` | UI rendering helper |
| `service/ssldoctor_service/migrations/*.sql` | Database schema and migrations |
| `packaging/entry_cli.py` | Frozen-build CLI entry point |
| `packaging/entry_agent.py` | Frozen-build agent entry point |
| `packaging/entry_server.py` | Frozen-build server entry point |
| `packaging/build.py` | Build orchestration |
| `packaging/release.py` | Release bundling |
| `packaging/winsvc.py` | Windows service wrapper |
| `tests/` | Unit, integration, TLS fixture, nginx, air-gap, contract, and end-to-end tests |
| `service/tests/` | Control-plane, tenancy, identity, monitoring, audit, migration tests |
| `schemas/findings-1.0.schema.json` … `findings-1.6.schema.json` | Published findings-contract schemas (current: 1.6) |
| `docs/decisions/` | Architecture decision records (ADR-001: remembered servers) |

---

## 13. One-paragraph summary

`ssldoctor.py` calls `ssl_doctor/cli.py :: main`, which either delegates to the
agent entry point or builds a `SSLDoctorCLI`. That object owns a
`FindingStore`, timeouts, the optional SSH session, and remote scan facts. The
program then either runs a batch of `-c`/slash commands or enters the
full-screen shell (or the line REPL with `--no-tui`). Each
line is split with `shlex` and dispatched to a `cmd_*` method. Commands run
read-only checks in `netchecks.py`, `local.py`, `certs.py`, or `server.py`,
convert results to `Finding` objects, append them to the store, and print them.
`/diagnose` sends the whole store through `analyze.py` to produce ranked causes
and an overall PASS/WARNING/FAIL verdict. `/report` builds a findings-contract
document, redacts secrets and private keys in `contract.py`, and writes JSON
and/or self-contained HTML via `report.py`. `/server connect` verifies the host
key before any password is asked for or read from the OS vault, and can
remember the server for next time. `/exit` disconnects SSH, clears the
password, stops the loop, prints `bye`, and returns exit code `0`; batch mode
instead returns `1` only when the final diagnosis is `FAIL`.
