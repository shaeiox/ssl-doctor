# SSL Doctor v0.7.0

Offline-capable SSL/TLS diagnostic tool for IT support engineers. It answers:
*why does this TLS connection fail — the client machine, the nginx server, the
certificate chain, or the network path — and what evidence proves it?*

- Python 3.10+, standard library only (+ system `openssl`/`ssh` binaries when
  present). No cloud services, no AI APIs, nothing to install.
- Every check is **read-only**. Passwords and private keys are never printed,
  logged, or included in reports.

## Run

```bash
python3 ssldoctor.py                                      # interactive session
python3 ssldoctor.py "/tls example.com"                   # one-shot command
python3 ssldoctor.py -c "/scan example.com --with-server" -c "/report both out"
```

| Option | Effect |
|---|---|
| `-c "<command>"` | run a command non-interactively (repeatable); exit code `1` when the diagnosis is `FAIL` |
| `--timeout <seconds>` | network timeout (default 8 s; `/timeout` changes it in a session) |
| `--no-tui` (or `--plain`) | line-oriented REPL instead of the full-screen shell |
| `--typewriter`, `--typewriter-speed <cps>` | type output out gradually on an interactive terminal (also `/typewriter on\|off\|speed <n>`) |
| `-h`, `--help` | banner and command list |

Environment: `NO_COLOR` / `SSL_DOCTOR_COLOR=never|always` control colour,
`SSL_DOCTOR_TUI=0` disables the full-screen shell.

### Development

Nothing needs installing to run the tool. A virtual environment is optional and
is not part of the repository (`venv/` is git-ignored):

```bash
python3 -m venv venv                       # optional
venv/bin/python -m unittest discover -s tests
```

Tests that need the `openssl` binary are skipped when it is missing.

## Terminal look

SSL Doctor opens as a **full-screen application** built like a terminal: the
classic two-stroke wordmark centred at the top, then every command's output
appended underneath it on one left margin, scrolling like a log, and a rounded
chat-style composer that follows the output. Only the banner is centred, so an
evidence line gets the full width of the window.

```
                ════════════════════════════════════════════════════════════════════
                  ██████ ██████ ██       █████  ██████ ██████ ██████ ██████ ██████
                  ██     ██     ██       ██  ██ ██  ██ ██       ██   ██  ██ ██  ██
                  ██████ ██████ ██       ██  ██ ██  ██ ██       ██   ██  ██ ██████
                      ██     ██ ██       ██  ██ ██  ██ ██       ██   ██  ██ ██  ██
                  ██████ ██████ ██████   █████  ██████ ██████   ██   ██████ ██  ██
                   offline ssl/tls diagnostics · client · server · chain · nginx
                                     creator: eleven  ·  v0.7.0
                ════════════════════════════════════════════════════════════════════

  Welcome. SSL Doctor is read-only; credentials are never logged.

  ssl-doctor> /local
    ╭─ /local ─────────────────────────────────────────────────────────────────────────────────╮
    │ ▸ collecting local system information                                                    │
    │ ✓ PASS       local.os            Operating system and clock                              │
    │   • OS: Linux-6.1.158+-x86_64-with-glibc2.36                                             │
    │   • Python: 3.11.2 / OpenSSL 3.0.20 7 Apr 2026                                           │
    │ ✓ PASS       local.proxy         Proxy configuration                                     │
    │   • no proxy environment variables set; direct connections                               │
    │ ? NOT TESTED local.certstore     Windows certificate stores                              │
    │   • not running on Windows; Windows trust stores cannot be examined here                 │
    │ ? NOT TESTED local.events        Schannel event log (Windows)                            │
    │   • only available on Windows                                                            │
    ╰─ 2 passed · 0 failed · 0 warnings · 2 not tested ────────────────────────────────────────╯

  ▸ /scan    full workflow: domain, then client and server checks
    /server  SSH setup, nginx config, logs and comparison
    /tls     remote TLS/HTTPS diagnostics for a host
  ╭─ ssl-doctor ───────────────────────────────────────────── 4 findings · timeout 8s · ssh off ─╮
  │ ❯ /s                                                                                         │
  ╰─ Tab complete · ↑↓ select · Esc close ────────────────────────────────────────────── ⏎ send ─╯
```

Each command that produces findings draws **one framed block**: the command is
the frame's title, every check gets a row with its status glyph, word and id,
evidence/detail/`fix:` lines sit indented inside the border, and the counters are
written into the closing border. Text wraps inside the frame — nothing is elided.
On an interactive terminal the frame opens as soon as a phase starts (its first
row says what is running) and each finding is drawn into it the moment its check
completes; batch and piped runs draw the finished frame.

**The composer** is a rounded box. Its top border carries the label — `ssl-doctor`,
the question being asked, or the spinner and verb of a running check — and, on
the right, the session summary (`shop.example:443 · 12 findings · 1 fail ·
timeout 8s · ssh off`). The input row shows a dim placeholder until you type and
scrolls sideways to keep the caret visible; the bottom border carries the key
hints and `⏎ send`. The border is terracotta while it waits for a command,
lavender while it waits for an answer, and grey while a check runs.

**Completion.** Typing `/` opens up to three matching commands with their
descriptions; `Tab` completes the highlighted one, `↑`/`↓` move the highlight,
and a space or `Esc` dismisses the list.

| Key | Action |
|---|---|
| `Enter` | send the command in the composer |
| `Tab` | complete the highlighted command |
| `↑` / `↓` | move the completion highlight, or recall earlier commands |
| `←` / `→`, `Home` / `End` | move the caret in the composer |
| `Backspace`, `Ctrl-U` | edit / clear the composer |
| mouse wheel | scroll the transcript |
| drag with the left button | select transcript text; releasing copies it (`copied 3 lines · 212 chars · …`) |
| `Ctrl-Y` | copy the previous command's response, keeping what you typed |
| `PgUp` / `PgDn` | scroll the transcript (the newest output is always one key away) |
| `Ctrl-L` | redraw |
| `Ctrl-C`, `Ctrl-D` | leave the session (same status code as the line REPL) |

The column is the terminal width, capped at 120 columns and left-aligned; the
banner is centred in it and drops from the wordmark to a compact form when the
window is shorter than 24 rows or narrower than the wordmark.
Mouse reporting (wheel, press, drag, release) is switched on only while the
composer is reading, so mouse bytes can never end up inside a running check;
during a check, and with Shift+drag at any time, the terminal's own selection
works as usual. Copies need no extra software: on Windows they use the Win32
clipboard, on Linux/X11 (including XWayland) SSL Doctor owns the X clipboard
through a small detached helper that serves it until something else is copied,
the way `xclip` does. Wayland-only sessions use `wl-copy` and macOS `pbcopy`.
The terminal clipboard escape (OSC 52) is sent as well, for SSH sessions — many
terminals ignore it (VTE-based ones such as GNOME Terminal and xfce4-terminal
do), so a copy carried only by it is reported as *not confirmed*, with
Shift+drag (the terminal's own selection) as the way out. Commands, answers, findings, exit
codes and reports are identical to the line-oriented mode — the shell only
presents them.

**Opting out** — any of these runs the line-oriented REPL instead:
`--no-tui`, `SSL_DOCTOR_TUI=0`, a non-tty stdin/stdout (pipes, CI, `-c` batch
runs), `TERM=dumb`, or a platform without a key reader. That mode prints the
centred wordmark, then the same framed blocks as the session scrolls, with the
same rounded composer around its prompt; piped and `NO_COLOR` output stays plain
`[   + PASS]` rows.

### Inside the frame

- **Status colours** come from semantic roles: `✓ PASS` green, `⚠ WARNING`
  amber, `✗ FAIL` red-pink, `? NOT TESTED` grey. The frame border is the design
  system's tool pink, the title terracotta, and the footer counts are coloured
  one counter at a time — so a colourless terminal still loses no information.
- **Progress** never writes into the transcript. The spinner (`· ✢ ✳ ✶ ✻ ✽`,
  120 ms) and its verb replace the composer's label while a check runs.
- **Questions** (`/server connect`, host-key trust, mode choice) take over the
  composer's label and are answered in it, with the accepted keys
  (`[Y]es  [N]o`) in its bottom border — the accepted answers are unchanged, and
  passwords are masked and never written to the transcript.
- **Diagnosis** keeps its ranked causes, certainty labels, `limit:` and `fix:`
  lines. A warning that justifies no root cause is listed as `UNRESOLVED`, with
  what was observed, what can be concluded, why it stays uncertain, and the next
  step to verify it.

### Colour and glyphs

Colour is a semantic role, resolved once per run, so the same code path serves
every terminal:

| Condition | Result |
|---|---|
| `NO_COLOR` set | plain — no escape sequences at all |
| `SSL_DOCTOR_COLOR=never` / `always` | force plain / force colour on a terminal |
| stdout is not a terminal | plain (pipes, files, CI logs) |
| `COLORTERM=truecolor` or `24bit` | TrueColor |
| `TERM` contains `256color` | 256-colour |
| otherwise, on a terminal | 16-colour |
| `TERM=dumb`, Windows console without ANSI, or an encoding that cannot render `✓ │` | plain, ASCII frames (`+ - \|`) |

Plain mode is byte-compatible with earlier releases (plus the `+ x !` glyphs),
so `-c` batches, captured logs, JSON reports and the findings contract are
unchanged. `SSL_DOCTOR_COLOR=always` is useful for demo captures and does not
override redirection to a file.

## The scan modes

`/scan` identifies the domain, examines the client side, and — when you have
SSH authorization — the server side. Scope flags pin the scan to one side:

| Command | Scope |
|---|---|
| `/scan example.com` | **Combined**: domain identification → client-side (network path + this machine) → asks to add server-side SSH checks → diagnosis |
| `/scan example.com --client-only` | **Client side only**: DNS/TCP/TLS/HTTPS checks as seen by this client + local machine diagnostics (clock, proxy, Windows stores, certutil, Schannel). No SSH at all |
| `/scan example.com --server-only` | **Server side only**: public endpoint measurement (for comparison) + SSH + nginx SSL configuration examination + configured-vs-presented certificate. No local machine checks |
| `/scan example.com --with-server` | Combined, without the SSH yes/no prompt (script-friendly) |

Targets accept `host`, `host:port`, or a full URL (`https://example.com/path`).

### What the domain identification shows

The *Domain profile* finding ties together: DNS answers, the certificate's
identity (subject, SAN DNS/IP names, issuer), whether the requested name is
actually covered, and the canonical URL after redirects — including a warning
when the target redirects to a *different* host (you may be diagnosing the
wrong endpoint).

### Certificate checks on the presented chain

| Check id | What it proves |
|---|---|
| `tls.chain` | The chain the server **actually sends**, judged on its own: `complete`, `incomplete` (intermediates not sent) or `broken` (a certificate is not issued by the next one, matched by name and key identifier). Reported `NOT TESTED` when the chain can't be read; it never assumes "leaf only". |
| `tls.verify` | Validation against this machine's full trust store, including any cached intermediates (what *this* machine sees). |
| `tls.verify.rootonly` | Validation against trusted **roots only**, with no cached or bundled intermediates (what a client that has never seen the intermediate sees). PASS on `tls.verify` with FAIL here means the server is missing its intermediate. |
| `tls.hostname` | Name coverage from **subjectAltName only**. A CN-only certificate fails, because modern clients ignore the CN. |

Endpoint comparison compares only endpoints that completed a handshake for the
same server name, over certificate fingerprint, hostname coverage and chain
status. An unreachable, rejected or timed-out endpoint produced no certificate,
so it can never be evidence that a certificate differs; with fewer than two
comparable endpoints the result is `NOT TESTED` (inconclusive) instead of a
warning. A match covers the compared endpoints only: when DNS returned more
addresses than were compared, the finding says so (for example "the 4 comparable
endpoint(s) present the same certificate facts; 3 of 7 DNS address(es) were not
compared"). `tls.sni` reports how the server answers with and without SNI as an
*observation*: a different default certificate is normal for name-based virtual
hosting, and only `tls.hostname`/`tls.verify` decide whether the requested name is
served correctly. Protocol rows state whether a version was accepted under the
relaxed `ALL:@SECLEVEL=0` policy or with default settings, and an inconclusive
probe is reported as inconclusive - never as a refusal - while a version the
primary handshake negotiated is never reported as unsupported.

Deprecated TLS 1.0/1.1 are always probed a second time with default settings,
because a handshake with `ALL:@SECLEVEL=0` only shows that the server's stack can
still negotiate the version when legacy cipher suites are offered - not that an
ordinary client can. `facts.probe_policy.support` records `default`,
`relaxed-only`, `relaxed-only-unverified`, `rejected` or `inconclusive` per
version, and `facts.probe_policy.default_probe` the raw outcome of the
default-policy re-probe (`accepted`, `refused`, `client-limited`, …).
`relaxed-only` is a warning with the policy limitation attached.
`relaxed-only-unverified` stays a visible warning and an `UNRESOLVED` diagnosis
entry, with no claim about server support; its remediation is a controlled test
from a client that can still offer the version, with that test's limitations
spelled out. A probe this client could not even send (`NO_PROTOCOLS_AVAILABLE`,
no ciphers in its default context) is `client-limited`: a limitation of the test,
never a server refusal.

Handshake failures carry a machine-readable `failure_kind` (`connect-timeout`,
`negotiation-timeout`, `tls-alert`, `network-error`). A timeout is retried once:
if the second attempt completes, the finding is `WARNING` and the diagnosis says
the path is intermittent. A rejection is never retried and is the only evidence
that can support a protocol/cipher cause. All TLS probes connect to the address
the TCP check proved reachable, and name it in the evidence. The TLS 1.0–1.3
matrix classifies each row as accepted, refused, timed out or network error, and
states when legacy versions were probed with the relaxed cipher policy
`ALL:@SECLEVEL=0`.

The chain is read via the public Python API (3.13+), the equivalent internal API
(3.10–3.12), or `openssl s_client -showcerts`. The handshake evidence names the
method that was used.

### What server-side (nginx) mode examines

Via a read-only SSH session (`/server connect` or `/scan --server-only` /
`/server nginx <domain>[:port]`; without a port, the session's TLS port is used):

1. **Configuration source**: `nginx -T` when the account may run it, otherwise
   the readable files under `/etc/nginx` (`nginx.conf`, `conf.d/`,
   `sites-enabled/`). Insufficient permissions → explicit `NOT TESTED`.
2. **Server-block inventory**: total blocks and TLS-enabled blocks with their
   `listen`/`server_name`.
3. **Vhost resolution for your domain and port**: the server block nginx would
   serve, using nginx's own rules. Only blocks listening on the target port are
   considered. Then: exact `server_name` (the first one wins; duplicates raise a
   WARNING) → longest `*.leading` wildcard → longest `trailing.*` wildcard →
   first matching regex → that port's `default_server` → first block on that
   port. A WARNING on fallback explains the classic "wrong certificate" mystery.
   `ssl_certificate`/`ssl_certificate_key` inherited from `http{}` are resolved.
4. **SSL settings of that vhost**: `ssl_protocols` (legacy TLS flagged),
   `ssl_ciphers` / `ssl_prefer_server_ciphers`.
5. **Chain linkage of `ssl_certificate`**: the leaf comes first, and each
   certificate must be issued by the next one. A leaf-only file (intermediates
   not sent) or a wrong intermediate gives a WARNING naming the broken link.
6. **Certificate details + key pairing** of the referenced files (digest-only
   comparison, key bytes never read out).
7. **Configured-vs-presented**: fingerprint of the nginx-configured cert vs
   the certificate the world actually receives — catching stale reloads, wrong
   vhosts, or TLS terminating elsewhere.
8. **TLS-related service-log entries**, when readable.

## Full command set

| Command | What it does |
|---|---|
| `/scan …` | See table above |
| `/tls <host\|URL> [--sni name]` | Remote TLS/HTTPS suite: DNS, TCP, handshake, chain, validation, TLS 1.0–1.3 matrix, SNI diff, multi-IP diff, weak ciphers, HTTP redirects |
| `/local [cert]` | Client machine: OS, clock skew vs server, proxy, Windows stores/root-CA presence, certutil chain engine, Schannel events |
| `/cert inspect <file> [host]` | Parse PEM/DER cert or chain file: dates, SANs, fingerprints, chain order |
| `/cert match <cert> <key>` | Prove key belongs to cert (digest comparison only) |
| `/server connect · status · disconnect` | Interactive SSH setup with verified host keys |
| `/server overview · nginx · cert · config · logs · compare` | The read-only server-side checks listed above |
| `/diagnose` | Correlate everything into ranked causes (confirmed / probable / possible) with evidence + remediation |
| `/report [html\|json\|both] [path]` | Self-contained HTML and/or machine-readable JSON |
| `/report agent [dir]` | AI-ready export of the latest completed scan: `agent-report.md` (paste into any AI model; ends with a built-in analysis prompt) and `agent-report.json` (findings contract), in `./ssl-doctor-agent-report-<timestamp>/` or `dir`. Nothing is sent anywhere |
| `/copy [all]` | Copy the previous command's response (or the whole session) to the clipboard as plain text |
| `/typewriter [on\|off\|speed <n>]` | Gradual output on an interactive terminal |
| `/timeout`, `/findings`, `/clear`, `/help`, `/version`, `/exit` | Session utilities |

JSON reports follow the versioned **findings contract** (currently `1.5`;
schemas in [`schemas/`](schemas/), reference in
[`docs/findings-contract.md`](docs/findings-contract.md)). Minor versions only
add fields, so 1.0–1.4 documents keep validating.

`ssldoctor.py agent enroll|run` runs SSL Doctor as an outbound-only scan agent
for the optional service in [`service/`](service/); see
[`docs/agents.md`](docs/agents.md).

## Security behavior

- Host keys are verified against `~/.ssl-doctor/known_hosts` before every SSH
  connection; **unknown keys require an explicit "yes", changed keys are
  refused** (MITM alarm) — never silently accepted.
- SSH passwords never appear on the command line: an `SSH_ASKPASS` helper
  (0700, private state dir) answers in a detached session, and is deleted on
  disconnect.
- No `sudo`, no service restarts, no config edits — when the account lacks
  rights, checks report `NOT TESTED` and say exactly what rights are needed.
- Windows-only checks (stores, certutil, Schannel) activate solely on Windows.

## Windows client checks

- **`local.rootca`** looks up the *root* the presented chain leads to, found by
  path building. It is never the issuer of whichever certificate happens to be
  sent last. When the server's chain is incomplete, broken or unread, the check
  reports `NOT TESTED` ("presented chain incomplete; anchor cannot be
  determined"). It does not blame the client's root store, because the fault is
  the server's (see `tls.chain`).
- **`local.certutil`** runs automatically during `/scan` and `/local`. It
  validates the leaf the server presented with the Windows chain engine (what
  Schannel applications use), so no certificate file is needed.
  `/local <file>` still checks a specific file instead.

## Layout (intentionally flat)

```
ssldoctor.py            entry point
ssl_doctor/
  cli.py                REPL, theme/frames/spinner, banner, prompts, scan orchestration
  tui.py                full-screen shell: layout, transcript, composer, key reader
  findings.py           PASS/FAIL/WARNING/NOT TESTED model + session store
  certs.py              offline certificate parsing + key matching (digest-only)
  netchecks.py          target parsing, domain profile, DNS/TCP/TLS/HTTPS checks
  local.py              client machine + Windows-specific diagnostics
  server.py             SSH transport, host-key trust, nginx config analysis
  analyze.py            correlation rules -> prioritized root causes, unresolved findings
  report.py             JSON + HTML report rendering
  contract.py           findings-contract schema, validation, redaction
  agent.py              outbound-only scan agent (`ssldoctor.py agent`)
schemas/                published findings-contract JSON schemas (1.0-1.5)
docs/                   contract, agents, executed commands, execution flow
service/                optional multi-tenant service (separate package)
tests/                  unittest suite (`python -m unittest discover -s tests`)
```
