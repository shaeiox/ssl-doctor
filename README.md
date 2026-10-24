# SSL Doctor v0.3.0

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

## Terminal look

The interface follows the Claude Code terminal design language: warm
terracotta accents, a two-stroke wordmark, and frames that tell you *who* is
working. On startup:

```
════════════════════════════════════════════════════════════════════
  ██████ ██████ ██       █████  ██████ ██████ ██████ ██████ ██████
  ██     ██     ██       ██  ██ ██  ██ ██       ██   ██  ██ ██  ██
  ██████ ██████ ██       ██  ██ ██  ██ ██       ██   ██  ██ ██████
      ██     ██ ██       ██  ██ ██  ██ ██       ██   ██  ██ ██  ██
  ██████ ██████ ██████   █████  ██████ ██████   ██   ██████ ██  ██

  offline ssl/tls diagnostics · client · server · chain · nginx
  creator: eleven  ·  v0.3.0
  all checks are read-only; credentials are never logged
════════════════════════════════════════════════════════════════════
```

- **Hot pink frames** wrap work the tool did (`/tls`, `/local`, `/server …`,
  one block per command, findings as rows, counters in the footer).
- **Lavender frames** wrap a question that is waiting on you, with the keys to
  press. Answers behave exactly as before — only the presentation is new.
- **Dashed ASCII input** (`- - -`, `| > `) is the prompt; it is deliberately
  not Unicode box drawing.
- **Thinking indicator**: `· ✢ ✳ ✶ ✻ ✽` reverse-mirror spinner plus a verb
  (`✳ Chaining…`) while network or SSH work runs. Determinate progress is a
  counter (`▸ Step 2/4`), never a progress bar.
- Status is carried by glyph **and** word **and** colour, so it survives a
  monochrome capture: `✓ PASS`, `⚠ WARNING`, `✗ FAIL`, `? NOT TESTED`.

```
  ┌─ /scan shop.example:443 ───────────────────────────────────────────┐
  │ ✓ PASS       tls.verify           certificate validation (system
                                      trust)
  │   • TLS 1.3 · TLS_AES_256_GCM_SHA384 · chains to a trusted root
  │ ✗ FAIL       tls.chain            server presents a complete, linked
                                      chain
  │   • the server sends only the leaf certificate (1 certificate)
  │   fix: append the intermediate to ssl_certificate on the nginx
  │   server
  │ ⚠ WARNING    tls.hostname         certificate covers the requested
                                      name
  │   • subjectAltName covers www.shop.example only
  │ ? NOT TESTED tls.verify.rootonly  roots-only validation
  │   • skipped in this example; see the check table above
  └─ 1 passed · 1 failed · 1 warnings · 1 not tested ──────────────────┘
  ┌─ Run authorized server-side checks (SSH)? ─────────────────────────┐
  │  [Y]es  [N]o   default: no
  └────────────────────────────────────────────────────────────────────┘
```

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
| `TERM=dumb`, Windows console without ANSI, or an encoding that cannot render `✓ │` | plain / dashed ASCII frames |

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
| `/timeout`, `/findings`, `/clear`, `/help`, `/version`, `/exit` | Session utilities |

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
  cli.py                REPL, theme/frames/spinner, prompts, scan orchestration
  findings.py           PASS/FAIL/WARNING/NOT TESTED model + session store
  certs.py              offline certificate parsing + key matching (digest-only)
  netchecks.py          target parsing, domain profile, DNS/TCP/TLS/HTTPS checks
  local.py              client machine + Windows-specific diagnostics
  server.py             SSH transport, host-key trust, nginx config analysis
  analyze.py            correlation rules -> prioritized root causes
  report.py             JSON + HTML report rendering
```
