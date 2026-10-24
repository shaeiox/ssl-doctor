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
warning. `tls.sni` reports how the server answers with and without SNI as an
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
version. `relaxed-only` is a warning with the policy limitation attached,
`relaxed-only-unverified` is a warning plus a diagnosis note and no claim about
server support, and a probe this client could not perform (no protocols or
ciphers available in its default context) is reported as a limitation of the
test, never as a server refusal.

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
  cli.py                REPL, prompts, colors, spinner, scan orchestration
  findings.py           PASS/FAIL/WARNING/NOT TESTED model + session store
  certs.py              offline certificate parsing + key matching (digest-only)
  netchecks.py          target parsing, domain profile, DNS/TCP/TLS/HTTPS checks
  local.py              client machine + Windows-specific diagnostics
  server.py             SSH transport, host-key trust, nginx config analysis
  analyze.py            correlation rules -> prioritized root causes
  report.py             JSON + HTML report rendering
```
