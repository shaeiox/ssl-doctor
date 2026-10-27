# Commands used to troubleshoot in SSL Doctor

Reference for the commands used in this project to diagnose TLS failures and to
verify the project itself. Everything here is **read-only**: no `sudo`, no
service restarts, no config edits, and no credentials in command lines.

- Tool version: **SSL Doctor v0.11.1**
- Entry point: `ssldoctor.py` (also installed as the `ssl-doctor` console script)
- Interactive: `python3 ssldoctor.py` (full-screen shell on a terminal; `--no-tui` for the line REPL)
- One-shot: `python3 ssldoctor.py "/tls example.com"`
- Batch: `python3 ssldoctor.py -c "/scan example.com --with-server" -c "/report both out"`

---

## 1. Start and orient

```bash
python3 ssldoctor.py                # interactive REPL
python3 ssldoctor.py /version       # print version and exit
python3 ssldoctor.py /help          # list every slash command
python3 ssldoctor.py -h             # CLI usage/options
python3 ssldoctor.py --no-tui       # line-oriented REPL instead of the full-screen shell
python3 ssldoctor.py --no-remember  # never remember servers or use saved passwords
SSL_DOCTOR_MOUSE=off python3 ssldoctor.py   # full-screen shell without mouse capture (PgUp/PgDn scroll)
```

Useful session utilities:

```text
/version                  show version
/timeout [net_s] [cmd_s]  show/set network timeout (default 8s) and remote command timeout
/findings [scope]         list PASS/FAIL/WARNING/NOT TESTED findings recorded this session
/copy [all]               copy the previous response (all: the whole session) to the clipboard
/clear                    discard recorded findings and the cached diagnosis
/exit                     leave ssl-doctor (also closes any SSH session)
```

---

## 2. Primary troubleshooting workflow

The normal sequence is: **identify the domain → check the client path → check
the server (if authorized) → correlate → report**.

```text
/scan example.com
/scan example.com --client-only
/scan example.com --server-only
/scan example.com --with-server
```

| Command | Scope |
|---|---|
| `/scan example.com` | Combined run: domain identification → client-side checks → asks whether to add SSH server-side checks → diagnosis |
| `/scan example.com --client-only` | DNS/TCP/TLS/HTTPS as seen from this machine, plus local-machine diagnostics. No SSH |
| `/scan example.com --server-only` | Public endpoint measurement + SSH + nginx SSL config + configured-vs-presented certificate. No local checks |
| `/scan example.com --with-server` | Combined run without the SSH yes/no prompt (script-friendly) |

Targets accept `host`, `host:port`, or a URL (`https://example.com/path`).

At the server step every interactive `/scan` asks which server to use: the open
session, a remembered server (domain matches first) or `n` for a new one; Enter
takes the most likely choice.

### Remote TLS/HTTPS suite

```text
/tls example.com
/tls example.com 8443
/tls https://example.com/path
/tls example.com --sni internal.example.com
```

`/tls` covers DNS, TCP, handshake, chain, validation, the TLS 1.0–1.3
matrix, SNI differences, multi-IP differences, weak ciphers, and HTTP
redirects.

### Diagnose and report

```text
/diagnose                  correlate all findings into ranked causes
/report html               write a self-contained HTML report (default)
/report json report.json   machine-readable findings JSON
/report both out           write both out.html and out.json
/report agent              AI-ready agent-report.md + agent-report.json of the latest scan
```

`/report agent` writes into `./ssl-doctor-agent-report-<YYYYmmdd-HHMMSS>/` (or a
directory you name). Give `agent-report.md` to any AI model: it carries the
evidence, the diagnosis with its uncertainty, and an analysis prompt.

---

## 3. Client-machine troubleshooting

```text
/local                     OS, clock skew, proxy, Windows stores, certutil, Schannel
/local /path/to/cert.pem   also validate a specific certificate file on this machine
```

Windows-only checks activate only on Windows. When the server's chain is
incomplete, `local.rootca` reports `NOT TESTED` instead of blaming the client.

Clock skew (`local.clockskew`) compares this machine's clock with the HTTP `Date`
header of the last network check (`/tls` or `/scan`), at the moment that response
arrived:

- The evidence names the host whose `Date` was used (and says so when it is a
  redirect target), the measurement uncertainty (1 s `Date` resolution plus the
  request round trip), and an `Age` correction when a cache served the response.
- WARNING above 60 s and FAIL above 300 s apply to the skew minus its
  uncertainty.
- The reference is valid for 120 s. Running `/tls example.com` and then `/local`
  more than two minutes later gives `NOT TESTED` "server time reference is
  <n>s old; repeat the network check" - run `/tls` again, or use `/scan`, which
  runs the local checks right after the network checks.
- On its own, a failing client-machine check makes the overall result WARNING,
  not FAIL: it describes this machine, not the endpoint.

---

## 4. Certificate troubleshooting

```text
/cert inspect server.crt
/cert inspect chain.pem example.com
/cert match server.crt server.key
/cert cafile roots.pem
```

- `inspect` parses a certificate or chain file strictly by content (PEM, DER;
  PKCS#7, PKCS#12, keys and CSRs are named). It lists every certificate with
  its role, verifies each link's signature with `openssl verify`, and reports
  dates, key usages, key and signature policy and the trust class.
- `/cert cafile <file>` checks a root / CA bundle: only CA certificates that
  their own key signed count as roots.
- `match` proves a key belongs to a certificate using a digest comparison;
  private key material is never printed.

---

## 5. Server-side (nginx) troubleshooting over SSH

```text
/server connect                         interactive SSH setup, verified host keys
/server connect files                   connect to the remembered server "files"
/servers                                list remembered servers (never passwords)
/server forget files                    forget "files" and its saved password
/server forget --all                    forget every remembered server (asks first)
/server forget-password files           delete only the saved password
/server status                          show SSH session state
/server overview                        remote OS / web-server identification
/server nginx example.com               running nginx -> its config graph -> vhost, protocols, ciphers, cert/key
/server nginx example.com:8443          same, for a non-default TLS port
/server cert /etc/nginx/ssl/site.crt /etc/nginx/ssl/site.key
/server config show                     nginx settings in force for this server (auto/manual)
/server config set --cert /opt/pvm/nginx/conf/ssl/fullchain.pem --key /opt/pvm/nginx/conf/ssl/private.key
                                        save this server's certificate/key paths (manual mode)
/server config set files --conf /opt/pvm/nginx/conf/nginx.conf
                                        point discovery at a main configuration for "files"
/server config clear                    back to automatic discovery
/server services                        who serves the TLS port, config test, reload state, renewal
/server config                          scan readable TLS/vhost configuration
/server logs                            recent TLS-related service log entries
/server compare                         configured certificate vs served certificate
/server disconnect                      close the SSH session
```

Nginx configuration comes from the **running** nginx: SSL Doctor reads the
master process (`ps`, `/proc/<pid>/exe|cwd|cgroup`), its systemd unit
(`systemctl show`), the executable's `-V` (only for a root-owned,
non-writable executable), and then the `include` graph of the main file
(`stat`, `base64` of each file). A bounded `find` over `/etc/nginx`,
`/usr/local/nginx`, `/usr/local/etc/nginx`, `/opt` and `/srv` runs only when
none of that names a configuration. `nginx.conf` states the evidence level
(runtime-verified / runtime-associated / candidate / none). Nothing is
reloaded, restarted or written.

For the certificate and key files the configuration names, SSL Doctor runs
only these read-only commands on the server. It handles every
`ssl_certificate` / `ssl_certificate_key` pair, so an RSA + ECDSA block gives
two pairs, and it includes CA files from `ssl_trusted_certificate` /
`ssl_client_certificate`:

| Purpose | Command (paths quoted) |
|---|---|
| file state (exists / readable / not a file / unreachable) | `for p in …; do [ -f "$p" ] && [ -r "$p" ] …; done` |
| certificate bytes (public files only; at most 1 MiB) | `head -c 1048576 -- <cert> \| base64` (fallback `cat <cert>`) |
| certificate details | `openssl x509 -noout -subject -issuer -dates -serial -fingerprint -sha256 -ext subjectAltName -in <cert>` |
| key state (prints one token: readable / encrypted / unreadable / …) | `head -c 4096 <key> \| grep -q …`, `openssl asn1parse -inform DER -in <key> \| head -n 4 \| grep -q …`, `openssl pkey -in <key> -passin pass: -noout` |
| key pairing (public-key digests only) | `openssl x509 -noout -pubkey -in <cert> \| openssl pkey -pubin -outform DER \| sha256sum` and `openssl pkey -in <key> -passin pass: -pubout -outform DER \| sha256sum`, each step reporting its own failure |
| ownership and mode | `stat -c '%U %G %a %F' -- <file>`, and `id -Gn <account>` for the nginx master's account |

For the service itself (`/server services`, and part of `/scan --with-server`):

| Purpose | Command |
|---|---|
| who listens on the TLS port | `ss -H -ltnp` (fallback `netstat -ltnp`) |
| processes, worker start times | `ps -eo pid=,ppid=,user=,etimes=,args=` |
| native configuration test (test mode only, trusted root-owned binary only, real exit status kept) | `<nginx> [-p …] [-c …] -t`, `apache2ctl -t` / `httpd -t [-f …]`, `haproxy -c -f …` |
| Apache / HAProxy configuration | the same framed `base64` read as nginx, with Include/IncludeOptional (at most 3 levels, 60 files) |
| reload evidence | `stat -c '%Y %n'` of the certificate and key, `journalctl -u <unit> -n 200 --no-pager -q` |
| renewal tooling | `command -v certbot acme.sh lego`; certificate-path lines of `/etc/letsencrypt/renewal/*.conf` and acme.sh domain configs; `systemctl list-timers`; names (not contents) of cron files that mention them; `readlink -f` |

Nothing is reloaded, restarted or signalled: a test asserts that no executed
command contains `reload`, `restart`, `graceful`, `kill`, `-s <signal>`,
`systemctl start/stop/restart/reload` or `sudo`.

Revocation (from the client side, to the verified address):

| Purpose | Command |
|---|---|
| stapled OCSP response (default) | `openssl s_client -connect <ip>:<port> -servername <name> -status -msg` |
| validation of a response | `openssl ocsp -respin <resp.der> -issuer <issuer> -cert <cert> -CAfile <issuer> -partial_chain -no_nonce` |
| `--revocation=online` only | `openssl ocsp -issuer … -cert … -url <AIA OCSP> -no_nonce -respout …`; the CRL is fetched over HTTP (at most 10 MiB) and checked with `openssl crl -CAfile <issuer>` |

Signatures, chains and policy are then judged on this machine from the
certificate bytes; key bytes never leave the server. A passphrase file
(`ssl_password_file`) is only state-checked (exists / readable), never read.

Host keys are checked against `~/.ssl-doctor/known_hosts`: unknown keys require
an explicit `yes`, and changed keys are refused (possible MITM). Keys are read
with `ssh-keyscan`, or through `ssh` with every authentication method off when
`ssh-keyscan` cannot negotiate a key exchange. If the account lacks rights,
checks report `NOT TESTED` and name the missing permission.

After a successful connection you can remember the server (profile only by
default, or with its password in Windows Credential Manager / the Linux Secret
Service). A saved password is used only when the host key is trusted and
matches the one it was saved with; see
[ADR-001](decisions/ADR-001-remembered-servers.md).

Example sequence:

```text
/scan example.com --server-only
/server nginx example.com
/server compare
/diagnose
/report both example-tls
```

---

## 6. Agent mode (control plane)

```bash
ssl-doctor agent enroll "$SSLDOCTOR_URL" "$TOKEN" --state /var/lib/ssl-doctor/agent.json
ssl-doctor agent run --state /var/lib/ssl-doctor/agent.json
ssl-doctor agent run --once --state /var/lib/ssl-doctor/agent.json
ssl-doctor agent run --state C:\missing.json   # exits non-zero without state
```

Enrollment tokens are single-use and expire after 24 hours. A revoked agent
exits with status 2.

---

## 7. Commands used to verify the project

Regression suite (the primary check used during development):

```bash
python3 -m unittest discover -s tests -v
```

Result on this checkout (v0.11.1, Linux, as root, project `venv`): **1009 tests run, OK (27 skipped)**. The
skipped tests are platform-bound: the real Windows Credential Manager contract
runs only on Windows (the `windows-latest` CI job), the real Secret Service
contract only with `SSL_DOCTOR_TEST_SECRET_SERVICE=1` on a desktop session, and
a few POSIX/Windows-specific terminal and permission tests on the other OS
(and, when run as root, the unreadable-file discovery, private-key-state and
untraversable-directory permission tests).

Service/control-plane suite (needs its dev extras / throwaway PostgreSQL):

```bash
PYTHONPATH=service python -m unittest discover -s service/tests -v
```

Targeted suites used for specific problems:

```bash
python3 -m unittest discover -s tests -p "test_release_bundle.py" -v
python3 -m unittest discover -s tests -p "test_airgap.py" -v      # may need sudo/netns
PYTHONPATH=service:service/tests python -m unittest test_server_main test_upgrade -v
```

CI equivalent (`.github/workflows/tests.yml`):

```bash
python -m pip install jsonschema
python -m unittest discover -s tests -v
python -m pip install . "./service[dev]"
PYTHONPATH=service python -m unittest discover -s service/tests -v
```

---

## 8. Build, package, and air-gap verification

```bash
python -m pip install . "./service[dev]" "pyinstaller>=6.6" "cyclonedx-bom>=4"
python packaging/build.py                    # writes dist/<os>/
python packaging/release.py --dist dist/linux --dev-key
```

Smoke test the built binary with no Python on `PATH`:

```bash
env -i PATH=/usr/sbin:/sbin HOME=/tmp dist/linux/ssl-doctor /version
dist/linux/ssldoctor-server/ssldoctor-server init \
  --data /var/lib/ssldoctor-server --org "CI" --listen 127.0.0.1:18080
```

Verify a signed offline bundle (only `openssl` and `sha256sum` required):

```bash
openssl pkeyutl -verify -pubin -inkey RELEASE-KEY.pub -rawin \
        -in SHA256SUMS -sigfile SHA256SUMS.sig
sha256sum -c --strict SHA256SUMS
openssl pkey -pubin -in RELEASE-KEY.pub -outform DER | sha256sum
```

Server lifecycle commands:

```bash
ssldoctor-server init --data <dir> --org "<org>" --listen 0.0.0.0:8443
ssldoctor-server run --data <dir>
ssldoctor-server upgrade --data <dir>        # backs up into backups/ first
ssldoctor-server backup --data <dir>
ssldoctor-server verify-audit --data <dir>
ssldoctor-server version
```

---

## 9. Interpreting results

Every check reports one of:

| Status | Meaning |
|---|---|
| `PASS` | The check ran and the evidence is good |
| `FAIL` | The check ran and the evidence proves a fault |
| `WARNING` | Something is wrong but not necessarily fatal |
| `NOT TESTED` | The check could not run; the reason and missing permission are stated |

Key chain checks:

| Check id | What it proves |
|---|---|
| `tls.chain` | The chain the server actually sends: complete, incomplete, or broken |
| `tls.verify` | Validation against this machine's full trust store |
| `tls.verify.rootonly` | Validation against trusted roots only; `tls.verify` PASS + this FAIL means a missing intermediate |
| `tls.hostname` | Name coverage from subjectAltName only (CN-only certificates fail) |
| `local.rootca` | Whether the real root from the path is present on Windows |
| `local.certutil` | Windows chain-engine validation against the presented leaf |
| `nginx.domain` | Which server block nginx would use, and whether it fell back |
| `nginx.chainfile` | Whether the configured certificate file is leaf-first and properly linked |
| `nginx.certref` | Resolved `ssl_certificate` / `ssl_certificate_key` paths |
| `nginx.protocols` | Configured TLS protocol versions, with legacy versions flagged |

A missing or wrong intermediate is treated as a **server** cause, ranked ahead
of client causes even when validation passes on the engineer's own machine.
