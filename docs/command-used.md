# Commands used to troubleshoot in SSL Doctor

Reference for the commands used in this project to diagnose TLS failures and to
verify the project itself. Everything here is **read-only**: no `sudo`, no
service restarts, no config edits, and no credentials in command lines.

- Tool version: **SSL Doctor v0.9.2**
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

---

## 4. Certificate troubleshooting

```text
/cert inspect server.crt
/cert inspect chain.pem example.com
/cert match server.crt server.key
```

- `inspect` parses PEM/DER certificates or a chain file (dates, SANs,
  fingerprints, chain order).
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

Result on this checkout (v0.9.2, Linux): **582 tests run, OK (22 skipped)**. The
skipped tests are platform-bound: the real Windows Credential Manager contract
runs only on Windows (the `windows-latest` CI job), the real Secret Service
contract only with `SSL_DOCTOR_TEST_SECRET_SERVICE=1` on a desktop session, and
a few POSIX/Windows-specific terminal and permission tests on the other OS.

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
