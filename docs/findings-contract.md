# Findings contract (`findings/1.x`)

Every JSON report, agent upload and service export is a findings document.
Current schema: [`schemas/findings-1.3.schema.json`](../schemas/findings-1.3.schema.json)
(source of truth: `ssl_doctor/contract.py`). Earlier minor versions stay
published: [`findings-1.2`](../schemas/findings-1.2.schema.json),
[`findings-1.1`](../schemas/findings-1.1.schema.json),
[`findings-1.0`](../schemas/findings-1.0.schema.json).

| Version | Change |
|---|---|
| 1.0 | Initial contract |
| 1.1 | Optional `facts` block: `leaf` (`sha256`, `subject`, `not_after`) and `chain_status` (`complete`/`incomplete`/`broken`/`unread`). Monitoring uses it for drift and expiry |
| 1.2 | Optional `failure_kind` on every finding, and `handshake_ip` / `handshake_failure` in `facts`. Separates *what went wrong* from the finding status, so a stall is never read as a protocol/cipher rejection |
| 1.3 | Optional `observation` on findings (what was *seen*, not a failure), `limitations` on every cause (where its evidence is incomplete), and `endpoints` / `endpoint_comparison` / `probe_policy` in `facts`. Lets the diagnosis separate observations from defects and state its confidence honestly |

## Versioning

- `schema_version` is `"<major>.<minor>"`. Consumers accept only the major
  version they support and reject others with an error naming both versions.
- **Minor** versions only add: new optional fields or new check ids.
- **Major** versions may rename or remove fields or check ids.

## Failure classification (`failure_kind`)

`status` says what the outcome was; `failure_kind` says what went wrong. Both are
needed: a stalled handshake and a rejected handshake both end in `FAIL`, but they
have different owners (network path vs. server configuration). The value is `""`
when nothing failed, including every `PASS`.

| `failure_kind` | Emitted by | Meaning |
|---|---|---|
| `""` | any check | no classified failure |
| `connect-timeout` | `tls.handshake` | the TCP connect to the probed address timed out |
| `negotiation-timeout` | `tls.handshake` | the socket opened, but the peer sent no TLS response in time |
| `tls-alert` | `tls.handshake` | the peer rejected the offer with a TLS alert or no shared cipher |
| `network-error` | `tls.handshake` | the connection was reset or became unreachable during negotiation |
| `no-version-accepted` | `tls.protocols` | every per-version probe was refused |
| `no-version-answered` | `tls.protocols` | every per-version probe stalled or errored without a TLS answer |
| `probe-inconclusive` | `tls.protocols`, `tls.multiip` | the probe could not establish a result from the available evidence |
| `endpoint-unreachable` | `tls.multiip` | no endpoint could be reached, so no certificate evidence exists |

A `WARNING` on `tls.handshake` with a timeout-class `failure_kind` means the stall
was confirmed by a second attempt, which then completed.

## Observations (`observation`)

An observation says what was *seen*; it is not a failure and must not be turned
into a configuration defect on its own. `""` means "nothing notable observed".

| `observation` | Emitted by | Meaning |
|---|---|---|
| `endpoint-certificate-difference` | `tls.multiip` | two or more comparable endpoints presented different certificate facts |
| `endpoint-comparison-inconclusive` | `tls.multiip` | fewer than two endpoints yielded comparable certificate evidence |
| `sni-certificate-differs` | `tls.sni` | a different certificate is served when the client sends no SNI (normal for name-based virtual hosting) |
| `sni-without-probe-failed` | `tls.sni` | the certificate served without SNI could not be obtained |
| `probe-inconclusive` | `tls.protocols` | at least one protocol-version probe produced no definite result |

## Cause limitations (`limitations`)

Every cause lists the material gaps in its evidence, for example "only the first
endpoints returned by DNS were compared" or "legacy acceptance was probed with a
relaxed cipher policy". A cause with no limitations is one that rests on a
direct, complete measurement.

## Endpoint states (`facts.endpoints`)

| `state` | Meaning | Comparable? |
|---|---|---|
| `negotiated` | handshake completed; certificate facts captured | yes |
| `tls-rejected` | the peer answered with a TLS alert | no |
| `tcp-unreachable` | the address could not be reached | no |
| `timed-out` | connect or negotiation exceeded the deadline | no |
| `probe-unavailable` | handshake completed without a readable certificate | no |

## Secrets

Documents never contain passwords, private keys or tokens. Serialization
scrubs the session's known secret values (plain, URL-encoded, base64 and hex
forms) and any `PRIVATE KEY` PEM block, replacing them with `[REDACTED]`.

## Check-id registry

| Check id | Meaning |
|---|---|
| `net.dns` | DNS resolution of the target hostname |
| `net.tcp` | TCP connectivity to the target port |
| `tls.handshake` | Unauthenticated TLS handshake: protocol, cipher, presented chain |
| `tls.certvalid` | Validity period of the presented leaf |
| `tls.hostname` | Hostname coverage by subjectAltName |
| `tls.chain` | Completeness and linkage of the chain the server sends |
| `tls.verify` | Validation against the full system trust store |
| `tls.verify.rootonly` | Validation against trusted roots only (no cached intermediates) |
| `tls.protocols` | TLS protocol version matrix |
| `tls.sni` | Behaviour with and without SNI (an observation, not a defect claim) |
| `tls.multiip` | Certificate consistency across comparable DNS endpoints (unreachable endpoints are not compared) |
| `tls.weakcipher` | Acceptance of obsolete cipher suites |
| `https.response` | HTTPS response and redirect analysis |
| `scan.domain` | Domain identity profile |
| `local.os` | Operating system and clock |
| `local.clockskew` | System clock versus server clock |
| `local.proxy` | Proxy configuration |
| `local.certstore` | Windows certificate stores |
| `local.rootca` | Expected root CA present in the Windows ROOT store |
| `local.certutil` | Windows chain engine validation (certutil) |
| `local.events` | Schannel event log |
| `cert.parse` | Certificate file parsing |
| `cert.validity` | Validity period of an inspected certificate file |
| `cert.selfsigned` | Self-signed inspected certificate |
| `cert.hostname` | Hostname coverage of an inspected certificate file |
| `cert.chainfile` | Chain structure inside an inspected file |
| `cert.keymatch` | Certificate / private key pairing (digest comparison) |
| `ssh.hostkey` | SSH host key verification |
| `ssh.auth` | SSH authentication |
| `ssh.state` | SSH session state |
| `srv.os` | Server OS and identity |
| `srv.web` | Web server detection |
| `srv.cert` | Certificate file on the server |
| `srv.keymatch` | Certificate / key pairing on the server |
| `srv.perms` | Certificate and key file permissions |
| `srv.tlsconf` | TLS virtual host configuration overview |
| `srv.logs` | TLS-related service log entries |
| `srv.compare` | Configured versus presented certificate |
| `nginx.conf` | Nginx configuration source |
| `nginx.blocks` | Nginx server block inventory |
| `nginx.domain` | Nginx server block selected for the domain and port |
| `nginx.protocols` | Nginx ssl_protocols of the selected block |
| `nginx.ciphers` | Nginx ssl_ciphers of the selected block |
| `nginx.certref` | Certificate and key referenced by the selected block |
| `nginx.chainfile` | Linkage of the ssl_certificate file |
