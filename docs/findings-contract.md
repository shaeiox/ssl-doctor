# Findings contract (`findings/1.x`)

Every JSON report, agent upload and service export is a findings document.
Current schema: [`schemas/findings-1.5.schema.json`](../schemas/findings-1.5.schema.json)
(source of truth: `ssl_doctor/contract.py`). Earlier minor versions stay
published: [`findings-1.4`](../schemas/findings-1.4.schema.json),
[`findings-1.3`](../schemas/findings-1.3.schema.json),
[`findings-1.2`](../schemas/findings-1.2.schema.json),
[`findings-1.1`](../schemas/findings-1.1.schema.json),
[`findings-1.0`](../schemas/findings-1.0.schema.json).

| Version | Change |
|---|---|
| 1.0 | Initial contract |
| 1.1 | Optional `facts` block: `leaf` (`sha256`, `subject`, `not_after`) and `chain_status` (`complete`/`incomplete`/`broken`/`unread`). Monitoring uses it for drift and expiry |
| 1.2 | Optional `failure_kind` on every finding, and `handshake_ip` / `handshake_failure` in `facts`. Separates *what went wrong* from the finding status, so a stall is never read as a protocol/cipher rejection |
| 1.3 | Optional `observation` on findings (what was *seen*, not a failure), `limitations` on every cause (where its evidence is incomplete), and `endpoints` / `endpoint_comparison` / `probe_policy` in `facts`. Lets the diagnosis separate observations from defects and state its confidence honestly |
| 1.4 | Per-version probe classes in `facts.probe_policy.support` (`default`, `relaxed-only`, `relaxed-only-unverified`, `rejected`, `inconclusive`) plus `confirmed_legacy` / `unverified_legacy`, and three new observations that say which policy actually proved deprecated-TLS acceptance. A relaxed-policy handshake can no longer be reported as ordinary-client support |
| 1.5 | Optional `uncertainty` on findings (why the evidence cannot settle the question), `diagnosis.unresolved` (warnings kept visible without a root cause), `facts.probe_policy.default_probe` (raw default-policy probe state, `client-limited` = never sent) and `facts.endpoint_comparison.addresses` (DNS addresses, so partial coverage is explicit) |

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
| `probe-inconclusive` | `tls.protocols` | at least one protocol-version probe produced no definite result and no stronger class applied |
| `legacy-accepted-default` | `tls.protocols` | a deprecated version (TLS 1.0/1.1) was accepted with the default cipher policy, so an ordinary client can negotiate it |
| `legacy-accepted-relaxed-only` | `tls.protocols` | a deprecated version answered only when legacy cipher suites were offered, and the default-policy probe was refused: the server still speaks it, but a default-configured client is rejected |
| `legacy-accepted-unverified` | `tls.protocols` | a deprecated version answered only under the relaxed policy and the default-policy probe could not produce a result (client limitation or timeout), so ordinary-client compatibility is unknown |
| `tls12-relaxed-only` | `tls.protocols` | TLS 1.2 answers only when legacy cipher suites are offered, and the default-policy probe was refused: default-configured clients cannot negotiate it |

## Cause limitations (`limitations`)

Every cause lists the material gaps in its evidence, for example "only the first
endpoints returned by DNS were compared" or "legacy acceptance was probed with a
relaxed cipher policy". A cause with no limitations is one that rests on a
direct, complete measurement.

## Protocol probe policy (`facts.probe_policy`)

| Key | Meaning |
|---|---|
| `negotiated` | the protocol the primary handshake negotiated, if any |
| `relaxed_versions` | versions that needed `ALL:@SECLEVEL=0` to answer |
| `support` | per version (`TLS 1.0` … `TLS 1.3`): `default`, `relaxed-only`, `relaxed-only-unverified`, `rejected`, `inconclusive` |
| `confirmed_legacy` | deprecated versions accepted under the default policy (`default` only) |
| `unverified_legacy` | deprecated versions accepted under the relaxed policy whose default-policy probe gave no result |
| `default_probe` | per re-probed version: `accepted`, `refused` (the peer answered no), `client-limited` (this client could not offer the version, nothing was sent), `inconclusive`, `unsupported` |

`default` is the only class that establishes ordinary-client interoperability. A
version the primary handshake negotiated is never reported as `rejected`. A probe
the local client could not perform (no applicable protocol or cipher in the
default context) is `relaxed-only-unverified` or `inconclusive`, never `rejected`.

## Unresolved findings (`diagnosis.unresolved`)

A warning whose evidence justifies no root cause stays visible here instead of
disappearing into a generic note. Each entry keeps three things apart:
`observed` (what the probe saw), `conclusion` (the most the evidence supports)
and `uncertainty` (why the probes cannot settle the question), plus the
`recommendation` for a controlled verification. `overall` is still derived from
causes only.

## Endpoint states (`facts.endpoints`)

| `state` | Meaning | Comparable? |
|---|---|---|
| `negotiated` | handshake completed; certificate facts captured | yes |
| `tls-rejected` | the peer answered with a TLS alert | no |
| `tcp-unreachable` | the address could not be reached | no |
| `timed-out` | connect or negotiation exceeded the deadline | no |
| `probe-unavailable` | handshake completed without a readable certificate | no |

`endpoint_comparison` reports `addresses` (unique DNS addresses), `probed` and
`comparable`. A match covers the `comparable` endpoints only; when it is lower
than `addresses` the finding says how many were not compared.

## Agent reports (`meta.report_kind = "agent"`)

`/report agent` writes `agent-report.json`: the same document `/report json`
produces for the session (same `summary`, `findings`, `diagnosis`, `facts`),
with run context added under `meta`. `meta` is an open object in every
published schema, so no schema version changes.

| Key | Meaning |
|---|---|
| `meta.report_kind` | `"agent"` |
| `meta.agent_report.scan` | `host`, `port`, `sni`, `ips`, `handshake_ip`, `protocol`, `cipher`, `final_url` of the latest completed scan; `first_finding_utc` / `last_finding_utc`; `targets` (every distinct finding target in the session) |
| `meta.agent_report.environment` | `tool`, `python`, `openssl`, `platform` of the process that ran the session; `local_os_evidence` (the `local.os` finding's evidence, or `null` when `/local` did not run) |
| `meta.agent_report.configuration` | `network_timeout`, `command_timeout`, `ssh_connected` |

Values the scan did not record are `null`; they are never inferred. The
companion `agent-report.md` is rendered from this (redacted) document only.

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

**Nginx configuration evidence.** `nginx.conf` says which configuration the
`nginx.*` findings come from and how it relates to the running nginx; its first
evidence line is `evidence level: <level>` — `runtime-verified`,
`runtime-associated`, `candidate` or `none`. Status: `PASS` = complete include
graph of the running instance; `WARNING` = candidate or incomplete graph (the
reason is in `uncertainty`); `NOT TESTED` = nothing could be read. When the
graph is not a complete one of the running instance and no block matches the
port, `nginx.domain` is `NOT TESTED` (with `uncertainty`), never a `WARNING`
claiming the absence; the diagnosis then raises no nginx-derived server cause
and may add an `unresolved` entry for `nginx.conf`.
