# Findings contract (`findings/1.x`)

Every JSON report, agent upload and service export is a findings document.
Current schema: [`schemas/findings-1.1.schema.json`](../schemas/findings-1.1.schema.json)
(source of truth: `ssl_doctor/contract.py`). Earlier minor versions stay
published: [`findings-1.0`](../schemas/findings-1.0.schema.json).

| Version | Change |
|---|---|
| 1.0 | Initial contract |
| 1.1 | Optional `facts` block: `leaf` (`sha256`, `subject`, `not_after`) and `chain_status` (`complete`/`incomplete`/`broken`/`unread`). Monitoring uses it for drift and expiry |

## Versioning

- `schema_version` is `"<major>.<minor>"`. Consumers accept only the major
  version they support and reject others with an error naming both versions.
- **Minor** versions only add: new optional fields or new check ids.
- **Major** versions may rename or remove fields or check ids.

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
| `tls.sni` | Certificate difference with and without SNI |
| `tls.multiip` | Certificate consistency across DNS endpoints |
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
