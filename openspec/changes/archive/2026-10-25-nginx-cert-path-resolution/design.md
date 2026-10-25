# Design

## Context

See `proposal.md`. Verified in the code:

- `ServerSession.nginx_scan()` selects the server block from the discovered
  configuration (`nginx_discovery.Discovery`, v0.9.3), then takes
  `ssl_certificate` / `ssl_certificate_key` (or the `http{}` ones) **verbatim**
  and calls `_chainfile_finding(cert)` (`cat <value>`) and
  `scan_cert(cert, key)` (`openssl x509 -in <value>`). Relative values are
  therefore read relative to the SSH account's home directory.
- `_chainfile_finding` returns FAIL "no PEM certificates readable" for a
  missing or unreadable file; `scan_cert` returns `srv.cert` FAIL for any
  `openssl` failure and `srv.keymatch` WARNING when fingerprints cannot be
  derived (e.g. a root-only key).
- Remembered servers: `profiles.Profile` (flat, validated dataclass, schema 1,
  `~/.ssl-doctor/profiles.json`, atomic read-modify-write) keyed by `name` with
  `host`/`port`/`username`; saved passwords live in the OS vault under
  `ssl-doctor:ssh:<user>@<host>:<port>` and expire independently
  (`ProfileStore.expire` only clears `password_saved`). The CLI loads the
  store lazily (`_profiles()`), connects through `_server_connect()` →
  `_ConnectSettings` (with `.profile`), and persists through `_persist()`.
- `/server config` already exists (TLS-configuration inventory,
  `tls_config_scan`).
- nginx's own rule (nginx 1.26.2): `ngx_ssl_load_certificate` and the key
  loader call `ngx_get_full_name(pool, &ngx_cycle->conf_prefix, path)`
  (`src/event/ngx_event_openssl.c:667, 805`); `ngx_process_options` resolves
  `-c` against `prefix` and then sets `conf_prefix` to the directory of the
  resulting file (`src/core/nginx.c:1060–1068`). `include` uses
  `conf_prefix` too (`ngx_conf_full_name(cycle, …, 1)`); `error_log`, `pid` and
  similar use `prefix` (`…, 0`).

## Goals / Non-Goals

**Goals:** resolve certificate/key paths exactly as nginx does, with
provenance; gate certificate validation on file access; store manual
per-server settings in the existing profiles; reuse them on reconnect;
report disagreements instead of hiding them.

**Non-Goals:** resolving variables (`$ssl_server_name`) or `data:` values;
Apache; `ssl_trusted_certificate` / `ssl_client_certificate`; editing or
reloading anything on the server; sharing settings between profiles of the
same host.

## Decisions

### D1. Resolution rule = nginx's configuration prefix
`conf_prefix = dirname(main configuration) + "/"`, where the main
configuration is the one discovery selected (runtime `-c` resolved against
`-p`, build default, unit, search, or operator override). Absolute values are
used unchanged; relative ones become `normpath(conf_prefix + value)`.
*Alternative:* resolve against the `-p` prefix (what the request suggested for
`/opt/pvm/nginx/ssl/…`) — rejected: nginx itself does not, so SSL Doctor would
validate a file nginx never opens. The prefix-relative location is still
checked as an observation (D5).

### D2. Provenance from the graph files
Discovery keeps the read files with their content. For each value used by the
selected block, the first file (in graph order) containing a line
`ssl_certificate[_key] <value>;` gives `file:line`; a value taken from
`http{}` is labelled "inherited from http{}". A value found nowhere (e.g. from
an `-T` dump without file contents) is labelled "line unknown".

### D3. Not statically resolvable
Values containing `$` or starting with `data:` are reported as such; no file
is read and validation is NOT TESTED with that reason.

### D4. File-state probe (one round trip)
New probe primitive `file_states(paths)`: for each safe path (`SAFE_PATH`), one
line `@@SSLDOCTOR <state> <path>` with state `readable` (`-f` and `-r`),
`denied` (`-e` but not `-r`), `notfile` (`-e`, not `-f`), `missing`
(not `-e` and parent searchable), `unreachable` (parent not searchable).
Unsafe paths → `unsupported`, never sent. Implemented by `_SshNginxProbe`
and the in-memory test host; `scan_cert` uses it too.

### D5. The prefix-relative observation
When a relative value resolves to a missing file and the effective `-p` prefix
(runtime or override) differs from `conf_prefix`, `prefix + value` is checked
in the same `file_states` call; if it exists it is reported: "exists, but
nginx resolves `ssl/fullchain.pem` against the configuration prefix
`/opt/pvm/nginx/conf/`, so it would not open this file". It is never
validated as the configured certificate.

### D6. Findings and gating in `nginx_scan`
After block selection: `nginx.certref` (unchanged id; now with provenance and
the resolved path) → **`nginx.path_resolution`** (new) →
`nginx.chainfile` only if the certificate is `readable` (else NOT TESTED
"certificate file could not be opened: <state>") → `scan_cert(resolved cert,
resolved key, key_state)`; `srv.keymatch` NOT TESTED when the key is not
readable. `_chainfile_finding`: readable but no PEM → FAIL "no PEM
certificate in the file" (distinct from the incomplete-chain WARNING).
`scan_cert` used directly (`/server cert`) first calls `file_states` and
returns `srv.cert` NOT TESTED for missing/denied/unreachable files.
`nginx.path_resolution` status per the spec: PASS (both exist, cert
readable) / WARNING (disagreement, or missing in an unconfirmed graph) / FAIL
(missing in a `Discovery.conclusive` graph) / NOT TESTED (unresolvable or
certificate unreadable). Recommendation in automatic mode when not PASS:
"Set this server's paths with /server config set".

### D7. Findings contract 1.6
`nginx.path_resolution` is a new check id → minor bump to 1.6 per
`contract.py`'s policy: `SCHEMA_VERSION = "1.6"`, publish
`schemas/findings-1.6.schema.json` (the schema itself is unchanged apart from
the version note), add the id to `CHECK_IDS` and `docs/findings-contract.md`.
Earlier schemas stay published. *Alternative:* fold resolution into
`nginx.certref` — rejected: the request and the defect both need the
resolution outcome to be separate from the directive and from the content.

### D8. Profile fields (schema 1, additive)
`Profile` gains `nginx_mode` (`auto`|`manual`, default `auto`),
`nginx_cert`, `nginx_key`, `nginx_conf`, `nginx_prefix` (default `""`).
Validation: absolute, `SAFE_PATH` characters, no leading `-`, ≤ 4096 chars;
`manual` needs a certificate or key path. On load, an invalid nginx value is
dropped with a warning and the rest of the profile kept (the profile is not
skipped, unlike invalid connection fields). Old files load unchanged; an older
SSL Doctor would drop the new fields on its next save (changelog note).
*Alternative:* a separate `diagnostics` file keyed by host:port — rejected:
the request asks to extend the existing profile store, and a second store would
need its own identity and lifecycle rules.

### D9. Session settings and discovery overrides
`server.NginxSettings(mode, cert, key, conf, prefix, origin)` lives on the
session (`ServerSession.nginx_settings`, default automatic). The CLI sets it
from the profile after a successful connection (and notes it when not
automatic), and replaces it after `/server config set|clear`; either
invalidates the cached discovery. `nginx_discovery.discover()` takes
`conf_override` / `prefix_override`: the override main configuration is used
instead of the runtime/default one; it counts as runtime-associated only when
it equals what the running master's arguments resolve to, otherwise as
candidate labelled "operator-specified". The prefix override replaces the
runtime prefix for `-c` resolution and D5.

### D10. Commands
`cmd_server`: `config` + `show|set|clear` → settings handlers; bare `config`
(or other words) → the existing inventory. Target: an explicit profile name,
else the connected server's profile (matched by username, host, port), else
the recent-servers pick; when connected without a profile, offer "remember
(profile only)" and fall back to session-only when declined or when
remembering is disabled. `set` takes `--cert/--key/--conf/--prefix` (values
validated with the profile rules; `--cert none` clears one field) or prompts
with the current values as defaults; any cert/key → `manual`. Writes go
through `_persist()`. `show` never prints secrets (there are none) and names
the profile and endpoint. Completion offers `show|set|clear` and profile
names; `/help` lists them.

### D11. Tests
In-memory host (`tests/fixtures/nginx_host.py`) gains file states and an
unreadable/denied model; the real `file_states` script is tested under
`/bin/sh` like the other probe scripts. CLI tests reuse the
`test_remembered_connect.Harness` (temporary profile store, memory vault,
scripted prompts, fake sessions extended with `nginx_settings`).

## Risks / Trade-offs

- [The request expected prefix-relative resolution] → nginx's source decides;
  the prefix-relative file is still surfaced (D5) so a misplaced file is
  visible, and the brief's example holds when the main configuration lives at
  the prefix root (spec scenario).
- [Directive provenance by text search] → identical values in several files
  report the first in graph order; noted in evidence as "first occurrence".
- [Older SSL Doctor drops the new profile fields on save] → documented; no
  schema bump because old code ignores the version anyway.
- [Manual paths go stale after a renewal to a new path] → disagreement with
  discovery is reported every scan; `clear` returns to automatic.
- [Contract 1.6 consumers] → additive; 1.0–1.5 documents keep validating.

## Migration Plan

None required: existing profiles load with `nginx_mode = auto`. Documents
become 1.6. Rollback: revert; profiles written by the new version still load
in the old one (unknown fields ignored).
