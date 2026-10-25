# Proposal

## Why

After configuration discovery (v0.9.3) SSL Doctor knows *which* nginx
configuration it analyses, but it still uses `ssl_certificate` and
`ssl_certificate_key` values exactly as written. A relative path such as
`ssl/fullchain.pem` is handed to `cat`/`openssl` relative to the SSH account's
home directory, so the file is "missing" and `nginx.chainfile` / `srv.cert`
report **FAIL** — a path problem shown as a broken certificate or chain. A key
that the diagnostic account may not read (normal for root-only keys) is a
`srv.keymatch` WARNING. And when a custom layout defeats automatic discovery
there is no way to tell SSL Doctor where the files are and have it remember
that for the server, although per-server profiles already exist.

nginx resolves a relative `ssl_certificate` / `ssl_certificate_key` against its
*configuration prefix* — the directory of the main configuration file after
`-c` was resolved against `-p` (`ngx_cycle->conf_prefix`, nginx
`src/core/nginx.c`, `src/event/ngx_event_openssl.c`) — not against the `-p`
prefix and not against the SSH account's working directory. For
`-p /opt/pvm/nginx/ -c conf/nginx.conf`, `ssl/fullchain.pem` therefore means
`/opt/pvm/nginx/conf/ssl/fullchain.pem`. SSL Doctor must apply that rule, say
how it derived each path, and keep path problems apart from certificate
problems.

## What Changes

- **Certificate path resolution.** For the selected server block, every
  `ssl_certificate` / `ssl_certificate_key` value (including ones inherited
  from `http{}`) keeps its original text and its source file and line; it is
  resolved with nginx's rule (absolute as is, relative against the
  configuration prefix; values with variables or `data:` reported as not
  statically resolvable), and the resolved file is checked on the server for
  existence and readability — missing, not readable, and not a regular file
  are reported separately. When the file is missing at nginx's location but
  exists relative to the `-p` prefix, that is reported as a file nginx would
  *not* use.
- **Validation only after access.** `nginx.chainfile`, `srv.cert`,
  `srv.keymatch` run on files that were located and opened; otherwise they are
  NOT TESTED with the reason. Invalid PEM stays distinct from an incomplete
  chain; a key the account cannot read makes the pairing NOT TESTED, not a
  warning. `/server cert <file> [key]` gets the same access checks.
- **New finding `nginx.path_resolution`** (findings contract **1.6**, a new
  check id only): configured value, source, resolved path, method, file state,
  manual vs automatic origin and any disagreement between them.
- **Per-server diagnostic settings** in the existing remembered-server
  profiles: `nginx_mode` (`auto` | `manual`), certificate path, private-key
  path, and optional main-configuration and prefix overrides. Passwords stay in
  the OS vault; the settings live and expire independently of them.
- **Commands:** `/server config show [name]`, `/server config set [name]`
  (prompts, or `--cert`, `--key`, `--conf`, `--prefix`), `/server config clear
  [name]` (back to automatic). Bare `/server config` keeps its current meaning
  (TLS-configuration inventory). Settings apply to the connected server's
  profile, or to a named remembered server; a server that is not remembered is
  offered "remember (profile only)", or the settings apply to this session only.
- **Reuse on reconnect.** Connecting to a remembered server loads its
  settings; manual paths are used without asking again, discovery still runs
  and a disagreement is reported, never silently resolved. When automatic
  resolution fails, the result suggests `/server config set`.
- Read-only on the server throughout (no reload, no file or permission change).
  Not **BREAKING**: existing commands keep their behaviour; documents become
  findings 1.6 (one added check id).

## Capabilities

### New Capabilities
- `nginx-cert-path-resolution`: how configured certificate and key paths are
  turned into server files — nginx's resolution rule, provenance, file-state
  checks, the prefix-relative "would not be used" observation — and how
  certificate validation depends on successful access.
- `server-diagnostic-settings`: per-server nginx settings (auto / manual,
  certificate, key, main configuration, prefix) — commands, storage in the
  remembered-server profile, precedence over automatic discovery, reuse on
  reconnect, and isolation between servers.

### Modified Capabilities
<!-- none: the related capabilities (server-profiles, nginx-config-discovery,
     nginx-vhost-diagnosis) belong to changes that are not archived yet and are
     extended here through new capabilities instead of deltas against them. -->

## Impact

- **Code:** `ssl_doctor/nginx_discovery.py` (configuration prefix, directive
  provenance, path resolver, operator overrides for main configuration and
  prefix); `ssl_doctor/server.py` (file-state probe, `nginx.path_resolution`,
  validation gated on access in `nginx_scan`, `scan_cert`, `_chainfile_finding`,
  `nginx_settings` on the session); `ssl_doctor/profiles.py` (four fields +
  mode, validated); `ssl_doctor/cli.py` (`/server config show|set|clear`,
  loading settings on connect, help, completion); `ssl_doctor/contract.py`
  (1.6, `nginx.path_resolution`); `schemas/findings-1.6.schema.json`.
- **Compatibility:** `profiles.json` stays schema 1 (new optional fields; old
  files load unchanged). An older SSL Doctor reading a newer file ignores the
  new fields and drops them on its next save — noted in the changelog.
- **Docs:** README, `docs/command-used.md`, `docs/execution-flow.md`,
  `docs/findings-contract.md`, CHANGELOG, ADR-001 implementation note, brain.
