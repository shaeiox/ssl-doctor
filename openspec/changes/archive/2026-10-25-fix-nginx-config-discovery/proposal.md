# Proposal

## Why

`/server nginx` (and the server step of `/scan`) decides which nginx
configuration to analyse by running whatever `nginx` is on the account's `PATH`
with `-T`, or else by reading a fixed list of files under `/etc/nginx` and two
`/usr/local` paths. It never looks at the nginx that is actually running, never
follows `include` directives in that fallback, and reports the result as
`nginx.conf` **PASS**. On a custom installation — e.g. a master started as
`/opt/pvm/nginx/sbin/nginx -p /opt/pvm/nginx/ -c conf/nginx.conf` — it analyses
an unrelated or partial file, finds no block on port 443, and raises
`nginx.domain` WARNING "no server block listens on port 443" while the HTTPS
endpoint answers 200 with a valid certificate. The diagnosis then turns that
warning into *"Several nginx server blocks claim this domain"*, because its rule
treats every non-fallback `nginx.domain` warning as a conflict. Both conclusions
are unsupported by evidence.

## What Changes

- **Runtime-first discovery.** Before reading configuration, find the running
  nginx master (process list: executable, `-p`, `-c`, `-g`; `/proc/<pid>/exe`
  when readable), the systemd unit that owns it (`ExecStart`, unit file, main
  PID) as supplementary evidence, and the build defaults of *that* executable
  (`<exe> -V`: `--prefix`, `--conf-path`). Only if none of these yields a main
  configuration does a bounded candidate search run (fixed roots, depth and
  file limits, no mount crossing).
- **Include graph.** From the selected main configuration, follow `include`
  directives (absolute, relative to the configuration directory, wildcards,
  nested), de-duplicating normalised paths, detecting cycles, and recording
  missing and permission-denied files separately. Files found on disk but not
  reached through the graph are reported as *discovered only* and never
  analysed as active configuration.
- **Evidence levels.** Every analysed configuration carries how it relates to
  the running instance: *runtime-verified* (taken from the running master's own
  arguments or its executable's defaults, graph complete, and no file changed
  since the master started), *runtime-associated*, *candidate (unconfirmed)*,
  or *none found*. `nginx -T` is run only with the executable and arguments of
  the running master (or an operator-set `SSLDOCTOR_NGINX_CMD`), never with an
  unrelated binary from `PATH`.
- **Honest conclusions.** `nginx.conf` reports the discovery outcome (PASS only
  for a complete, runtime-associated graph; WARNING for an unconfirmed or
  incomplete one; NOT TESTED when nothing usable was read). "No server block
  listens on port N" is a conclusion only for a complete, runtime-associated
  graph; otherwise `nginx.domain` is NOT TESTED with the reason in
  `uncertainty`. The diagnosis no longer reports conflicting server blocks
  without a duplicate-name note, and an endpoint that works while the
  configuration cannot be established becomes an *unresolved* entry, not a
  server misconfiguration.
- **Same discovery for `/server config` and `srv.web`**: the TLS-config
  inventory uses the discovered graph instead of fixed `/etc/nginx`
  directories, and web-server detection reports the running nginx master even
  when no `nginx` is on `PATH`.
- Read-only throughout: no reload, restart, configuration or permission
  change; bounded output and timeouts; paths validated before they reach a
  remote shell. Not **BREAKING**: CLI commands, check ids and the findings
  contract (1.5) are unchanged.

## Capabilities

### New Capabilities
- `nginx-config-discovery`: how SSL Doctor identifies the running nginx
  instance and the configuration associated with it — process, service and
  executable evidence, bounded candidate search, include-graph resolution,
  evidence levels, access limitations, and the read-only and bounded-execution
  guarantees of that discovery.
- `nginx-vhost-diagnosis`: what SSL Doctor may conclude from the discovered
  configuration — TLS listener and virtual-host findings qualified by the
  completeness and runtime association of the graph, conflict claims only on
  evidence, and root-cause / unresolved entries that keep network health and
  configuration discovery apart.

### Modified Capabilities
<!-- none: no existing main spec covers server-side nginx analysis -->

## Impact

- **Code:** new `ssl_doctor/nginx_discovery.py` (pure functions: parse process
  list, `nginx -V`, systemd properties; resolve nginx path semantics; build the
  include graph through an injected reader); `ssl_doctor/server.py`
  (`nginx_scan`, `tls_config_scan`, `webserver_detection` use the discovery
  result; the existing parser and block-selection code are reused);
  `ssl_doctor/analyze.py` (nginx vhost rule, unresolved entry).
- **Findings:** same check ids (`nginx.conf`, `nginx.blocks`, `nginx.domain`,
  …); richer evidence and `uncertainty`; status semantics of `nginx.conf` and
  `nginx.domain` tightened as above. Findings contract stays 1.5.
- **Remote commands (read-only):** `ps`, `readlink`/`cat` under `/proc/<pid>`,
  `systemctl show`, `<discovered exe> -V`, bounded `find`, `stat`, `cat` of
  graph files, and `<discovered exe> -T` with its own `-p`/`-c`.
- **Tests:** scripted fake remote for discovery; scenarios for standard,
  custom (`/opt/pvm/nginx`), explicit `-c`/`-p`, not-included `default.conf`,
  undeterminable runtime, HTTPS-works-but-unconfirmed, missing/unreadable files;
  existing nginx tests keep passing.
- **Docs:** README server-side section, `docs/command-used.md`,
  `docs/execution-flow.md`, CHANGELOG, project brain.
