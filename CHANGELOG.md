# Changelog

## v0.11.1 — no faults reported on healthy systems

Fixes seven cases where a healthy server or client was reported as faulty
(audit findings A–H): permission-limited `nginx -t`, certbot key symlinks,
shared certificates across server blocks, certutil output, stale clock
references, invisible renewal schedules, and client-side checks deciding the
endpoint verdict. Findings contract stays **1.7**; no schema change.

### Changed

- **BREAKING for scripts that use the exit code:** a failing check about the
  machine running SSL Doctor (`local.*`, for example `local.clockskew` or
  `local.certutil`) that no root cause explains now makes the overall result
  WARNING instead of FAIL, so a batch run exits 0. The overall result and exit
  code describe the endpoint and its server. The finding stays listed under
  unexplained findings, and a confirmed client cause still gives FAIL (exit 1).

### Fixed

- **An unprivileged SSH account no longer gets a "configuration test fails"
  diagnosis on a valid nginx configuration.** `nginx -t` run without root cannot
  open the pid file or error log and always ends with "configuration file …
  test failed"; that summary line defeated the permission check, so
  `srv.configtest` was FAIL with a confirmed cause and the scan exited 1. The
  test is now classified from its error-level lines only (nginx `[emerg]`/
  `[alert]`/`[crit]`, Apache `AH…`, HAProxy `[ALERT]`). Access errors alone give
  NOT TESTED `permission-denied`, naming the files and keeping "syntax is ok".
  A non-zero exit with no recognised error is NOT TESTED `command-failed`.

- **certbot keys are no longer reported as readable by other users.**
  `srv.perms` read the configured path without following links, so certbot's
  `live/<name>/privkey.pem` symlink was judged as mode 777. Mode, owner, group
  and the service account's access are now judged on the file the path
  resolves to, and the evidence names both (`link -> target`). A directory the
  account cannot enter gives NOT TESTED `permission-denied`; an ACL on the file
  is noted as not evaluated. The recommendation names the file and the exact
  `chmod`/`chown`, and never removes the service account's read access.

- **Server blocks that share a certificate no longer contradict each other.**
  With a redirect block reusing the site's certificate, `srv.inventory` marked
  the selected block `[selected, served]` yet warned that the certificate
  "belongs to" the other block, and raised a cause. Certificates are now
  compared by identity: blocks sharing the selected block's certificate are
  listed as "shares the certificate"; blocks that do not listen on the scanned
  port are listed as "other listener" (nginx defaults: port 80 for an address
  without a port, unix sockets never match). Without a presented certificate, a
  covering block is an uncertainty, not a warning.

- **`local.certutil` no longer fails a successful Windows verification.** Any
  "error" in certutil's output - the `dwErrorStatus=0` lines of its chain dump,
  a certificate name, an unreachable revocation URL - made it FAIL, which also
  raised the "Windows chain engine fails" cause. certutil's exit status now
  decides; a failure names its error code (for example `0x800b010a`).
  Unreachable revocation URLs are listed as a warning line of a PASS, and
  certutil that cannot be started is NOT TESTED.

- **Clock skew is measured when the server's `Date` arrived, not when `/local`
  runs.** `/tls` followed minutes later by `/local` reported the waiting time
  as clock skew (FAIL above 300 s). The server time now carries its receive
  time, round trip, source host and `Age` (cached responses are corrected).
  A reference older than 120 s is NOT TESTED; the evidence names the time
  source and the uncertainty, and the thresholds apply to the skew minus that
  uncertainty. The "client clock" cause now needs a date-related validation
  error; a missing issuer is no longer blamed on the clock.

- **Renewal is no longer "not scheduled" when the schedule is just invisible.**
  A non-root SSH account cannot list the root crontab, and the probe treated
  that as empty, so a certbot certificate renewed from root's crontab gave a
  WARNING and a cause. The probe now reports which sources it could read; with
  a schedule source hidden, `srv.renewal` is NOT TESTED `permission-denied`
  naming it. A schedule counts only for the tool that manages the certificate
  (cron entries are reported as `<tool>: <file>`, never their lines).

## v0.11.0 — trustworthy certificate verdicts

Chains are verified by signature, not by names; every certificate in a chain
is judged for dates, constraints, usage and algorithm policy; keys, revocation
(stapled OCSP by default) and the running service are checked without reading
secrets or changing the server. A failing check can no longer disappear from the overall result, and checks
that could not be completed are no longer reported as certificate or key
failures. Findings contract **1.7** (additive; 1.0–1.6 documents keep
validating).

### Changed

- **The overall result counts every failing check.** It used to come from
  matched root causes only, so an endpoint serving an *expired intermediate*
  (`tls.verify` FAIL behind a valid leaf) was diagnosed `PASS` and `-c` exited
  0. A FAIL that no cause rule explains is now listed in
  `diagnosis.unexplained` and makes the result FAIL (exit 1). An unexplained
  warning makes it WARNING. **Scans that used to be PASS with a failing or
  warning check now report FAIL or WARNING.** Failures of the network path
  (timeouts, resets) and of SSL Doctor's own session (SSH login, remote command
  execution) count as WARNING, never FAIL.
- The HTML report rebuilds the same verdict as the JSON document, including
  unexplained findings.

### Fixed

- **An encrypted private key on the server was reported as a confirmed
  key/certificate mismatch.** The pairing hashed the empty output of a failed
  `openssl pkey` and compared it with the certificate. The key's state is now
  classified first (readable, encrypted, unreadable, missing, unsupported) from
  its structure, without reading it into the output. Every openssl step is
  judged by its exit status, and a digest of empty input is never compared.
  Encrypted, unreadable and unextractable keys give `srv.keymatch` NOT TESTED
  (`key-encrypted`, `key-unreadable`, `command-failed`). A real mismatch is
  still FAIL.
- `/cert match`: a DER-encoded encrypted key was FAIL "private key
  unreadable", and a certificate whose public key could not be extracted was
  FAIL "does NOT belong". Both are NOT TESTED now. A missing or unreadable key
  file is NOT TESTED too, and plain DER keys work with OpenSSL 1.1.1.
- **A validation-handshake timeout was a certificate failure.** `tls.verify` /
  `tls.verify.rootonly` that stall or are reset before a verdict are NOT TESTED
  with the failure kind. They raise no certificate cause, and the diagnosis
  says validation was inconclusive. A TLS-level rejection stays FAIL. Both
  validations now connect to the address the TCP check verified, and name it.

### Added (phase 7: revocation, IPv4/IPv6)

- `tls.revocation`: the OCSP response the server staples is fetched (a
  dedicated `openssl s_client -status` handshake to the verified address, since
  Python's ssl module cannot request stapling). It is validated with
  `openssl ocsp`: the signature must verify against the issuer, the response
  must name this certificate, and it must be within its time window. States are
  `good`, `revoked`, `unavailable`, `not-checked` and `inconclusive`, with
  their source. A revoked certificate is a confirmed cause and opens the
  service's `revoked` alert. An invalid stapled response is a server warning.
- `--revocation=staple|online|off` (default `staple`) and the agent job
  option `options.revocation`. `online` asks the CA's OCSP responder, then the
  CRL, for the leaf and each intermediate (privacy note in the README).
- Endpoint comparison probes both address families when DNS publishes both,
  alternating within the cap of 4. Each endpoint is labelled `ipv4` / `ipv6`,
  and the evidence names a difference between the families, or a family that
  is unreachable from this network (never a certificate difference).
  `facts.endpoints[].family` is part of contract 1.7.

### Added (phase 6: service discovery and runtime state)

- `srv.service`: the process listening on the TLS port, from `ss` / `netstat`.
  An unsupported terminator (for example Caddy) or no local listener is
  reported, and nginx-derived causes are then not raised for that endpoint.
- `srv.configtest`: the service's own configuration test (`nginx -t`,
  `apachectl -t` / `httpd -t`, `haproxy -c`), run only for trusted root-owned
  binaries and only in test mode, with the real exit status and a bounded
  summary. A failure caused only by this account's permissions is NOT TESTED,
  not FAIL. `nginx -T` was run before, but its result was discarded.
- Apache httpd and HAProxy: detected from their process titles, with
  configuration read with includes (bounded, candidate evidence). The vhost or
  bind for the domain is reported with its certificate/key/chain paths and
  their states; the certificate and key checks run on files that can be opened.
- `srv.reload`: certificate and key modification times compared with the
  newest worker, plus reload errors from the service journal. "A reload is
  needed" is reported; SSL Doctor never reloads.
- `srv.renewal`: certbot, acme.sh or lego, reported as managing a certificate
  only when its configuration names the configured path (symlinks resolved),
  together with its timer or cron entry. Cron file contents are never read.
- `/server services`, also part of `/scan --with-server` and the server agent.
- A command audit test proves that no state-changing command is executed.

### Fixed (phase 5: server certificate deployment)

- **The configured-vs-served comparison no longer uses a stale file.** A
  fingerprint from an earlier `/server cert` was compared after a later scan
  that could not read its certificate. Each scan now starts a fresh context,
  and the comparison is NOT TESTED when this scan read nothing.
- **RSA + ECDSA configurations.** Every `ssl_certificate` / `ssl_certificate_key`
  pair of the selected block is resolved, validated and paired, and a count
  mismatch is a FAIL. `srv.compare` matches the served certificate against
  each pair, so an ECDSA certificate served from a dual block is no longer a
  mismatch.
- The server block is selected by listen address as well as name, as nginx
  does for `listen 10.0.0.5:443` next to `listen 443`.

### Added (phase 5)

- `srv.compare` also compares the full served chain with the configured file
  and names the first differing position (missing / added / replaced). A
  mismatch is FAIL only against the running instance's configuration.
- `srv.perms` runs in every nginx scan (and so in `/scan` and the server
  agent), judged by role: a private key readable by other users warns, and a
  file the nginx master's account cannot read fails. Only `stat` and `id` are
  run.
- `srv.keystartup`: an encrypted key without a usable `ssl_password_file` is a
  FAIL (nginx could not start). The passphrase file is state-checked, never
  read.
- `srv.inventory`: every TLS server block's certificate, with the selected and
  served ones flagged, and other blocks that also cover the domain.
- Causes for a missing configured file, an unstartable encrypted key,
  unreadable files, a served chain that differs from the file, and an
  alternative certificate.

### Added (phase 4: structured facts, causes, reports)

- `facts.certificates` is filled for the presented chain (`presented`), every
  configured chain file read on the server (`configured:<path>`, also in
  server-agent documents) and `/cert inspect` files (`supplied:<path>`). Each
  entry carries status, trust class, anchor and per-certificate role, dates,
  key, signature, CA flag, KU/EKU, SKI/AKI and link verification. There is no
  key material.
- Service alerts: new conditions `chain_certificate_invalid` (an expired or
  not-yet-valid certificate in the presented chain) and `revoked`. Alert
  evaluation now keys on `facts.leaf`, so server-agent documents with
  configured-chain facts neither alert nor hide a later leaf change.
- Named causes for an anchor that expired and for a non-CA or forged link.
  For a private or unknown trust class judged against this machine's store, an
  *unresolved* entry is raised instead of a cause (this machine may not be the
  client). An encrypted key is named in the notes, with no mismatch concluded.
- `/diagnose`, the HTML report and `agent-report.md` (new subsection 5.8)
  list unexplained findings. The agent report no longer says the overall
  status comes from causes only.

### Fixed (phase 3: trust, lifecycle, policy, hostnames)

- **An expired certificate configured on the server was `srv.cert` PASS.** The
  configured certificate is now judged like the presented one: expired, not
  yet valid, or not covering the domain is FAIL, with a server cause.
- **Every certificate's dates count.** `chain.validity` checks each certificate
  after the leaf. An expired intermediate behind a valid leaf now gets a
  confirmed cause naming the intermediate (it was overall PASS before phase 0,
  and unexplained since). An intermediate that expires before the leaf warns.
- Hostname coverage is a single matcher for `tls.hostname`, `cert.hostname`,
  `tls.sni`, endpoint comparison and the domain profile. It adds IDN (A-label),
  IP-only-for-IP, partial-label and public-suffix wildcard rules, and names the
  matching entry.

### Added (phase 3)

- `chain.trust`: trust class `public` / `private` / `self-signed` / `unknown`
  from verified paths, evaluated offline. The evidence names the trust store and
  its anchor count, or the service CA file that anchors a private chain. An
  expired anchor and an empty store are reported as such.
- `cert.policy` (`policy 1`): weak RSA/DSA keys, unusual EC curves, MD5/SHA-1
  signatures (a root's own self-signature is reported, not judged).
- `--expiry-warn-days 1-365` (default 30). Agent jobs carry
  `options.expiry_warn_days`; the service sends each target's
  `expiry_threshold_days`, and the agent declines an out-of-range value.

### Fixed (phase 2: verified chains)

- **Chains are verified, not matched by name.** Each link of `tls.chain`,
  `nginx.chainfile` and `cert.chainfile` must verify with `openssl verify`: the
  next certificate's key signed it, it is a CA, and `pathLenConstraint` holds.
  A forged intermediate (same name and key identifier, different key) and a
  non-CA "intermediate" used to give `complete` / PASS; they are now FAIL
  (`chain-signature`) with a cause that says the chain does not verify. A
  wrong or misordered intermediate stays a WARNING. Without `openssl`, links
  are name-only and the chain is never PASS.
- Names compare by RFC 5280 rules (case and whitespace).
- Chain findings carry their defect class in `failure_kind`, and the diagnosis
  uses it instead of evidence text. A file that only repeats a certificate is
  no longer reported as "does not send the full chain".

### Added (phase 2)

- Anchoring: a verified self-signed top, or every path to a trusted root (with
  cross-signed CAs, up to 8 paths), chosen by key identifier when roots share
  a name, and noted. `tls.chain` now uses the trust anchors for every chain,
  not only single certificates. A verified chain whose root this machine lacks
  stays complete, marked "anchor unknown". A missing intermediate is named
  with its key identifier and AIA URL; nothing is fetched.
- `chain.usage`: the leaf must allow TLS server authentication (EKU and a Key
  Usage that fits its key type), and issuers need `keyCertSign`, for presented,
  configured and supplied chains. Its cause replaces the generic "validation
  failed" for an unsuitable-purpose error.
- A certificate counts as self-signed only when its own key verifiably signed
  it. Equal names are reported as "self-issued name, not self-signed".

### Fixed (phase 1: strict certificate files)

- **Truncated and corrupt PEM files no longer pass.** A trailing block without
  its END line was ignored (`cert.parse` PASS, "1 certificate"), and a block
  with invalid Base64 still gave PASS plus a warning. Every BEGIN must now have
  its END, and every block must decode as X.509. Otherwise `cert.parse` (and
  `nginx.chainfile` for a configured file) is FAIL, naming the block.
- **A repeated certificate is a duplicate, not a broken chain.** Duplicates are
  listed ("position 3 duplicates position 1") and left out of linkage.
- **A certificate whose subject equals its issuer is a root only if its own key
  signed it.** Self-signatures and issuer signatures are checked with the system
  `openssl verify`, isolated from the system trust store.
- `nginx.chainfile` is FAIL when the file starts with a CA certificate (nginx
  serves the first certificate) and when it is DER-encoded (nginx loads only
  PEM). An unrelated certificate in the file is a WARNING.

### Added (phase 1)

- Formats are detected from content: PEM, DER, PKCS#7, PKCS#12, private keys
  and CSRs, whatever the file is called, each with a conversion hint. Key
  blocks are counted and never read.
- Each certificate record carries its key type, size and curve, signature
  algorithm, Basic Constraints, Key Usage, Extended Key Usage, SKI/AKI, AIA and
  CRL distribution points. Every file and chain finding lists each certificate
  with its role.
- `/cert cafile <file>` and `cert.cafile` for nginx `ssl_trusted_certificate` /
  `ssl_client_certificate`. In a service CA file, intermediates are normal and
  only listed.
- Configured certificate files are read over SSH as base64 (exact bytes, at
  most 1 MiB), falling back to `cat`.

### Added

- Findings contract 1.7: check ids for the coming certificate and service
  checks; failure kinds `verifier-unavailable`, `key-encrypted`,
  `key-unreadable`, `command-failed`, `permission-denied`; optional
  `facts.certificates` and `diagnosis.unexplained`;
  `contract.unregistered_checks()`. Validation keeps accepting check ids from
  later 1.x versions.
- `tests/baseline/`: the recorded test-id list and `record.py --check`, which
  fails when a baseline test disappears, starts skipping or fails.

### Verification

- Integration gate: no private-key line, passphrase or SSH password reaches
  any export (terminal, JSON, HTML, agent report, agent upload); an end-to-end
  `/scan --with-server` names an expired intermediate and a missing reload and
  exits 1. All 45 audited checks are now covered by passing tests
  (`openspec/changes/complete-certificate-diagnostics/verification.md`).

## v0.10.1 — mouse-wheel scrolling on Windows consoles

The full-screen shell scrolls with the mouse wheel in cmd, PowerShell and Git
Bash (winpty) too, and consoles that cannot draw it fall back to line mode with
their own scrollback. No change to checks or the findings contract (1.6).

### Fixed

- **Mouse-wheel scrolling in cmd, PowerShell and Git Bash.** The full-screen
  shell scrolls its transcript itself (the alternate screen has no scrollback),
  but the classic Windows console starts with Quick Edit on, which takes the
  mouse for its own selection, and winpty (Git Bash's `python` alias) forwards
  the mouse only when the program asks for mouse input with Quick Edit off —
  so the wheel never reached the shell there. While it waits for a key the shell
  now switches Quick Edit off and mouse input on, and restores the console's
  mode afterwards.
- **Windows consoles without VT processing** (legacy console mode, old builds)
  no longer get the alternate screen they cannot draw: they use line mode,
  where the console's own scrollback works, with a note saying why.

### Added

- `ssl_doctor/termcaps.py` decides, per terminal, between the full-screen shell
  and line mode and whether the mouse is captured; `SSL_DOCTOR_MOUSE=off` keeps
  the shell without mouse capture. README lists the supported terminals.

## v0.10.0 — nginx certificate paths, per-server settings

Certificate and key paths are resolved the way nginx resolves them and checked
for access before any certificate validation; each remembered server can keep
its own nginx paths. Findings contract **1.6** (one added check id,
`nginx.path_resolution`); 1.0–1.5 documents keep validating.

### Fixed

- **Certificate paths are resolved the way nginx does.** `ssl_certificate` /
  `ssl_certificate_key` were used verbatim, so a relative value such as
  `ssl/fullchain.pem` was looked up in the SSH account's home directory and
  reported as `nginx.chainfile` / `srv.cert` FAIL. Relative values are now
  resolved against nginx's configuration prefix — the directory of the main
  configuration file, nginx's `conf_prefix` (`-p /opt/pvm/nginx/ -c
  conf/nginx.conf` → `/opt/pvm/nginx/conf/ssl/fullchain.pem`) — with the file
  and line each value came from. A file that exists only relative to `-p` is
  reported as one nginx would not open. Values with variables or `data:` are
  reported as not statically resolvable.
- **Validation needs an opened file.** `nginx.chainfile`, `srv.cert` and
  `srv.keymatch` run only on files that could be opened, otherwise NOT TESTED
  with the reason (missing, not readable by this account, not reachable).
  Content without PEM is its own FAIL, distinct from an incomplete chain; a
  root-only key makes the pairing NOT TESTED instead of a warning.
  `/server cert` checks access first, too.

### Added

- **`nginx.path_resolution`** finding (findings contract **1.6**, a new check
  id only): configured value, source line, resolved path, method, file state,
  automatic vs saved origin and any disagreement.
- **Per-server nginx settings:** `/server config show|set|clear [name]`
  (`--cert`, `--key`, `--conf`, `--prefix`) saves manual certificate/key paths
  and main-configuration / prefix overrides in the remembered server's profile
  and reuses them on every connection to that server; `clear` returns to
  automatic discovery. Bare `/server config` is unchanged. Older SSL Doctor
  versions ignore the new profile fields and drop them on their next save.

## v0.9.3 — nginx configuration of the running instance

Server-side nginx analysis starts from the running nginx and says how sure it
is of the configuration it analysed; a working HTTPS endpoint is no longer
contradicted by a configuration that was merely found on disk. Check ids and
the findings contract (1.5) are unchanged.

### Fixed

- **Nginx configuration discovery follows the running nginx.** SSL Doctor used
  `nginx -T` from the account's `PATH` or a fixed `/etc/nginx` file list, so a
  custom installation (e.g. `/opt/pvm/nginx/sbin/nginx -p … -c …`) was analysed
  from an unrelated or partial file and reported "no server block listens on
  port 443" — then diagnosed as "several server blocks claim this domain" —
  while HTTPS worked. Discovery now starts from the running master (`-p`, `-c`,
  `/proc/<pid>/exe`), its systemd unit and its executable's `-V` defaults,
  falls back to a bounded search, follows the `include` graph (expanded where
  each include appears) and attaches an evidence level. `nginx.conf` reports
  that level and every file it could not read; "no server block on port N" is
  concluded only from a complete configuration of the running instance
  (otherwise `nginx.domain` is NOT TESTED); a conflict between server blocks is
  claimed only when two blocks really share a name; and a working endpoint with
  an unconfirmed configuration becomes an unresolved entry instead of a server
  cause. `/server config` and web-server detection use the same discovery.
  Executables named in process titles are run only when root-owned and not
  group/world-writable. Check ids and the findings contract (1.5) are unchanged.

## v0.9.2 — no empty passwords, clearer errors

Empty passwords are never sent or saved, and file, tool and state problems
produce a message instead of a Python exception. No change to checks or the
findings contract (still 1.5).

### Fixed

- **Empty passwords are never used.** An empty or whitespace-only password is
  refused at the prompt and asked again (at most three times, then the
  connection is cancelled); Ctrl-C at the prompt is reported as cancelled
  instead of "empty password". `ServerSession` never runs `ssh` for a password
  login without a usable password, no vault backend saves or returns an empty
  one, and the askpass helpers (`askpass.sh`, `askpass.cmd`, the frozen exe)
  exit non-zero instead of handing `ssh` an empty line.
- **Errors are reported, not raised.** A missing `ssh-keygen` or `openssl`, an
  unusable `~/.ssl-doctor` directory or trust store, an undecodable
  `profiles.json`, a failed profile save (after a successful login), an
  unwritable report path, a missing or corrupt agent state file
  (`ssl-doctor agent run` used to end with a traceback) and Windows
  Credential Manager OS errors now produce a clear message and the session
  continues. An unexpected bug in a command is reported as an internal error
  in that command, without ending the session.

## v0.9.1 — every scan asks which server to use

`/scan` no longer reuses an open SSH session silently for another domain: the
server step asks which server to use. No change to checks or the findings
contract (still 1.5).

### Changed

- **Every `/scan` asks which server to use.** When the server step starts and
  an SSH session is open or servers are remembered, the scan lists the current
  session, the remembered servers (those serving the scanned domain first) and
  `n` for a new one; Enter picks the most likely choice. A session left open by
  an earlier scan is no longer reused silently for another domain. With nothing
  to choose from the connection prompts start directly; batch runs (`-c`)
  never ask.
- A new SSH connection replaces the current session only once it has
  connected: a failed attempt keeps the working session, and `/scan` then
  skips its server step instead of falling back to the old server.

### Documentation

- Brought the reference docs up to v0.9.0: `docs/command-used.md` (version,
  start options, host-key fallback, remembered servers, current test count),
  `docs/execution-flow.md` (version, imported modules, constructor state,
  start options, askpass helper mode, file map with `tui`, `textcells`,
  `clipboard`, `profiles`, `vault` and schemas 1.0–1.5), and the README layout.

## v0.9.0 — remembered servers

Reconnect to a server you have used before with `/server connect <name>`: SSL
Doctor remembers non-secret server profiles and, if you choose, keeps the
password in the operating system's credential vault, bound to the server's
host key. No new dependency; the findings contract stays at 1.5.

### Added

- **Remembered servers.** After a successful `/server connect`, SSL Doctor asks
  whether to remember the server: *profile only* (default), *save password
  too*, or *no*. `/server connect <name>` then connects without the prompts,
  `/server connect` offers the recent servers, and `/scan <domain>` offers the
  matching one. `/servers` lists them; `/server forget <name>|--all` and
  `/server forget-password <name>` delete. Profiles are non-secret
  (`~/.ssl-doctor/profiles.json`, owner-only, atomic, validated on load).
  Saved passwords live only in the OS credential vault — Windows Credential
  Manager or the Linux Secret Service — and are released only after the host
  key is trusted and matches the fingerprint they were saved with; a rejected
  password is deleted, unused ones expire after 90 days, and without a vault
  nothing is saved. `--no-remember` / `SSL_DOCTOR_REMEMBER=off` turn it off;
  batch runs, agents and the service never remember
  ([ADR-001](docs/decisions/ADR-001-remembered-servers.md)).

### Changed

- `/server connect` asks for the password after the host key is verified,
  so no password is collected for a host that will be refused.

## v0.8.4 — server-side checks run again

`/scan` and `/server` checks over SSH get past "reading server identity"
again. No change to checks or the findings contract (still 1.5).

### Fixed

- **`/scan` step 3 stopped with "NameError: name 'fatal' is not defined".**
  The findings-streaming change (v0.7) dropped the remote command from the
  server identity check (`ServerSession.overview()`) while keeping the code
  that reads its result, so every server-side run failed right after
  "reading server identity". The command is back, and a new test drives every
  server check on a connected session against success, empty, error and
  transport-failure replies.

## v0.8.3 — SSH connect: host keys without ssh-keyscan's KEX, Windows passwords

`/server connect` works against servers that pick sntrup761x25519 when the
local `ssh-keyscan` cannot run it, and password logins work on Windows. No
change to checks or the findings contract (still 1.5).

### Fixed

- **`/server connect` failed with "choose_kex: unsupported KEX method
  sntrup761x25519-sha512@openssh.com" while `ssh user@host` worked.**
  `ssh-keyscan` proposes OpenSSH's compiled-in default key exchange list
  unfiltered, and that list always starts with sntrup761x25519; an OpenSSH
  build without it cannot run it once a modern server agrees to it. `ssh`
  filters the same defaults down to what the binary implements. When
  `ssh-keyscan` fails to negotiate a key exchange (or is missing), the host key
  is now read through `ssh` itself: one probe per key type that records the
  key in a scratch file and cannot log in (every authentication method is
  off). Trust checks, change detection and the trust prompt are unchanged.
- **SSH password login on Windows.** The `SSH_ASKPASS` helper was a POSIX
  shell script, which Win32-OpenSSH (it starts the helper with
  `CreateProcessW`) cannot run, so the password never reached `ssh`. On
  Windows the helper is now an `askpass.cmd` that runs the Python interpreter,
  or the frozen `ssl-doctor.exe` itself in helper mode. The password is read
  from the environment and never written into the helper, so characters such
  as `% & | ^ !` survive. Needs OpenSSH 8.4 or newer (`SSH_ASKPASS_REQUIRE`).

## v0.8.2 — result frames straight at every window size

Result frames in the full-screen shell are redrawn to the window on every
resize, and text is measured in terminal cells, so wide characters no longer
push a border out. No change to checks or the findings contract (still 1.5).

### Fixed

- **Result frames stay straight at every window size.** Two causes. A frame
  reached the shell's transcript as text drawn at the width the command ran
  with, so narrowing the window re-wrapped its border rows (the right edge
  broke onto the next row) and widening left it short. Every width was also
  counted in code points, so a CJK character or emoji (an IDN host, a
  certificate subject) pushed the right border one cell out. The transcript
  now redraws each frame at the current width when it is laid out (borders
  rebuilt, rows re-padded, long rows wrapped inside the frame), and all
  measuring, cutting and wrapping is done in terminal cells
  (`ssl_doctor/textcells.py`), including the composer and mouse selection.

## v0.8.1 — Windows mouse wheel, selection and copy

The full-screen shell's mouse wheel, drag-to-select and copy now work on
Windows, and the dependencies are listed in `requirements*.txt`. No change to
checks, output or the findings contract (still 1.5).

### Fixed

- **Mouse wheel, selection and copy on Windows.** The shell read keys with
  `msvcrt.getwch()`, which resets the console input mode to 0 for the length of
  the call and drops every non-key record, so the
  `ENABLE_VIRTUAL_TERMINAL_INPUT` flag set just before it never took effect.
  The terminal was in mouse-reporting mode (no native selection) but no report
  ever reached the shell. The Windows reader now reads `ReadConsoleInputW`
  records under its own raw VT mode, and also decodes native `MOUSE_EVENT`
  records that arrive between keys.

### Added

- **`requirements.txt`** and **`requirements-dev.txt`** spell out the Python
  dependencies in one place: control plane (FastAPI, uvicorn, psycopg,
  multipart), the lazily imported SSO libraries (Authlib, python3-saml,
  xmlsec), `pywin32` on Windows, and the test/build tooling. The CLI stays
  standard-library only, so neither file is needed to run it.

## v0.8.0 — AI-ready reports, copy to clipboard, full-screen shell

`/report agent` exports a scan for any AI model; text can be copied out of a
session (mouse selection, `/copy`, `Ctrl-Y`) on Windows and Linux without extra
software; and the interactive session is now a full-screen application with
result frames, a centred banner and a chat-style composer. The findings
contract stays at 1.5.

### Copy to clipboard

- **`/copy`** copies the previous command's response to the clipboard as plain
  text, exactly as shown (frame borders included, no colour codes); **`/copy
  all`** copies the whole session. Repeating `/copy` copies the same response.
  Works in the full-screen shell and the line REPL.
- Clipboard delivery uses the terminal clipboard escape (OSC 52, also over SSH;
  tmux passthrough supported) and, when installed and its display is present,
  `wl-copy`, `xclip`, `xsel`, `pbcopy` or `clip.exe` — run without a shell, with
  a timeout. The confirmation names the routes and never claims a copy that only
  the terminal escape carried; the copied text is never echoed.
- Passwords read through the masked prompt or `getpass` never enter the recorded
  responses or the copied session.
- **Select-to-copy** in the full-screen shell: drag with the left button over the
  transcript to highlight text (reverse video); releasing copies it and the
  composer confirms. A click without a drag copies nothing; the banner and the
  composer are not selectable. **`Ctrl-Y`** copies the previous response without
  touching what is typed.
- Mouse reporting moves from `?1000h` to button-event tracking (`?1002h`, SGR
  `?1006h`), still enabled only while the composer reads.

#### Fixed

- **Copy did nothing on Linux desktops without a clipboard tool** (seen with
  xfce4-terminal 1.1.3 / VTE 0.76 on Linux Mint 22.3): VTE ignores OSC 52 and
  `xclip`/`xsel`/`wl-copy` were not installed, so neither route reached the
  clipboard. Copies now use the OS clipboard natively — the X11 CLIPBOARD
  selection (served by a detached helper, a fork so frozen builds work) and the
  Win32 clipboard API — before falling back to tools; the escape-only case says
  "copy not confirmed" and points to Shift+drag.
- **Mouse selection and wheel could not work on Windows**: the key reader never
  enabled console VT input, so Windows Terminal's mouse reports never arrived,
  and an escape sequence would have been typed into the composer. VT input is
  now on while one key is read (restored after), and sequences are read whole.

### `/report agent`

- **`/report agent [dir]`** exports the latest completed scan for analysis by any
  AI model (ChatGPT, Claude, Gemini or a local model), without re-running
  anything. It writes `agent-report.md` — metadata, executive summary, target and
  environment, evidence by area, diagnosis with observations, hypotheses,
  probable/confirmed causes and unresolved findings kept apart, recorded next
  steps and missing evidence, then a built-in analysis prompt reproduced
  verbatim — and `agent-report.json`, the same findings-contract document
  `/report json` writes plus scan/environment context in `meta`. Default
  location: `./ssl-doctor-agent-report-<YYYYmmdd-HHMMSS>/`.
- The Markdown is rendered only from the redacted JSON document, so both files
  describe the same scan and carry the same redaction; statuses are never
  upgraded, `NOT TESTED` stays `NOT TESTED`, and missing data reads "not
  recorded" or "not collected in this session".
- Without a completed `/scan` or `/tls` the command explains how to make one and
  writes nothing; an existing report is never overwritten, and a failed write
  leaves neither file behind.
- `/report html|json|both` are unchanged (shared preparation, byte-identical
  output). No schema version change: the agent keys live in `meta`, which every
  published schema leaves open (documented in `docs/findings-contract.md`).

### Full-screen shell, streamed result frames, chat composer

Presentation only: commands, flags, accepted answers, check ids, verdicts, exit
codes, the JSON report payload and the findings contract are unchanged.

- **Full-screen application mode**: the interactive session opens in the
  alternate screen as a terminal-like log — wordmark, then everything you run
  appended underneath it on one left margin. Nothing is centred: the column is
  the window width (capped at 120) and every row starts at the same gutter.
  Output is captured wrapped, never truncated, and stays scrollable; the command
  bar has editing and history, and the spinner and questions live in the status
  line. Opt out with `--no-tui` or `SSL_DOCTOR_TUI=0`; batch runs, pipes and
  `TERM=dumb` keep the line-oriented REPL unchanged.
- **Mouse-wheel scrolling**: the transcript scrolls with the wheel, three rows a
  notch. Reporting is enabled only while the command bar (or a question) is
  reading, so wheel bytes can never reach a running check; `PgUp`/`PgDn` still
  work.
- **`/` completion**: typing a partial command name shows up to three matches
  with their descriptions. `Tab` completes the highlighted one, `↑`/`↓` move the
  highlight, `Esc` or a space dismisses the list. The list is built from the same
  command table `/help` renders.
- **A framed block per result**: each command's findings are drawn in one
  rounded frame whose title is the command, with a row per check (glyph, status,
  check id, title), the evidence/detail/`fix:` lines inside the border, and the
  counters in the closing border. Frames are shared with the line-oriented REPL
  and fall back to `+ - |` corners where box drawing is unavailable.
- **Centred classic banner**: the two-stroke wordmark, its double rules, the
  tagline and `creator: eleven · v<version>` are centred — on the terminal in the
  line REPL and batch runs, in the application column in the full-screen shell.
  The wordmark is centred as one block, so every letter keeps its shape.
- **Chat-style composer** replaces the dashed `| > ` command bar, in the shell and
  the line REPL alike: a rounded box with the label (`ssl-doctor`, the question
  being asked, or the running check) and the session summary in its top border,
  a `❯` input row with a dim placeholder that scrolls to keep the caret visible,
  and the key hints plus `⏎ send` in its bottom border. Terracotta = ready,
  lavender = waiting for an answer, grey = a check is running.
- **Streaming keeps the frame**: on an interactive terminal a result frame opens
  when a phase starts and each finding is drawn into it as its check completes,
  with the counters in the closing border — instead of bare rows outside any box.
  Inside the shell the spinner runs in the composer, so the screen keeps
  redrawing while a long check streams.

#### Fixed

- The shell's capture stream reports itself as a terminal, so after the merge
  with streaming every finding would have been printed as a bare row and the
  screen would only redraw when the command ended. Streaming now draws into the
  result frame and keeps the composer's spinner running.
- `/server compare` printed its finding twice when output was not streamed.
- A finding a check returned without emitting it could be missing from streamed
  output; each phase now reconciles what was emitted with what was returned.
- The typewriter effect no longer types into the shell's capture.
- `failure kind` and `observation` lines are kept inside result frames (they were
  only shown by the unframed printer).
- The banner, the composer and the re-coloured result frames lost their colours
  while a command ran or streamed: the flag that keeps captured output colourless
  also switched off the screen renderer's painter, and the spinner redraws the
  screen during the command. The renderer now has its own painter
  (`paint_screen()`) that only follows the terminal's colour mode.

## v0.7.0 — evidence-grounded TLS diagnosis

Diagnosis fixes from the handshake-attribution, evidence-based-probe,
legacy-protocol and legacy-TLS-semantics work. The findings contract moves from
1.1 to **1.5**; every step is additive and 1.0–1.4 stay published.

### Legacy-TLS diagnosis semantics

On a `google.com:443` scan TLS 1.0/1.1 completed a handshake only under
`ALL:@SECLEVEL=0` and their default-policy probes failed locally with
`NO_PROTOCOLS_AVAILABLE`. The classification was already correct, but the
remediation said to "treat legacy TLS as enabled until proven otherwise", the
open warning was reduced to a free-text note plus the generic "some checks report
warnings/failures", and a match among 4 of 7 DNS addresses read as "all 4
comparable endpoints". Findings contract **1.5** (additive; 1.0–1.4 stay published).

#### Root causes fixed

- The default-policy re-probe outcome was folded into `relaxed-only-unverified`
  without recording *why*: a client that never sent the probe (`client-limited`)
  and a probe without an answer read the same. It is now kept per version in
  `facts.probe_policy.default_probe`, and the evidence row says when nothing was
  sent to the server.
- Findings had no place for "why the evidence cannot settle this", so it lived in
  prose. `Finding.uncertainty` now carries it, separate from `evidence`.
- A warning with no justified cause had no structured home in the diagnosis.
  `diagnosis.unresolved` keeps `observed` / `conclusion` / `uncertainty` /
  `recommendation` apart; the generic note now names the unexplained findings.
- The endpoint comparison had no address count, so a partial match could not say
  it was partial. `endpoint_comparison.addresses` and an explicit coverage caveat
  were added.

#### Changed verdicts by check id

| Check id | Before | Now |
|---|---|---|
| `tls.protocols` (unverified legacy) | "Treat legacy TLS as enabled until proven otherwise … then disable them if accepted" | "Not confirmed - verify before changing anything", with a controlled `openssl s_client -tls1` / `-tls1_1` test and its limitations; the server's configuration is named as authoritative |
| `tls.multiip` | "all 4 comparable endpoint(s) present the same certificate facts" | "the 4 comparable endpoint(s) present the same certificate facts; 3 of 7 DNS address(es) were not compared", plus an uncertainty entry |
| diagnosis | note "Deprecated TLS may be enabled …" + "some checks report warnings/failures" | `unresolved` entry for `tls.protocols`; `overall` stays cause-derived |

### Legacy-protocol evidence

A single warning on `tls.protocols` could claim that "deprecated TLS 1.0/1.1 are
accepted by the server" after probing them only with `ALL:@SECLEVEL=0`. A lowered
security level proves that the server's stack can still negotiate a version when
legacy cipher suites are offered; it does not prove that an ordinary,
default-configured client can connect. The findings contract moves to **1.4**
(additive: per-version `support` classes and four new observations; 1.0–1.3 stay
published and keep validating).

#### Root causes fixed

- `check_protocol_matrix` probed TLS 1.0/1.1 exclusively under the relaxed cipher
  policy, so acceptance was reported as ordinary-client support. A default-policy
  probe now runs for every legacy version that answers, and the two facts are
  recorded separately.
- A probe the local client could not perform (`NO_PROTOCOLS_AVAILABLE`,
  `NO_CIPHERS_AVAILABLE`, `CA MD TOO WEAK`, a local SSL-context error) was returned
  as `refused`, i.e. as a server answer. With a modern OpenSSL build the default
  context has no TLS 1.0/1.1 ciphers, so a legitimate client limitation would have
  read as a server refusal.

#### Changed verdicts by check id

| Check id | Before | Now |
|---|---|---|
| `tls.protocols` | TLS 1.0/1.1 were probed only with `ALL:@SECLEVEL=0`; any answer became `[POSSIBLE · server] "deprecated TLS 1.0/1.1 are accepted by the server"` and the generic "protocol configuration carries compatibility/security risks" cause | Four per-version classes (`default`, `relaxed-only`, `relaxed-only-unverified`, `rejected`/`inconclusive`) and four observations. `default` ⇒ ordinary clients can negotiate the version; `relaxed-only` ⇒ a default-configured client is refused, reported with an explicit limitation; `relaxed-only-unverified` ⇒ a note, a WARNING and no cause about server support. Client-side probe limits are reported as a limitation of the test, never as a refusal |

#### Tests

- `tests/test_protocol_policy.py` (new): legacy accepted under the default policy,
  relaxed-only acceptance, an unverifiable default-policy probe, TLS 1.2 default
  support, TLS 1.3 support, refusals, timeouts before/after the handshake, and the
  diagnosis certainty, limitations and remediation that each case earns.
- `tests/test_probe_consistency.py` updated where it pinned the superseded
  semantics (`relaxed`-only tables, `client-limited` local errors, per-row
  inconclusive assertions).

### Evidence-based probes

Three unsupported warnings from a single scan are fixed at their source, and the
diagnosis now separates what was observed from what it infers. Findings contract
moves to **1.3** (additive: `observation`, `limitations`, `endpoints`,
`endpoint_comparison`, `probe_policy`; 1.0-1.2 stay published and keep validating).

#### Root causes fixed

- `check_multi_ip` compared error strings with certificate fingerprints, so an
  unreachable endpoint read as "different certificate"; it also compared only the
  fingerprint and probed addresses `net.tcp` never verified.
- The protocol matrix never saw the protocol the primary handshake negotiated, a
  timeout row was inert, and relaxed-policy acceptance was not separated from
  default-client interoperability.
- An SNI fingerprint difference was promoted to a virtual-host defect although a
  default certificate for clients without SNI is normal.

#### Changed verdicts by check id

| Check id | Before | Now |
|---|---|---|
| `tls.multiip` | Any difference between endpoint result *strings*, including unreachable endpoints, was a WARNING and a probable server cause | Only endpoints that completed a handshake for the same server name are compared, over fingerprint, hostname coverage and chain status. Fewer than two comparable endpoints ⇒ `NOT TESTED` (inconclusive, no cause); a measured difference ⇒ `WARNING` with both values and a listed limitation |
| `tls.sni` | A differing no-SNI certificate was a WARNING with "check virtual-host configuration", promoted to a possible server cause | An observation (`PASS` + `observation=sni-certificate-differs`); no cause; a missing no-SNI probe is `NOT TESTED`; only a failing handshake for the requested name is `FAIL` |
| `tls.protocols` | A stalled probe could be silent or read as a policy result; relaxed acceptance looked like ordinary support | Rows are accepted / accepted under relaxed policy / refused / inconclusive; a version the primary negotiated is never "refused"; inconclusive rows are retried once inside a budget and prevent a clean PASS; a TLS 1.2 default-policy probe states whether a modern client can connect |

### Handshake failure attribution

Fixes a diagnosis that blamed the server's protocol configuration for a stalled
TLS handshake. The findings contract moves to **1.2** (additive; 1.0 and 1.1
stay published and keep validating).

#### Root cause fixed

- `tls.handshake` recorded a timeout and a protocol/cipher rejection identically
  (`FAIL`, prose evidence only), and the diagnosis mapped on the status alone.
  A run with a stalled handshake next to "TLS 1.0–1.3 accepted" was reported as a
  probable **server** protocol/cipher mismatch.
- The handshake and the per-version probes re-resolved the hostname instead of
  using the address `net.tcp` verified, so they could measure a different
  endpoint than the one that was proven reachable.

#### Changed verdicts by check id

| Check id | Before | Now |
|---|---|---|
| `tls.handshake` | Any failure: `FAIL`, evidence "handshake/connect timed out" or "handshake failed", no structured cause | Failures carry `failure_kind`. A timeout is retried once: a recovered stall is `WARNING` (and still yields all certificate facts), a repeated stall is `FAIL`. A rejection is `FAIL` on the first attempt. Evidence names the phase, the probed address and each attempt |
| `tls.protocols` | A timeout was counted as "refused"; the relaxed cipher policy for TLS 1.0–1.2 was undisclosed | Rows are `accepted` / `refused` / `timed out` / `network error`; `failure_kind` is `no-version-accepted` or `no-version-answered`; accepted legacy versions disclose the `ALL:@SECLEVEL=0` policy |
| `tls.handshake` + `tls.protocols` | Contradiction possible: "handshake fails" beside "TLS 1.2/1.3 accepted" | A failed handshake states which versions did answer and that the failure is a stall or rejection on the default path |
| diagnosis | Timeout ⇒ probable **server** protocol/cipher mismatch whenever a version was accepted | Attribution follows `failure_kind`: timeouts and resets are probable **network** causes with path advice; only `tls-alert` can produce a protocol/cipher mismatch (server). Unclassified failures fall back to network with a note |

## v0.6.0 — modern two-stroke startup banner

Adds a modern two-stroke startup banner (wordmark, tagline, credit) sized for
the terminal, with compact fallback for narrow terminals.

## v0.5.0 — warm terminal interface + streaming + typewriter

Presentation-only restyle, following the Claude Code terminal design language.
**Commands, flags, accepted answers, check ids, verdicts, exit codes, the JSON
report payload and the findings contract are unchanged.**

### What looks different

- **Startup banner**: a modern two-stroke wordmark spelling `SSL DOCTOR` between
  double rules, with the description, version, read-only note and
  `creator: eleven`. The full wordmark needs 64 columns; narrower terminals get
  a compact text form, and plain mode draws it with `#` and `=`.
- **Semantic colour roles** (`primary`, `tool`, `accent`, `success`, `warning`,
  `error`, `muted`, `subtle`, `surface`) with TrueColor → 256 → 16 → plain
  degradation. `NO_COLOR` wins over everything; new `SSL_DOCTOR_COLOR=never|always`
  exists for demos and captures. Piped output stays plain.
- **One frame per command**: findings print as rows inside a single rounded box
  for the command that produced them, with the passed/failed/warnings/not-tested
  counters in the closing border. Evidence, detail and `fix:` text are never
  truncated; narrow terminals wrap inside the border and shorten the counter text
  instead.
- **Dashed ASCII input frame** with a `| > ` prompt and a muted status line
  (`target · 12 findings · 1 fail · timeout 8s · ssh off`) that is suppressed in
  batch (`-c`) runs and in plain mode.
- **Questions to the operator** (SSH setup, host-key trust, mode choice) are
  drawn in a lavender frame with key hints; the accepted answer sets are
  identical.
- **Thinking indicator**: `· ✢ ✳ ✶ ✻ ✽` reverse-mirror spinner in terracotta
  with a per-invocation verb replaces the braille spinner. Plain mode prints a
  single muted line. Progress is still a counter, never a bar.
- **HTML report** adopts the same palette (terracotta title rule, hot-pink check
  ids, semantic status pills). Still one self-contained, printable file with no
  scripts, fonts or remote assets.
- ASCII fallbacks (`+ x ! > -`) apply when the terminal encoding cannot render
  the glyphs; on Windows, ANSI is enabled explicitly and plain mode is used when
  that fails.
- `/diagnose` now prints its overall verdict (`PASS`/`FAIL`/`WARNING`) in words
  next to the title instead of encoding it in the title's colour only.

### Fixed

- `/timeout` never reached its handler: the instance attribute `cmd_timeout`
  shadowed the `cmd_timeout()` method, so the command raised
  `TypeError: 'float' object is not callable`. The remote-command timeout is now
  stored as `command_timeout`; `/timeout` reports and sets both timeouts again.

### Compatibility

- Plain mode output is unchanged apart from the status glyph and the `·` → `-`
  bullet substitution, so existing captured logs, tests and CI output keep
  working.
- `python3 -m unittest discover -s tests` covers the theme resolver, glyph
  fallback, frame content, prompt defaults, spinner lifecycle and report skin
  (`tests/test_terminal_ui.py`).


## v0.3.0 — diagnostic correctness

This release fixes how SSL Doctor diagnoses the most common nginx failure: a
certificate installed **without its intermediate**. Results on servers you
checked before may change. These are intended corrections, listed by check id.

### Root cause fixed

- On Python 3.10–3.12, v0.2.0 could not read the certificate chain the server
  sends, so it always saw "leaf only". A correct install and a broken install
  looked identical.
- When the engineer's machine had the intermediate cached, a leaf-only server
  was diagnosed as overall **PASS**, while customers without that cache failed.
- The Windows root-store check crashed on every real Windows host. Had it run,
  it would have blamed the client for server-side chain faults.

### Changed verdicts by check id

| Check id | Before (v0.2.0) | Now (v0.3.0) |
|---|---|---|
| `tls.chain` | Always "server sends only the leaf" on Python 3.10–3.12 | The chain the server **actually sends** (public API, internal API or `openssl s_client`). `PASS` for a complete, linked chain. `WARNING` for missing intermediates or a wrong intermediate (names the broken position). `NOT TESTED` if the chain can't be read |
| `tls.verify.rootonly` | — (new) | Validation against trusted roots only, with no cached intermediates. `PASS` on `tls.verify` with `FAIL` here pinpoints a missing intermediate that the cache was hiding |
| `tls.verify` | Accepted CN-only certificates | Name check uses subjectAltName only (`hostname_checks_common_name = False`), matching modern clients |
| `tls.hostname` | Fell back to the CN | subjectAltName only. A CN-only certificate is `FAIL`, with evidence that modern clients ignore the CN |
| `cert.hostname` | Fell back to the CN | Same SAN-only rule for inspected files |
| `local.rootca` | Crashed into `NOT TESTED` on Windows; when it did run, it looked up the *intermediate* as if it were the root | Reads the real `(der, encoding, trust)` store entries and looks up the root found by path building. `NOT TESTED` ("presented chain incomplete; anchor cannot be determined") when the chain is incomplete |
| `local.certutil` | Only with `/local <file>` | Also runs during `/scan` and `/local` on Windows, against the presented leaf |
| `nginx.domain` | Ignored the listen port; for duplicate names the last block won; any non-exact match was a `WARNING` | Only blocks on the target port count; first block wins; duplicates and fallbacks are `WARNING`; wildcard/regex matches are `PASS` |
| `nginx.certref` | Only reported when missing | Also reports the resolved paths, including `ssl_certificate` inherited from `http{}` |
| `nginx.chainfile` | Counted `BEGIN CERTIFICATE` (any two certificates passed) | Verifies the leaf comes first and each certificate is issued by the next |

### Diagnosis (`/diagnose`, reports, exit code)

- A missing or wrong intermediate (`tls.chain`, `nginx.chainfile`,
  `tls.verify.rootonly`) is now a **server** cause, ranked ahead of client
  causes, even when validation passes on the engineer's machine.
- `nginx.domain`, `nginx.certref` and `nginx.protocols` now feed the diagnosis.
  Previously no `nginx.*` finding was used.
- The client root-store cause (`local.rootca`) is raised only when the presented
  chain is complete. It is now `probable`, not `confirmed`, because the machine
  running the check may not be the affected client.
- A self-signed certificate is `confirmed` only when the presented chain itself
  shows it.
- "local issuer" validation errors with a *complete* chain are reported as an
  untrusted root, no longer as missing intermediates.
- Check ids are matched exactly; prefix matching would have confused
  `tls.verify` with `tls.verify.rootonly`.

### Other

- One package at the repository root (the v0.1.0 copy was removed), plus
  `pyproject.toml` with an `ssl-doctor` console entry point.
- Regression suite: `python3 -m unittest discover -s tests`. It uses a
  throwaway PKI and local `openssl s_server` fixtures, and skips cleanly
  without `openssl`.
