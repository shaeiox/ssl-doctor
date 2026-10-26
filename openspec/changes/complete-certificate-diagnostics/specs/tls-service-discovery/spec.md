# Spec Delta

## Purpose

Identifies, read-only, which service on the server terminates TLS for the target, whether its configuration passes the service's own validation, whether it was reloaded after certificate changes, and which renewal tooling manages its certificates.

## ADDED Requirements

### Requirement: The TLS-terminating process is identified (audit #31)
Over SSH and in the server agent, SSL Doctor SHALL report which process listens on the target TLS port, from the socket table when readable. It SHALL map that process to a supported service (nginx, Apache httpd, HAProxy) or name it as unsupported (for example Caddy, Traefik, Java). When the listener cannot be determined, it SHALL report NOT TESTED with the reason.

#### Scenario: nginx owns port 443
- **WHEN** the socket table shows the nginx master listening on 443
- **THEN** `srv.service` is PASS "nginx (pid <n>) listens on :443", and nginx analysis proceeds

#### Scenario: Unsupported terminator
- **WHEN** the listener on 443 is `caddy`
- **THEN** `srv.service` is WARNING "TLS on :443 is served by caddy, which SSL Doctor does not analyse", and no nginx cause is raised for this endpoint

#### Scenario: Socket owner not visible to the account
- **WHEN** the account may list sockets but not their owning processes
- **THEN** `srv.service` is NOT TESTED "listener owner not visible to this account", and the evidence keeps the binaries found on PATH

#### Scenario: Nothing listens on the port
- **WHEN** no socket listens on the target port on this host
- **THEN** `srv.service` is WARNING "no local listener on :<port>; TLS may be terminated elsewhere"

### Requirement: Apache httpd and HAProxy are detected read-only (audit #31)
SSL Doctor SHALL detect running Apache httpd and HAProxy instances and their main configuration files from process arguments and their default locations. It SHALL apply the same trust rules for executing their binaries as nginx discovery (root-owned, not group- or world-writable).

#### Scenario: Apache with a custom configuration
- **WHEN** httpd runs with `-f /opt/web/conf/httpd.conf`
- **THEN** that file is reported as the configuration in use

### Requirement: The native configuration test result is recorded (audit #36)
For each detected supported service whose binary may be executed, SSL Doctor SHALL run its read-only configuration test (`nginx -t` with the instance's `-p`/`-c`, `apachectl -t` or `httpd -t -f`, `haproxy -c -f`). It SHALL record the real exit status and a bounded, redacted stderr summary as `srv.configtest`.

#### Scenario: Configuration test fails
- **WHEN** `nginx -t` exits 1 with "[emerg] cannot load certificate"
- **THEN** `srv.configtest` is FAIL with exit status 1 and that message, and the diagnosis raises a server configuration cause

#### Scenario: Configuration test passes
- **WHEN** `nginx -t` exits 0
- **THEN** `srv.configtest` is PASS with exit status 0

#### Scenario: Test cannot run with this account
- **WHEN** the test fails only because the account cannot read root-only files (for example "Permission denied" on a key)
- **THEN** `srv.configtest` is NOT TESTED "configuration test needs read access to …", not FAIL

#### Scenario: Untrusted binary
- **WHEN** the service binary is group- or world-writable
- **THEN** it is not executed, and `srv.configtest` is NOT TESTED naming the reason

### Requirement: The configuration test is never a state change
The configuration test SHALL be invoked only in its test/dump mode, with a bounded timeout. SSL Doctor SHALL NOT send signals, call `reload`/`restart`/`graceful`, write files, or use `sudo`.

#### Scenario: Command audit
- **WHEN** a full server scan runs
- **THEN** no executed command contains `-s reload`, `reload`, `restart`, `graceful`, `kill`, `systemctl start/stop/restart/reload` or `sudo`

### Requirement: Reload state after certificate changes is evidenced (audit #37)
SSL Doctor SHALL compare the modification time of each configured certificate and key with the start time of the service's current workers (or the master for services without workers). It SHALL report `reloaded after change`, `changed after the last reload`, or `unknown`, plus the most recent reload/start errors from the service journal or error log when readable.

#### Scenario: Certificate replaced but not reloaded
- **WHEN** the configured certificate file is newer than every nginx worker
- **THEN** `srv.reload` is WARNING "certificate changed after the running workers started; a reload is needed for nginx to serve it"
- **AND** no reload is performed

#### Scenario: Reload after renewal
- **WHEN** the workers started after the certificate's mtime
- **THEN** `srv.reload` is PASS

#### Scenario: Reload error in the journal
- **WHEN** the journal holds a recent "reload failed" or "cannot load certificate" line for the service
- **THEN** that line (truncated) appears in the `srv.reload` evidence, and the finding is WARNING

#### Scenario: Times not available
- **WHEN** process start times or file mtimes cannot be read
- **THEN** `srv.reload` is NOT TESTED "reload state unknown"

### Requirement: Renewal tooling is reported only when found (audit #45)
SSL Doctor SHALL look, read-only, for certbot, acme.sh and lego, and for their renewal configuration, systemd timers and cron entries. It SHALL report a tool as managing a certificate only when its configuration names the configured certificate path or its lineage directory.

#### Scenario: certbot manages the configured certificate
- **WHEN** `/etc/letsencrypt/renewal/shop.example.conf` names the `fullchain.pem` that nginx uses, and `certbot.timer` is enabled
- **THEN** `srv.renewal` is PASS "certbot renewal configured for this certificate (timer enabled)"

#### Scenario: Tool present but not linked
- **WHEN** certbot is installed, but no renewal configuration names the configured path
- **THEN** `srv.renewal` is WARNING "certbot is installed but does not manage <path>"

#### Scenario: Nothing found
- **WHEN** no renewal tooling or configuration is found
- **THEN** `srv.renewal` is NOT TESTED "no renewal tooling found"; it does not claim that renewal is manual
