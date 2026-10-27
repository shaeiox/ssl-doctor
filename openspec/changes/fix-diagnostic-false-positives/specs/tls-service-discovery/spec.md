# Spec Delta

## MODIFIED Requirements

### Requirement: The native configuration test result is recorded (audit #36)
For each detected supported service whose binary may be executed, SSL Doctor SHALL run its read-only configuration test (`nginx -t` with the instance's `-p`/`-c`, `apachectl -t` or `httpd -t -f`, `haproxy -c -f`). It SHALL record the real exit status and a bounded, redacted stderr summary as `srv.configtest`. The status SHALL be decided from the test's error-level lines. Summary lines the service prints about the test itself (nginx's "syntax is ok", "test is successful", "configuration file … test failed"; Apache's "Syntax OK") SHALL NOT decide it.

#### Scenario: Configuration test fails
- **WHEN** `nginx -t` exits 1 with "[emerg] cannot load certificate" for a file that does not exist
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

#### Scenario: Genuine error next to a permission error
- **WHEN** `nginx -t` reports "[alert] could not open error log file … (13: Permission denied)" and "[emerg] unknown directive "ssl_certificat"", then "test failed"
- **THEN** `srv.configtest` is FAIL naming the unknown directive

### Requirement: Renewal tooling is reported only when found (audit #45)
SSL Doctor SHALL look, read-only, for certbot, acme.sh and lego, and for their renewal configuration, systemd timers and cron entries. It SHALL report a tool as managing a certificate only when its configuration names the configured certificate path or its lineage directory. A schedule SHALL count for a certificate only when it belongs to the tool that manages that certificate.

#### Scenario: certbot manages the configured certificate
- **WHEN** `/etc/letsencrypt/renewal/shop.example.conf` names the `fullchain.pem` that nginx uses, and `certbot.timer` is enabled
- **THEN** `srv.renewal` is PASS "certbot renewal configured for this certificate (timer enabled)"

#### Scenario: Tool present but not linked
- **WHEN** certbot is installed, but no renewal configuration names the configured path
- **THEN** `srv.renewal` is WARNING "certbot is installed but does not manage <path>"

#### Scenario: Nothing found
- **WHEN** no renewal tooling or configuration is found and every source was readable
- **THEN** `srv.renewal` is NOT TESTED "no renewal tooling found"; it does not claim that renewal is manual

#### Scenario: Only another tool's schedule exists
- **WHEN** certbot manages the configured certificate, and the only schedule found is a cron file for lego
- **THEN** `srv.renewal` is not PASS; it reports that no certbot schedule was found

## ADDED Requirements

### Requirement: Permission-only configuration test failures are not tested (audit B)
When the configuration test exits non-zero and every error-level line is an access error (permission denied, errno 13, operation not permitted, must be root), `srv.configtest` SHALL be NOT TESTED with failure kind `permission-denied`, list the files it could not open, and keep a reported "syntax is ok" as evidence that parsing succeeded. It SHALL raise no cause and SHALL NOT affect the overall verdict.

#### Scenario: Unprivileged nginx -t
- **WHEN** `nginx -t` exits 1 with "[alert] could not open error log file … (13: Permission denied)", "syntax is ok", "[emerg] open() "/run/nginx.pid" failed (13: Permission denied)" and "configuration file /etc/nginx/nginx.conf test failed"
- **THEN** `srv.configtest` is NOT TESTED `permission-denied`, its evidence keeps "syntax is ok", and the overall verdict is not FAIL because of it

#### Scenario: Certificate key unreadable for this account
- **WHEN** `nginx -t` reports "[emerg] cannot load certificate key … Permission denied" and "test failed"
- **THEN** `srv.configtest` is NOT TESTED `permission-denied`, naming the key path

### Requirement: The configuration test never escalates privileges (audit B)
The configuration test SHALL run with the SSH account's own privileges. SSL Doctor SHALL NOT use sudo or any other privilege escalation for it.

#### Scenario: Account without root
- **WHEN** the SSH account is not root
- **THEN** the configuration test runs without sudo, and permission limits are reported as NOT TESTED

### Requirement: Renewal schedule sources report their visibility (audit G)
The renewal probe SHALL report, for each schedule source (systemd timers, `/etc/crontab`, `/etc/cron.d`, `/etc/cron.daily`, the per-user crontab spool, acme.sh homes), whether it was readable. It SHALL NOT report a certificate as unscheduled while a source could not be read.

#### Scenario: Root crontab not visible
- **WHEN** certbot manages the configured certificate, no timer is found, and the crontab spool cannot be read by the SSH account
- **THEN** `srv.renewal` is NOT TESTED `permission-denied` naming the unreadable source, and no renewal cause is raised

#### Scenario: Every source readable and no schedule
- **WHEN** certbot manages the configured certificate, every source was readable, and no certbot timer or cron entry exists
- **THEN** `srv.renewal` is WARNING "no systemd timer or cron entry for it was found"

#### Scenario: acme.sh home not readable
- **WHEN** no tool is found and `/root/.acme.sh` cannot be read by the SSH account
- **THEN** `srv.renewal` is NOT TESTED, and its evidence says that `/root/.acme.sh` could not be inspected
