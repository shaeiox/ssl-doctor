# Spec Delta

## Purpose

Turns the `ssl_certificate` and `ssl_certificate_key` values of the selected
nginx server block into the files nginx would open, says how each path was
derived and whether the file can be read, and keeps path problems separate from
certificate problems.

## ADDED Requirements

### Requirement: Relative paths follow nginx's configuration-prefix rule
A relative `ssl_certificate` or `ssl_certificate_key` value SHALL be resolved
against nginx's configuration prefix: the directory of the main configuration
file after a relative `-c` was resolved against the `-p` prefix (or the build
prefix). An absolute value SHALL be used as it is. The `-p` prefix itself, the
master's working directory and the SSH account's directory SHALL NOT be used.

#### Scenario: Custom installation
- **WHEN** the master runs with `-p /opt/pvm/nginx/ -c conf/nginx.conf` and the block says `ssl_certificate ssl/fullchain.pem;`
- **THEN** the resolved path is `/opt/pvm/nginx/conf/ssl/fullchain.pem`

#### Scenario: Main configuration at the prefix root
- **WHEN** the main configuration is `/opt/pvm/nginx/nginx.conf` and the block says `ssl_certificate ssl/fullchain.pem;`
- **THEN** the resolved path is `/opt/pvm/nginx/ssl/fullchain.pem`

#### Scenario: Prefix and configuration directory differ
- **WHEN** the prefix is `/srv/www/` and the main configuration is `/etc/nginx-www/nginx.conf`
- **THEN** a relative certificate path is resolved under `/etc/nginx-www/`, not `/srv/www/`

#### Scenario: Absolute path
- **WHEN** the block says `ssl_certificate /etc/ssl/site/fullchain.pem;`
- **THEN** that path is used unchanged

### Requirement: Every resolved path carries its provenance
For each value SHALL be recorded: the directive as written, the configuration
file and line it came from (or `http{}` inheritance), the resolved path, and
the method (absolute, configuration prefix, saved manual setting).

#### Scenario: Inherited key
- **WHEN** the key is set only in `http{}` of `/opt/pvm/nginx/conf/nginx.conf`
- **THEN** the key's provenance names that file and line and says it is inherited from `http{}`

### Requirement: Values that cannot be resolved statically are not guessed
A value containing an nginx variable (`$…`) or using the `data:` scheme SHALL be
reported as not statically resolvable, and no file SHALL be read for it.

#### Scenario: Certificate chosen per SNI
- **WHEN** the block says `ssl_certificate /etc/ssl/$ssl_server_name.pem;`
- **THEN** the certificate is reported as not statically resolvable and its validation is NOT TESTED

### Requirement: The file state is checked before any validation
For each resolved path, SSL Doctor SHALL check on the server whether it exists,
is a regular file and is readable by the SSH account, and SHALL report missing,
not readable and not a regular file as different states. A missing file SHALL
be FAIL only when the configuration is the complete configuration of the
running instance; otherwise it is WARNING with the reason in uncertainty. A file
that exists but is not readable SHALL be NOT TESTED.

#### Scenario: Missing certificate in a verified configuration
- **WHEN** the runtime-verified configuration points at a certificate that does not exist
- **THEN** `nginx.path_resolution` is FAIL with the resolved path and the state "missing"

#### Scenario: Root-only key
- **WHEN** the certificate is readable but the key is mode 600 root-owned and the account is not root
- **THEN** the key is reported as existing but not readable by this account, `nginx.path_resolution` stays PASS, and the key pairing is NOT TESTED

### Requirement: A prefix-relative file nginx would not use is pointed out
When the resolved file is missing but a file exists at the same relative path
under the `-p` prefix, SSL Doctor SHALL report that file as existing but not
the one nginx opens, and SHALL NOT validate it as the configured certificate.

#### Scenario: Files placed next to the prefix
- **WHEN** `ssl/fullchain.pem` resolves to `/opt/pvm/nginx/conf/ssl/fullchain.pem` (missing) and `/opt/pvm/nginx/ssl/fullchain.pem` exists
- **THEN** the evidence says the latter exists but nginx resolves the directive to the former

### Requirement: Certificate validation runs only on opened files
`nginx.chainfile`, `srv.cert` and `srv.keymatch` SHALL run only for files that
were located and read; otherwise they SHALL be NOT TESTED naming the unmet
prerequisite. Content that is not PEM SHALL be reported as such, distinct from
an incomplete chain; the key pairing SHALL be NOT TESTED when the key cannot be
read.

#### Scenario: Path resolution failed
- **WHEN** the certificate file is missing
- **THEN** `nginx.chainfile` and `srv.cert` are NOT TESTED with "certificate file could not be opened", not FAIL

#### Scenario: Invalid PEM
- **WHEN** the certificate file is readable but contains no PEM certificate
- **THEN** `nginx.chainfile` is FAIL "no PEM certificate in the file", not an incomplete-chain warning

#### Scenario: Incomplete chain
- **WHEN** the file holds only the leaf certificate
- **THEN** `nginx.chainfile` is WARNING about the missing intermediates, as today

### Requirement: Direct certificate inspection checks access first
`/server cert <file> [key]` SHALL check the file states first and report a
missing or unreadable certificate as NOT TESTED with the state, and a missing
or unreadable key as a NOT TESTED pairing, never as an invalid certificate.

#### Scenario: Typo in the path
- **WHEN** the operator runs `/server cert /etc/ssl/missing.pem`
- **THEN** `srv.cert` is NOT TESTED with "file not found", not FAIL

### Requirement: Path resolution has its own finding
The finding `nginx.path_resolution` SHALL report, for certificate and key, the
configured value, provenance, resolved path, method, file state, and whether
the paths came from automatic discovery or a saved manual setting.

#### Scenario: Example output for a working custom installation
- **WHEN** both files resolve under `/opt/pvm/nginx/conf/ssl/` and are readable
- **THEN** `nginx.path_resolution` shows each configured value, its resolved path and "relative to the configuration prefix"

### Requirement: The path-resolution status reflects access, not content
`nginx.path_resolution` SHALL be PASS when both files exist and the certificate
is readable; WARNING for a manual/automatic disagreement or a missing file in an
unconfirmed configuration; FAIL for a missing file in a confirmed
configuration; NOT TESTED when nothing could be resolved or the certificate
cannot be read.

#### Scenario: Status for a working custom installation
- **WHEN** both files resolve under `/opt/pvm/nginx/conf/ssl/` and are readable
- **THEN** `nginx.path_resolution` is PASS
