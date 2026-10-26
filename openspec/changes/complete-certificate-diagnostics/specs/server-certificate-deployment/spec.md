# Spec Delta

## Purpose

Describes which certificates, keys and chains a server's TLS services are configured to use, whether those files are safely readable by the service, and whether the running service actually serves them, without changing anything on the server.

## ADDED Requirements

### Requirement: Certificate, key and chain paths are discovered for every supported service (audit #32)
For nginx, the existing discovery and path resolution SHALL apply to every `ssl_certificate`/`ssl_certificate_key` pair. For Apache httpd, `SSLCertificateFile`, `SSLCertificateKeyFile` and `SSLCertificateChainFile` per matching `<VirtualHost>` SHALL be reported. For HAProxy, `crt` arguments of `bind` lines SHALL be reported. Each path SHALL carry its directive, source file and line.

#### Scenario: Apache virtual host
- **WHEN** the `<VirtualHost *:443>` for `shop.example` sets `SSLCertificateFile` and `SSLCertificateKeyFile`
- **THEN** both paths are reported with their source file and line, and validated like nginx paths

#### Scenario: HAProxy combined PEM
- **WHEN** `bind :443 ssl crt /etc/haproxy/certs/shop.pem` is configured
- **THEN** that file is reported as holding certificate, chain and key, and is inspected for certificates and key state without printing the key

### Requirement: Configured paths are validated for every supported service (audit #33)
Each discovered path SHALL be checked for existence, file type and readability with the states already defined for nginx (`readable`, `missing`, `denied`, `unreachable`, `notfile`, `unsupported`). Certificate validation SHALL run only on opened files.

#### Scenario: Apache key path missing
- **WHEN** the Apache `SSLCertificateKeyFile` does not exist
- **THEN** the path finding reports the key as missing, and the pairing is NOT TESTED

#### Scenario: Missing file affects the verdict
- **WHEN** a path finding is FAIL because a confirmed configuration points at a missing certificate
- **THEN** the overall verdict is FAIL even when no other rule explains it

### Requirement: Permissions and ownership are checked by role (audit #34)
For every resolved certificate and key, SSL Doctor SHALL report owner, group and mode during `/scan` and server-agent runs. It SHALL judge the file by its role (from content or directive, never the extension). A key readable by other users SHALL be WARNING. A key or certificate the service's worker account cannot read SHALL be FAIL when determinable. Key content SHALL never be read for this check.

#### Scenario: World-readable key named .pem
- **WHEN** `ssl_certificate_key /etc/ssl/private/site.pem` has mode 0644
- **THEN** `srv.perms` is WARNING "private key readable by other users", although the extension is not `.key`

#### Scenario: Worker account cannot read the certificate
- **WHEN** nginx's `user www-data` cannot read a certificate file with mode 0600 owned by another user, and the master is not running as root
- **THEN** `srv.perms` is FAIL "service account www-data cannot read <path>"

#### Scenario: Permissions run in the guided scan
- **WHEN** `/scan <target> --with-server` completes the nginx analysis
- **THEN** `srv.perms` findings exist for the configured certificate and key, without running `/server cert`

### Requirement: Multiple certificates, virtual hosts and listeners are resolved (audit #38)
SSL Doctor SHALL select the server block or virtual host by listen address and port as well as name, report every certificate configured for the selected block (including RSA and ECDSA pairs), and state which one applies to the target hostname and client key-exchange capabilities.

#### Scenario: RSA and ECDSA pair in one block
- **WHEN** the selected nginx block has two `ssl_certificate` and two `ssl_certificate_key` directives
- **THEN** both pairs are resolved, inspected and paired, and the evidence names the key type of each

#### Scenario: Listener on a specific address
- **WHEN** one block listens on `10.0.0.5:443` and another on `*:443` with the same name
- **THEN** the block for the address the target resolves to is selected, and the evidence names the address

### Requirement: The active certificate is compared with every configured certificate (audit #35)
`srv.compare` SHALL compare the presented leaf with each configured leaf of the selected block. It SHALL be PASS when one matches (naming which), and FAIL only when the presented leaf matches none and the configuration is the running instance's. It SHALL be NOT TESTED when the configured file was not read in this run.

#### Scenario: ECDSA certificate served from a dual configuration
- **WHEN** the client negotiates the ECDSA certificate of an RSA+ECDSA block
- **THEN** `srv.compare` is PASS, naming the ECDSA file, and is not FAIL because the RSA file differs

#### Scenario: No stale comparison
- **WHEN** an earlier command in the session inspected another certificate, and this scan could not read the configured certificate
- **THEN** `srv.compare` is NOT TESTED "configured certificate not read in this scan", and the earlier fingerprint is not used

#### Scenario: Served certificate differs
- **WHEN** the presented leaf matches no configured certificate of the running, complete configuration
- **THEN** `srv.compare` is FAIL, and the evidence lists the presented and every configured fingerprint

### Requirement: The full configured chain is compared with the presented chain (audit #27)
In addition to the leaf, SSL Doctor SHALL compare the ordered fingerprints of the configured chain file with the presented chain, and report the first differing position and whether the difference is an added, missing or replaced certificate.

#### Scenario: Server sends an older intermediate
- **WHEN** the configured file holds intermediate B, but the endpoint presents intermediate A
- **THEN** the comparison reports "position 2 differs: configured B, presented A"

#### Scenario: Comparison from a different vantage
- **WHEN** the presented chain was captured through a load balancer address
- **THEN** the evidence states the address the presented chain came from

### Requirement: Encrypted-key compatibility with service startup is reported (audit #39)
When a configured key is encrypted, SSL Doctor SHALL report whether the service is configured to unlock it: nginx `ssl_password_file`, Apache `SSLPassPhraseDialog`, or HAProxy (unsupported for encrypted keys). It SHALL report presence and readability, never content.

#### Scenario: Encrypted key without ssl_password_file
- **WHEN** the nginx key is encrypted and the block has no `ssl_password_file`
- **THEN** `srv.keystartup` is FAIL "nginx cannot load this encrypted key without ssl_password_file"

#### Scenario: Encrypted key with a passphrase file
- **WHEN** the key is encrypted and `ssl_password_file` names a file that exists
- **THEN** `srv.keystartup` is PASS "passphrase file configured" (its content is not read), and the pairing stays NOT TESTED

#### Scenario: Unencrypted key
- **WHEN** the key is not encrypted
- **THEN** no `srv.keystartup` problem is raised

### Requirement: Other configured certificates are inventoried (audit #44)
SSL Doctor SHALL list every certificate configured across the analysed service configurations, with block names, listen addresses, leaf subject, SAN and SHA-256 prefix. It SHALL flag the certificate actually served and any configured certificate that covers the target name but was not selected.

#### Scenario: Another block also covers the domain
- **WHEN** a second server block has a certificate covering `shop.example` but is not the selected block
- **THEN** `srv.inventory` is WARNING naming that block and its certificate as an alternative that a different listener or SNI order could serve

#### Scenario: Served certificate belongs to a different block
- **WHEN** the presented leaf matches the certificate of the default_server block rather than the selected one
- **THEN** the inventory names the block whose certificate is served
