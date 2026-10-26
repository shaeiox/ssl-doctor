# Spec Delta

## MODIFIED Requirements

### Requirement: Permissions and ownership are checked by role (audit #34)
For every resolved certificate and key, SSL Doctor SHALL report owner, group and mode during `/scan` and server-agent runs. It SHALL judge the file by its role (from content or directive, never the extension). A key readable by other users SHALL be WARNING. A key or certificate the service's worker account cannot read SHALL be FAIL when determinable. Key content SHALL never be read for this check. When the configured path is a symbolic link, mode, owner, group and readability SHALL be judged on the file it resolves to, and the evidence SHALL name both.

#### Scenario: World-readable key named .pem
- **WHEN** `ssl_certificate_key /etc/ssl/private/site.pem` has mode 0644
- **THEN** `srv.perms` is WARNING "private key readable by other users", although the extension is not `.key`

#### Scenario: Worker account cannot read the certificate
- **WHEN** nginx's `user www-data` cannot read a certificate file with mode 0600 owned by another user, and the master is not running as root
- **THEN** `srv.perms` is FAIL "service account www-data cannot read <path>"

#### Scenario: Permissions run in the guided scan
- **WHEN** `/scan <target> --with-server` completes the nginx analysis
- **THEN** `srv.perms` findings exist for the configured certificate and key, without running `/server cert`

#### Scenario: certbot live symlink to a private key
- **WHEN** `ssl_certificate_key /etc/letsencrypt/live/shop/privkey.pem` is a symbolic link to `../../archive/shop/privkey1.pem`, mode 0600, owner root
- **THEN** `srv.perms` is PASS, and its evidence names the link and the target with mode 600

#### Scenario: Symlink to a world-readable key
- **WHEN** the configured key is a symbolic link whose target has mode 0644
- **THEN** `srv.perms` is WARNING "private key readable by other users", naming the target

### Requirement: Other configured certificates are inventoried (audit #44)
SSL Doctor SHALL list every certificate configured across the analysed service configurations, with block names, listen addresses, leaf subject, SAN and SHA-256 prefix. It SHALL flag the certificate actually served and any configured certificate that covers the target name but was not selected. Certificates SHALL be compared by identity (leaf SHA-256), not by which block configures them.

#### Scenario: Another block also covers the domain
- **WHEN** a second server block that listens on the scanned port has a different certificate covering `shop.example`, and is not the selected block
- **THEN** `srv.inventory` is WARNING naming that block and its certificate as an alternative that a different listener or SNI order could serve

#### Scenario: Served certificate belongs to a different block
- **WHEN** the presented leaf matches the certificate of the default_server block rather than the selected one, and the selected block configures a different certificate
- **THEN** the inventory names the block whose certificate is served

## ADDED Requirements

### Requirement: A shared certificate is not an alternative certificate (audit C)
When the selected block configures the certificate that is presented, other blocks configuring the same certificate SHALL be listed for information only. They SHALL raise no warning and no cause. No finding SHALL state both that the selected block serves the certificate and that the certificate belongs to another block.

#### Scenario: Redirect block reusing the site certificate
- **WHEN** blocks `shop.test` (selected) and `alias.test` on port 443 both use the same certificate and key, and that certificate is presented
- **THEN** `srv.inventory` is PASS, `alias.test` is listed as sharing the certificate, and the diagnosis has no inventory cause

### Requirement: Inventory candidates must answer on the scanned listener (audit C)
A block SHALL be an alternative candidate only when its listen directives can accept connections on the scanned address and port. Blocks on other ports or addresses SHALL be listed without a warning.

#### Scenario: Same name on another port
- **WHEN** the scan targets port 443, and a block for the same name listens only on 8443 with a different certificate
- **THEN** that block raises no inventory warning

### Requirement: Without a presented certificate the inventory is not a warning (audit C)
When no presented certificate is known, a covering block that was not selected SHALL be listed in the `srv.inventory` evidence, with an uncertainty saying which block answers could not be confirmed. `srv.inventory` SHALL NOT be WARNING for that reason alone, and no cause SHALL be raised. The findings contract stays 1.7 with no new values.

#### Scenario: Server-only scan
- **WHEN** `/scan --server-only` analyses two blocks with different certificates covering the domain, and no presented certificate was captured
- **THEN** `srv.inventory` is PASS, lists the second block with an uncertainty, and the diagnosis raises no inventory cause

### Requirement: Permission visibility limits are reported, not judged (audit F)
When the session cannot fully determine access, `srv.perms` SHALL state the limit and SHALL NOT report a confirmed problem or a confirmed PASS for the part it could not see. This covers an ACL on the file, a parent directory the account cannot traverse, or a target that cannot be resolved.

#### Scenario: ACL present on the key
- **WHEN** the key has mode 0600 and an ACL entry
- **THEN** `srv.perms` notes that an ACL grants additional access that was not evaluated

#### Scenario: Parent directory not traversable
- **WHEN** `/etc/ssl/private` cannot be entered by the SSH account
- **THEN** `srv.perms` for a key inside it is NOT TESTED `permission-denied`, not FAIL

### Requirement: Permission recommendations name the file and group (audit F)
A `srv.perms` WARNING or FAIL SHALL recommend a change for the judged file (the link target when the path is a link), naming its path and the service group when known. It SHALL never recommend a mode that would remove the service account's read access.

#### Scenario: Key readable by others
- **WHEN** `/etc/ssl/private/site.key` is mode 0644 root:root and nginx's master runs as root
- **THEN** the recommendation names `/etc/ssl/private/site.key` and mode 0600 or 0640 with the service group
