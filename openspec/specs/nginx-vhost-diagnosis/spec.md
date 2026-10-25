# nginx-vhost-diagnosis Specification

## Purpose

Defines what SSL Doctor may conclude about nginx TLS listeners and virtual
hosts from a discovered configuration, so that an incomplete or unconfirmed
discovery is reported as such and never becomes a server misconfiguration.

## Requirements

### Requirement: `nginx.conf` reports the discovery outcome
`nginx.conf` SHALL state the evidence level, the running master and executable
(when found), the main configuration and how it was selected, the number of
graph files read, and every file not read with its reason. Its status SHALL be
PASS only for a runtime-verified or runtime-associated graph that is complete,
WARNING for a candidate or incomplete graph, and NOT TESTED when no
configuration could be read.

#### Scenario: Custom installation, complete graph
- **WHEN** the running master's `-c` leads to a complete graph under `/opt/pvm/nginx`
- **THEN** `nginx.conf` is PASS and its evidence names the master, the executable and `/opt/pvm/nginx/conf/nginx.conf`

#### Scenario: Only a candidate under /etc/nginx
- **WHEN** no master could be linked and `/etc/nginx/nginx.conf` is the only candidate
- **THEN** `nginx.conf` is WARNING and its uncertainty says the file is not confirmed to belong to the running instance

#### Scenario: Nothing readable
- **WHEN** no configuration file could be read
- **THEN** `nginx.conf` is NOT TESTED with the reason and the inspected locations

### Requirement: "No TLS server block" needs a complete, associated graph
A finding that no server block listens on the requested port, or that no
TLS-enabled server block exists, SHALL be raised (`nginx.domain` WARNING) only
for a complete graph at runtime-associated level or above. For a candidate or
incomplete graph, `nginx.domain` SHALL be NOT TESTED, its evidence SHALL say
which files were analysed, and its uncertainty SHALL say why the absence is not
established.

#### Scenario: Incomplete search
- **WHEN** only an unconfirmed `/etc/nginx/nginx.conf` with one port-80 block was read
- **THEN** `nginx.domain` is NOT TESTED, not a warning that the server has no TLS virtual host

#### Scenario: Verified graph without a 443 block
- **WHEN** a runtime-verified, complete graph has no server block listening on 443
- **THEN** `nginx.domain` is WARNING "no server block listens on port 443" with the graph files as evidence

### Requirement: Server-block inventory states its scope
`nginx.blocks` SHALL count only server blocks from the include graph and SHALL
state the evidence level and whether the graph is complete. A block SHALL count
as TLS-enabled when one of its `listen` directives carries `ssl` or the port
443, as today; discovered-only files SHALL be listed separately and not counted.

#### Scenario: Discovered-only file
- **WHEN** a discovered-only `default.conf` holds a TLS block
- **THEN** it is listed as not part of the configuration graph and not counted as TLS-enabled

### Requirement: Conflicts are claimed only on evidence
The diagnosis SHALL report that several server blocks claim a domain only when
the selected-block evidence carries a duplicate-name note for that port. A
`nginx.domain` warning caused by a fallback block SHALL keep the existing
fallback cause, and one caused by no block on the port SHALL produce a cause
that says so, limited to the analysed graph.

#### Scenario: No block on the port
- **WHEN** `nginx.domain` warns that no server block listens on port 443 in a verified graph
- **THEN** the cause says no server block listens on 443 in the analysed configuration, and no cause mentions several blocks claiming the domain

#### Scenario: Real duplicate
- **WHEN** two blocks on 443 both list `shop.test` as an exact name
- **THEN** the cause says several server blocks claim the domain and only the first is used

### Requirement: Network health and configuration discovery stay apart
When the HTTPS endpoint completed a TLS handshake (and validation passed) but
the nginx configuration is only a candidate, incomplete or not found, the
diagnosis SHALL add an unresolved entry that states the endpoint works and that
the configuration serving it could not be established, SHALL raise no server
misconfiguration cause from the nginx findings, and SHALL recommend no
configuration change.

#### Scenario: HTTPS works, configuration unconfirmed
- **WHEN** `tls.handshake` and `tls.verify` pass and `nginx.conf` is WARNING with a candidate graph
- **THEN** the diagnosis has an unresolved entry for `nginx.conf`, no server cause from `nginx.domain`, `nginx.blocks` or `nginx.certref`, and no recommendation to change the configuration

### Requirement: Facts and hypotheses are labelled
Evidence lines for discovery SHALL distinguish observed facts (a process, an
executable, a file read) from inferences; a suspected non-standard
configuration path SHALL appear only as uncertainty or as an unresolved
entry's conclusion, never as a confirmed or probable cause.

#### Scenario: Suspected custom path
- **WHEN** a master runs from `/opt/pvm/nginx/sbin/nginx` but its configuration could not be read
- **THEN** the possibility that the active configuration lives elsewhere appears in uncertainty, and no cause claims it
