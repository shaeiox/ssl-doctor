# Spec Delta

## Purpose

Lets an operator tell SSL Doctor, once per server, where that server's nginx
configuration and certificate files are, and has SSL Doctor reuse those
settings on every later connection without asking again or affecting other
servers.

## ADDED Requirements

### Requirement: Settings belong to one remembered server
Per-server nginx settings SHALL be stored in that server's remembered profile:
a mode (`auto` or `manual`), a certificate path, a private-key path, and
optional main-configuration and prefix overrides. They SHALL NOT contain a
password or key material, and SHALL apply only to the profile they were set on.

#### Scenario: Two servers
- **WHEN** manual paths are set for `files` and the operator connects to `web`
- **THEN** `web` uses automatic discovery and none of `files`' paths

#### Scenario: No secret in the profile file
- **WHEN** manual paths are saved for a password-login server whose password is saved too
- **THEN** the profile file contains the paths and no password

### Requirement: Saved paths are validated as untrusted input
Paths SHALL be accepted only when absolute, free of control characters and
shell metacharacters, and not starting with `-`; an invalid value SHALL be
refused with the reason and SHALL NOT be stored. Loading a profile SHALL apply
the same rules and drop invalid values with a warning.

#### Scenario: Relative manual path
- **WHEN** the operator enters `ssl/fullchain.pem` as the manual certificate path
- **THEN** it is refused with "use an absolute path" and nothing is saved

### Requirement: `/server config show` lists the settings in force
`/server config show [name]` SHALL show, for the connected server or the named
remembered server: which server and profile, the mode, each path with whether
it is a saved manual value or not set, and the overrides. Bare `/server config`
SHALL keep running the TLS-configuration inventory.

#### Scenario: Connected server without settings
- **WHEN** connected to `files` with no saved settings and the operator runs `/server config show`
- **THEN** the output names `files` and says it uses automatic discovery

### Requirement: `/server config set` saves settings for the right server
`/server config set [name]` SHALL apply to the connected server, or to the named
remembered server when one is given; without either it SHALL offer the recent
remembered servers. It SHALL accept the certificate path, key path, main
configuration and prefix by prompt or by `--cert`, `--key`, `--conf`,
`--prefix`; setting a certificate or key path SHALL switch the mode to
`manual`. Unrelated fields of the profile SHALL be unchanged.

#### Scenario: Set while connected
- **WHEN** connected to `files` and the operator runs `/server config set --cert /opt/pvm/nginx/conf/ssl/fullchain.pem --key /opt/pvm/nginx/conf/ssl/private.key`
- **THEN** `files` is saved in manual mode with those paths and its other profile fields are unchanged

#### Scenario: Set for a named server while not connected
- **WHEN** not connected and the operator runs `/server config set web --cert /etc/ssl/web.pem`
- **THEN** only `web`'s profile is changed

### Requirement: A server that is not remembered can still be configured
When the connected server has no profile, `/server config set` SHALL offer to
remember it (profile only) and save the settings there; when remembering is
declined or disabled, the settings SHALL apply to the current session only and
the CLI SHALL say they will not be kept.

#### Scenario: Remembering disabled
- **WHEN** remembering is off and the operator sets manual paths
- **THEN** the paths are used for this session and the CLI says they are not saved

### Requirement: `/server config clear` returns to automatic discovery
`/server config clear [name]` SHALL remove the manual paths and overrides of
that server and set its mode to `auto`, leaving the rest of the profile and any
saved password unchanged.

#### Scenario: Clear
- **WHEN** the operator runs `/server config clear` for `files`
- **THEN** `files` uses automatic discovery on the next scan and still connects with its saved password

### Requirement: Saved settings are reused on every connection
Connecting to a remembered server SHALL load its settings and state that they
are in use; in manual mode the saved paths SHALL be validated without asking
for them again. Settings SHALL survive disconnecting, restarting SSL Doctor and
the expiry or deletion of a saved password.

#### Scenario: Reconnect after restart
- **WHEN** manual paths were saved for `files`, SSL Doctor is restarted, and the operator runs `/server connect files` and `/server nginx files.example.com`
- **THEN** the saved paths are used and no path is asked for

#### Scenario: Password expired
- **WHEN** the saved password of `files` expires after 90 days unused
- **THEN** its nginx settings remain

### Requirement: Manual paths take precedence and disagreements are reported
In manual mode the saved certificate and key paths SHALL be the ones validated;
automatic discovery SHALL still run, and a different automatically resolved
path for the selected block SHALL be reported as a disagreement and never
substituted. A failing manual path SHALL be reported and kept until the
operator changes or clears it. Main-configuration and prefix overrides SHALL be
used as discovery input in either mode and reported as operator-specified.

#### Scenario: Manual and automatic disagree
- **WHEN** the saved certificate is `/etc/ssl/old.pem` and discovery resolves `/opt/pvm/nginx/conf/ssl/fullchain.pem`
- **THEN** `/etc/ssl/old.pem` is validated and `nginx.path_resolution` warns that automatic discovery found a different file

#### Scenario: Main configuration override
- **WHEN** the saved main configuration is `/opt/pvm/nginx/conf/nginx.conf` and no master is visible
- **THEN** discovery analyses that file and labels it as operator-specified

### Requirement: Failed automatic resolution suggests the manual setting
When automatic resolution of the certificate or key does not reach a readable
file, the server-side output SHALL suggest `/server config set` for that
server; it SHALL NOT prompt for paths on its own.

#### Scenario: Custom layout not found
- **WHEN** `nginx.path_resolution` is not PASS in automatic mode
- **THEN** its recommendation names `/server config set` and the scan continues without a prompt
