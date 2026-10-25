# Spec Delta

## Purpose

Identifies the nginx instance actually running on an authorized server and the
configuration associated with it, recording how strong that association is,
so later conclusions never rest on a configuration that merely exists on disk.

## ADDED Requirements

### Requirement: The running nginx master is identified first
Before reading configuration, server-side nginx analysis SHALL look for running
nginx master processes and record, for each, the PID, the executable, and the
`-p`, `-c` and `-g` arguments from its command line, using the executable link
of the process when it is readable. It SHALL NOT treat an `nginx` found on the
account's `PATH` as the running executable.

#### Scenario: Custom installation
- **WHEN** the process list shows `nginx: master process /opt/pvm/nginx/sbin/nginx -p /opt/pvm/nginx/ -c conf/nginx.conf`
- **THEN** the executable `/opt/pvm/nginx/sbin/nginx`, prefix `/opt/pvm/nginx/` and configuration argument `conf/nginx.conf` are recorded as runtime evidence

#### Scenario: Different nginx on PATH
- **WHEN** `nginx` on the account's `PATH` is `/usr/sbin/nginx` but the running master is `/opt/pvm/nginx/sbin/nginx`
- **THEN** `/opt/pvm/nginx/sbin/nginx` is used for every later step and `/usr/sbin/nginx` is not run

#### Scenario: Process details not readable
- **WHEN** the process list is restricted or the executable link cannot be read
- **THEN** the limitation is recorded as evidence and discovery continues with the next stage

### Requirement: Service definitions are supplementary evidence
When systemd is available, discovery SHALL read the unit that owns the running
master (or, without a running master, units whose name contains `nginx`) and
record its `ExecStart`, unit file and main PID. A unit not linked to the running
master's PID SHALL only contribute candidate paths.

#### Scenario: Unit owns the master
- **WHEN** the master's PID is the `MainPID` of `pvm-nginx.service` whose `ExecStart` carries `-c /opt/pvm/nginx/conf/nginx.conf`
- **THEN** the unit, its `ExecStart` and its configuration argument are recorded as runtime evidence for that master

#### Scenario: Unrelated unit
- **WHEN** an `nginx.service` exists but its main PID is not the running master
- **THEN** its configuration path is recorded as a candidate only

### Requirement: Paths follow nginx path semantics
The main configuration SHALL be resolved as nginx does: the `-c` argument, else
the executable's build `--conf-path`, a relative path being relative to the
prefix (`-p`, else the build `--prefix`); `include` paths that are relative
SHALL resolve against the main configuration's directory. Build defaults SHALL
be read from the identified executable (`-V`) and SHALL NOT override explicit
runtime arguments.

#### Scenario: Relative -c with -p
- **WHEN** the master runs with `-p /opt/pvm/nginx/ -c conf/nginx.conf` and the build `--conf-path` is `/etc/nginx/nginx.conf`
- **THEN** the main configuration is `/opt/pvm/nginx/conf/nginx.conf`, not the build default

#### Scenario: No -c argument
- **WHEN** the master runs without `-c` and its executable reports `--conf-path=/usr/local/nginx/conf/nginx.conf`
- **THEN** the main configuration is `/usr/local/nginx/conf/nginx.conf`

### Requirement: A bounded candidate search is the fallback
Only when no main configuration can be derived from runtime or executable
evidence SHALL discovery search fixed roots (`/etc/nginx`, `/usr/local/nginx`,
`/usr/local/etc/nginx`, `/opt`, `/srv`) for `nginx.conf`, without crossing
mount points, with a depth and result limit, and SHALL record each root
inspected and each root that was missing or not readable.

#### Scenario: Nothing running, custom tree on disk
- **WHEN** no nginx master is visible and `/opt/pvm/nginx/conf/nginx.conf` exists
- **THEN** it is found by the bounded search and recorded as a candidate, together with the roots that were inspected

### Requirement: Only the include graph of the main configuration is analysed
From the selected main configuration, discovery SHALL follow `include`
directives at any nesting level — absolute, relative and wildcard — using
normalised paths so that each file is read once, stopping at cycles, and
bounded in depth, file count and size. Files present on disk but not reached
through the graph SHALL NOT be analysed as configuration.

#### Scenario: Nested wildcard include
- **WHEN** `nginx.conf` includes `conf.d/*.conf` and `conf.d/site.conf` includes `snippets/tls.conf`
- **THEN** all three files are part of the graph and each is read once

#### Scenario: A TLS file that is not included
- **WHEN** `/opt/pvm/nginx/conf.d/default.conf` listens on 443 but no file of the graph includes it
- **THEN** it may be listed as discovered, and its server blocks are not counted as active configuration

#### Scenario: Include cycle
- **WHEN** two files include each other
- **THEN** each is read once and the cycle is recorded without failing the analysis

### Requirement: Missing, unreadable and unsupported files are told apart
Discovery SHALL record, per referenced file or pattern, whether it was read,
does not exist, matched nothing, was not readable for the account, exceeded a
limit, or used syntax the parser does not support, and SHALL mark the graph
incomplete when any referenced file could not be read.

#### Scenario: Permission denied
- **WHEN** an included file exists but is not readable for the SSH account
- **THEN** it is reported as not readable (not as missing) and the graph is incomplete

#### Scenario: Wildcard matching nothing
- **WHEN** `include sites-enabled/*;` matches no file
- **THEN** it is reported as matching nothing and does not make the graph incomplete

### Requirement: Every analysed configuration carries its evidence level
The analysed configuration SHALL carry exactly one evidence level:
*runtime-verified*, *runtime-associated* (linked to the running master through
its arguments, its executable's defaults or its service unit), *candidate*
(not linked to a running master) or *none* (nothing read).

#### Scenario: Candidate from the search
- **WHEN** the only configuration comes from the bounded candidate search
- **THEN** its evidence level is candidate

#### Scenario: Linked but incomplete
- **WHEN** the graph comes from the running master's `-c` but an included file could not be read
- **THEN** its evidence level is runtime-associated, not runtime-verified

### Requirement: Runtime verification needs an unchanged, complete graph
The level SHALL be runtime-verified only when the main configuration comes from
the running master's arguments or its executable's defaults, the graph is
complete, and no graph file was modified after the master started. A
configuration dump or test SHALL NOT by itself raise the level.

#### Scenario: Unchanged since start
- **WHEN** the graph comes from the master's own `-c`, is complete, and every file is older than the master's start time
- **THEN** the evidence level is runtime-verified

#### Scenario: Changed after start
- **WHEN** a graph file was modified after the master started
- **THEN** the evidence level is runtime-associated and the evidence says the running instance may not have loaded that change

### Requirement: Discovery is read-only
Discovery SHALL run only read-only commands through the existing SSH session and
SHALL never reload, restart or signal nginx, change files, permissions,
certificates or keys, install anything, or require root.

#### Scenario: Restricted account
- **WHEN** `ps`, `systemctl` and `-V` are unavailable or refused
- **THEN** each refusal is recorded and no stage fails the scan

### Requirement: Discovery commands are bounded and injection-safe
Every discovery command SHALL have a timeout and an output limit, a missing
command SHALL be reported as unavailable, and any path or pattern placed in a
remote command SHALL be validated against a safe character set or quoted.

#### Scenario: Unsafe characters in a discovered path
- **WHEN** an `include` pattern contains shell metacharacters such as `$(` or `;`
- **THEN** it is not placed in a remote command and is reported as unsupported

### Requirement: Executables are run only when trusted
`-V` and `nginx -T` SHALL be run only with the executable of the running master
when it is a root-owned regular file that is not group- or world-writable; only
when no master is visible MAY `SSLDOCTOR_NGINX_CMD` or the `nginx` on `PATH` be
run, its result being a candidate. `-T` output SHALL NOT be stored or printed
beyond the directives analysed.

#### Scenario: Spoofed process title
- **WHEN** a process titled `nginx: master process /tmp/x/nginx` points at a file that is not owned by root or is group- or world-writable
- **THEN** that file is never executed (no `-V`, no `-T`) and the reason is recorded

#### Scenario: Nothing visible, nginx on PATH
- **WHEN** no master process is visible and `nginx -T` from `PATH` succeeds
- **THEN** its configuration is analysed at candidate level
