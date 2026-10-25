# Spec Delta

## Purpose

Lets an operator reconnect to an SSH server they have used before without
re-entering its connection settings, by remembering named, non-secret server
profiles that can be listed, used and forgotten.

## ADDED Requirements

### Requirement: Remembering is offered after a successful connection
After `/server connect` authenticates successfully to a server that has no
profile, the CLI SHALL ask whether to remember it, offering *profile only*,
*save password too* (password logins only, and only when a credential vault is
available) and *no*, with *profile only* pre-selected. Nothing SHALL be
remembered before authentication succeeds.

#### Scenario: Remember a new server
- **WHEN** the operator connects to `files.example.com` for the first time and authentication succeeds
- **THEN** the CLI asks whether to remember it, with *profile only* pre-selected

#### Scenario: Failed connection
- **WHEN** host-key verification or authentication fails
- **THEN** no profile and no password are saved and no question is asked

#### Scenario: Key login
- **WHEN** the connection used a private key
- **THEN** the *save password too* choice is not offered

### Requirement: A profile holds only non-secret settings
A profile SHALL hold a name, host, port, username, authentication method, key
path (key logins), TLS target host and port, whether a password is saved, the
host-key fingerprint of the server when it was saved, and created and last-used
times. A profile SHALL NOT contain a password, a private key, a key passphrase or
arbitrary SSH options.

#### Scenario: Inspect the profile file
- **WHEN** a password login is remembered with *save password too*
- **THEN** the profile file contains the settings and the password-saved marker, and the password does not appear in it

### Requirement: Profiles are stored privately and written atomically
Profiles SHALL be stored in the tool's private state directory, readable and
writable only by the owning OS user. Every update SHALL replace the file
atomically, so an interrupted write leaves the previous profiles intact.

#### Scenario: File permissions on Linux
- **WHEN** the first profile is saved on Linux
- **THEN** the profile file is created with owner-only read/write permissions

#### Scenario: Interrupted save
- **WHEN** the process is killed while saving a profile
- **THEN** the next start reads the previous, complete set of profiles

### Requirement: The profile file is treated as untrusted input
When loading profiles the CLI SHALL accept only known fields with valid types and
values (names of letters, digits, `.`, `-`, `_`; ports 1–65535; auth method
`password` or `key`), SHALL ignore unknown fields, and SHALL NOT pass any profile
value to a shell. A file that cannot be parsed SHALL be ignored with a warning,
not crash the CLI or be overwritten silently.

#### Scenario: Injected option
- **WHEN** the profile file contains an extra field such as `"proxy_command": "nc evil 22"`
- **THEN** the field is ignored and never reaches the ssh command line

#### Scenario: Corrupt file
- **WHEN** the profile file is not valid JSON
- **THEN** the CLI warns that saved servers could not be read, starts normally, and does not overwrite the file until the operator saves a profile

### Requirement: `/servers` lists remembered servers
`/servers` SHALL list every profile with its name, `user@host:port`,
authentication method, whether a password is saved, and when it was last used,
and SHALL never display a secret. For password profiles it SHALL mention that a
key login is the stronger choice.

#### Scenario: List
- **WHEN** two profiles exist, one with a saved password
- **THEN** both are listed and only the saved-password marker, never the password, is shown

#### Scenario: Nothing saved
- **WHEN** no profile exists
- **THEN** `/servers` says that no servers are remembered and how to add one

### Requirement: Connecting to a profile skips the prompts
`/server connect <name>` SHALL connect with the profile's settings without asking
for them. For a password login it SHALL use the saved password when the
credential vault releases it, and otherwise ask only for the password. The
command completion menu SHALL offer profile names after `/server connect `.

#### Scenario: Saved password
- **WHEN** the operator runs `/server connect files` and the vault releases its password
- **THEN** the CLI connects without any prompt

#### Scenario: Profile only
- **WHEN** the profile has no saved password
- **THEN** the CLI asks only for the password

#### Scenario: Unknown name
- **WHEN** no profile is named `fles`
- **THEN** the CLI reports that no such server is remembered, lists the closest names, and starts nothing

### Requirement: `/server connect` without a name offers recent servers
`/server connect` with no argument SHALL, when profiles exist, offer to pick one
of the most recently used profiles or to enter a new server; choosing a new
server SHALL run today's prompts.

#### Scenario: Pick a recent server
- **WHEN** profiles exist and the operator runs `/server connect`
- **THEN** the recent profiles are offered and choosing one connects as `/server connect <name>` would

### Requirement: Every `/scan` asks which server to use
When an interactive `/scan` reaches its server step and an SSH session is open
or servers are remembered, it SHALL ask which server to use: the current
session (if any), each remembered server (those matching the scanned domain
first), or a new one. Enter SHALL pick the most likely choice. With no session
and nothing remembered, the connection prompts SHALL start directly.

#### Scenario: Second scan of another domain
- **WHEN** a session to `files.example.com` is open and the operator runs `/scan www.example.org`
- **THEN** the server step asks whether to use the current session, a remembered server, or a new one, instead of silently reusing the session

#### Scenario: Matching remembered server is the default
- **WHEN** no session is open, a remembered server's TLS target is `files.example.com`, and the operator runs `/scan files.example.com` and presses Enter
- **THEN** that server is connected without the connection prompts

#### Scenario: Keep the current session
- **WHEN** the operator chooses the current session
- **THEN** the scan uses it without reconnecting

#### Scenario: New server
- **WHEN** the operator chooses `n`
- **THEN** the connection prompts start, and the previous session is closed once the new one connects

#### Scenario: Nothing to choose from
- **WHEN** no session is open and no server is remembered
- **THEN** the connection prompts start without a question

#### Scenario: Unrecognised answer
- **WHEN** the operator answers with something that is neither a listed number, a remembered name nor `n`
- **THEN** the server step is skipped with a message and no connection is attempted

### Requirement: Batch scans never ask which server to use
`/scan` in batch mode (`-c`) SHALL NOT ask which server to use: it SHALL use an
open session when there is one and otherwise run the server step as before.

#### Scenario: Batch scan with a session
- **WHEN** a batch run has connected with `/server connect files` and then runs `/scan files.example.com --server-only`
- **THEN** the scan uses that session without a question

### Requirement: Prompts are pre-filled from a profile
When the operator enters a host that has a profile, the remaining prompts SHALL be
pre-filled with the profile's values as their defaults.

#### Scenario: Re-typed host
- **WHEN** the operator types `files.example.com` at the hostname prompt and a profile exists for it
- **THEN** port, user, auth method and TLS target default to the saved values

### Requirement: Forgetting removes a server completely
`/server forget <name>` SHALL delete the profile and any saved password for it;
`/server forget --all` SHALL do so for every profile after an explicit
confirmation; `/server forget-password <name>` SHALL delete only the saved
password and keep the profile.

#### Scenario: Forget one server
- **WHEN** the operator runs `/server forget files`
- **THEN** the profile is gone from `/servers` and its password is gone from the vault

#### Scenario: Forget all without confirming
- **WHEN** the operator runs `/server forget --all` and does not confirm
- **THEN** nothing is deleted

### Requirement: Remembering can be disabled
`--no-remember` and `SSL_DOCTOR_REMEMBER=off` SHALL disable the remember offer and
the use of saved passwords for the session. Batch mode (`-c`), scan agents and
the service SHALL never offer to remember and never read saved passwords.

#### Scenario: Batch run
- **WHEN** the CLI runs `-c "/server connect files"`
- **THEN** no remember question is asked and no saved password is read
