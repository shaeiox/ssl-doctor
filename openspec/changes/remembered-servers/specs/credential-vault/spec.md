# Spec Delta

## Purpose

Keeps SSH passwords the operator chose to save in the operating system's own
credential vault, and releases one only to the trusted server it was saved for,
so remembered logins never weaken how SSL Doctor protects credentials.

## ADDED Requirements

### Requirement: Saved passwords live only in the OS credential vault
A saved password SHALL be stored only in the operating system's credential
vault: Windows Credential Manager on Windows (per user, not roaming) and the
Secret Service (for example GNOME Keyring or KWallet) on Linux. It SHALL NOT be
written by SSL Doctor to any file, in plain, encoded or encrypted form.

#### Scenario: Save on Windows
- **WHEN** the operator saves the password for `eleven@files.example.com:22` on Windows
- **THEN** a generic credential named `ssl-doctor:ssh:eleven@files.example.com:22` exists in Credential Manager for that Windows user, and no file under the state directory contains the password

#### Scenario: Save on a Linux desktop
- **WHEN** the operator saves the password on Linux with a Secret Service running
- **THEN** the password is stored as a Secret Service item for that entry name, and no file under the state directory contains it

### Requirement: Without a vault, passwords are never saved
When no credential vault is available (no Secret Service, a locked or
unreachable vault, a headless session), the CLI SHALL NOT offer to save a
password, SHALL say why, and SHALL ask for the password at each connection. It
SHALL NOT fall back to any other storage.

#### Scenario: Headless Linux
- **WHEN** the operator connects from an SSH session on a Linux host without a Secret Service
- **THEN** only *profile only* and *no* are offered, with a note that no credential vault is available

#### Scenario: Vault locked at connect time
- **WHEN** a profile has a saved password but the vault cannot be read
- **THEN** the CLI asks for the password and connects as usual

### Requirement: A secret never crosses a command line, a file or output
A saved password SHALL be passed to and from vault tools only through standard
input/output or an in-process API, and to `ssh` only through the existing
askpass mechanism. It SHALL never appear in a process command line, the
transcript, `/copy`, logs, or any HTML, JSON or agent report.

#### Scenario: Process list
- **WHEN** a password is saved or read while another process lists command lines
- **THEN** the password does not appear in any command line

#### Scenario: Reports after a remembered login
- **WHEN** the operator connects with a saved password and exports `/report both` and `/report agent`
- **THEN** none of the files contain the password

### Requirement: A secret is released only to a trusted, matching host key
A saved password SHALL be read from the vault only after the server's host key
has been verified as trusted and matches the fingerprint recorded when the
password was saved. A changed or unknown key SHALL stop the connection before the
vault is read; a trusted key that differs from the recorded fingerprint SHALL
make the CLI ask for the password and offer to re-save it.

#### Scenario: Changed host key
- **WHEN** a remembered server presents a host key that differs from the trust store
- **THEN** the connection is refused as today and the vault is not read

#### Scenario: Re-trusted key
- **WHEN** the operator re-trusted a new key for a server after its password was saved
- **THEN** the saved password is not used; the CLI asks for it and offers to save it again

#### Scenario: Profile pointed at another host
- **WHEN** the profile file is edited so that `files` points at another host
- **THEN** no saved password is released for that host

### Requirement: A rejected secret is deleted
When authentication with a saved password fails, the CLI SHALL delete that saved
password, report that it was removed, and ask once for the password without
retrying the rejected one.

#### Scenario: Password changed on the server
- **WHEN** the server rejects the saved password
- **THEN** the vault entry is deleted, the operator is told, and one password prompt follows

### Requirement: Unused saved passwords expire
A saved password not used for 90 days SHALL be deleted from the vault the next
time the CLI reads profiles, and its profile SHALL show that no password is
saved.

#### Scenario: Old password
- **WHEN** a password was last used 91 days ago and the operator runs `/servers`
- **THEN** that password is deleted from the vault and the profile is listed without a saved password

### Requirement: The source of a password is shown without the value
When a saved password is used, the CLI SHALL state where it came from (for
example "password from Windows Credential Manager") and SHALL never show the
value or its length.

#### Scenario: Connect with a saved password
- **WHEN** `/server connect files` uses the saved password
- **THEN** the session notes the vault it came from and nothing about the value

### Requirement: An empty password is never used
An empty or whitespace-only password SHALL never be sent to a server, saved in
a vault or returned from one. At the password prompt it SHALL be refused and
asked again, up to three times, after which the connection is cancelled;
cancelling the prompt SHALL be reported as cancelled, not as an empty password.

#### Scenario: Enter at the password prompt
- **WHEN** the operator presses Enter without typing a password
- **THEN** the CLI says the password cannot be empty and asks again, and no connection is attempted with it

#### Scenario: Three empty answers
- **WHEN** the operator gives three empty answers
- **THEN** the connection is cancelled without running ssh

#### Scenario: Cancel the prompt
- **WHEN** the operator presses Ctrl-C at the password prompt
- **THEN** the CLI reports that password entry was cancelled and nothing was sent

#### Scenario: Empty password reaches the askpass helper
- **WHEN** ssh starts the askpass helper and no usable password is in its environment
- **THEN** the helper prints nothing and exits with a non-zero status, so ssh does not send an empty password

