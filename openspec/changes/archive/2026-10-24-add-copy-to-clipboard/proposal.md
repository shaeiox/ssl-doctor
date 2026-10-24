# Proposal

## Why

The full-screen shell turns on mouse reporting while the composer is reading, so
the terminal's own click-and-drag selection is captured by the application:
operators cannot select a fingerprint, an error line or a whole result frame and
paste it into a ticket or an AI chat. There is also no way to take a command's
complete output out of the session without re-running it with `-c` and a pipe.

## What Changes

- **Select-to-copy in the full-screen shell.** Dragging with the left mouse
  button over the transcript highlights the selected text; releasing the button
  copies it to the clipboard and confirms in the composer
  (`copied 3 lines · 212 chars`). A click without a drag only clears the
  selection. Selection covers transcript rows (banner and composer excluded) and
  copies plain text — the characters shown, never colour codes.
- **`/copy` command** in both presentations:
  - `/copy` copies the previous command's response (everything that command
    printed, as plain text).
  - `/copy all` copies the whole session transcript.
  - In the full-screen shell, `Ctrl-Y` copies the previous response from the
    composer without typing a command.
- **Clipboard delivery.** Text is sent with the terminal clipboard escape
  (OSC 52), which also works over SSH, and to a local clipboard tool when one is
  available (`wl-copy`, `xclip`, `xsel`, `pbcopy`, `clip.exe`). The confirmation
  says which route was used, so a terminal that ignores OSC 52 is not reported
  as a guaranteed copy.
- Mouse reporting changes from wheel/press reports (`?1000h`) to button-event
  tracking (`?1002h`, SGR `?1006h`) while the composer reads; it stays off while
  a command runs, so the native terminal selection still works then, and
  Shift+drag keeps working as the terminal's own selection at any time.
- Help text, completion table, key-hint footer and README document the above.

Not changing: commands' output, findings, reports, exit codes, batch (`-c`) and
piped output. The line-oriented REPL cannot see mouse selections (the terminal
owns them), so auto-copy on selection is full-screen only; `/copy` works in both.

## Capabilities

### New Capabilities
- `terminal-interface`: how the interactive presentation lets an operator take
  text out of the session — mouse selection that copies, `/copy` of the last
  response or the transcript, and clipboard delivery. (Same capability path the
  in-flight full-screen shell changes use; this change only adds requirements.)

### Modified Capabilities
<!-- none: no archived spec's requirements change -->

## Impact

- `ssl_doctor/tui.py`: mouse mode, SGR press/drag/release decoding, a selection
  model mapped onto the rendered transcript rows, highlight rendering, `Ctrl-Y`.
- `ssl_doctor/cli.py`: `/copy` command, response recording per command (shell
  and line REPL), help/completion entries, composer confirmation.
- New stdlib-only clipboard helper (OSC 52 + optional local tool via
  `subprocess`, never a shell); no new dependencies.
- Tests: `tests/test_tui.py` (decoding, selection, highlight), new tests for
  `/copy` and the clipboard helper; README keys table and CHANGELOG.
