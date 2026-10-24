# Proposal

## Why

The full-screen shell wraps every transcript in a bordered `output` panel. That
frame was the loudest thing on the screen: it competed with the banner, made the
content look boxed-in rather than presented, and forced two nesting levels (the
column plus the panel) for no information gain. The box also implied a fixed
viewport, while the content is really a conversation that should grow under the
banner.

## What Changes

- **No output frame.** The `┌─ output ─┐` / `│` / `└──┘` box is removed; the
  transcript is plain text inside the centred column.
- **Content flows under the banner.** The transcript starts one line below the
  header and grows downward; the status line, dashed input and key hints follow
  it instead of being pinned to the bottom of the screen.
- **Per-block centring.** Each command's output is centred on its own width with
  its internal alignment intact, and commands are separated by one blank line.
- **Everything else is unchanged**: the dashed input, the muted status line, the
  key hints, the banner, the spinner, every command and every verdict.

## Capabilities

### New Capabilities
- None.

### Modified Capabilities
- `terminal-interface`: the boxed output panel requirement is replaced by the
  flowing, frame-less layout (see the spec delta). The `add-fullscreen-tui` delta
  is amended in place because it is not yet archived.

## Impact

- **Code:** `ssl_doctor/tui.py` (layout, `center_blocks`, transcript `tail(...,
  fill=False)`) and `ssl_doctor/cli.py` (renderer, blank line between commands,
  header no longer adds its own trailing blank).
- **Tests:** layout tests updated for the frame-less composition plus new tests
  for block centring and blank-line separation.
- **Compatibility:** no command, verdict, answer set, exit code or report field
  changes; the line-oriented fallback is untouched.
- **Out of scope:** the banner, the theme, the key bindings, and the line-mode
  finding blocks.
