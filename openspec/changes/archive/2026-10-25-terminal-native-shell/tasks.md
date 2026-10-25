# Tasks

> Presentation change. Gate: no command, finding, verdict, answer set, exit code
> or contract value moves; pipes and the plain path keep their bytes.

## 1. Left-aligned layout

- [x] 1.1 Replace the centred column with a left gutter shared by header, transcript, status, input and hints, and verify no row is horizontally centred
- [x] 1.2 Cap the column at 120 columns while spanning narrower terminals, and verify a 200-column frame stops at 120 and a 50-column frame uses 50
- [x] 1.3 Draw the dashed input rules across the full column and verify the caret column is `1 + gutter + prompt + cursor`
- [x] 1.4 Verify a short and a long block start at the same column and that long lines wrap at the right edge

## 2. Mouse wheel

- [x] 2.1 Decode SGR wheel sequences (`ESC [ < 64/65 ; x ; y M`) into wheel-up/wheel-down keys
- [x] 2.2 Enable mouse reporting while the command bar is reading and disable it before returning to cooked mode, and verify the sequences are written on entry and exit
- [x] 2.3 Scroll three rows per wheel notch, clamp at the top, and verify the typed text survives a scroll
- [x] 2.4 Verify PageUp/PageDown still work and that no wheel bytes reach a running command

## 3. Completion

- [x] 3.1 Build one command table shared by `/help` and the completer, and verify `/help` output is unchanged
- [x] 3.2 Show at most three matches, with descriptions, while the bar holds a `/`-prefixed name
- [x] 3.3 Complete the highlighted command on Tab with a trailing space, and verify the list closes
- [x] 3.4 Move the highlight with Up/Down while the list is open and fall back to history when it is closed
- [x] 3.5 Dismiss the list on a space or Escape, and verify `/tls example.com` shows no list

## 4. Result frames

- [x] 4.1 Draw one rounded frame per command with the executed command as the title
- [x] 4.2 Keep every check row, evidence, detail and fix line inside the frame, wrapping rather than eliding
- [x] 4.3 Put the counters in the closing border and verify they fit at 40 columns
- [x] 4.4 Colour border/title/status/footer in the shell by recognising frame glyphs, and verify the plain and piped formats are unchanged
- [x] 4.5 Verify the ASCII fallback uses `+`/`-`/`|` and survives a cp1252 console

## 5. Verification

- [x] 5.1 Update the layout tests for left alignment and add tests for the wheel, completion and frames; verify the suite is green
- [x] 5.2 Capture a real pty frame and verify every row is exactly the terminal width
- [x] 5.3 Verify `-c` output for `/help`, `/version`, `/findings` is byte-identical to the previous commit
- [x] 5.4 Update the README, CHANGELOG and Project Brain

## Verification log

`python3 -m unittest discover -s tests` → **169 tests, OK (6 skipped)**.
Real pty (`script -qec`, 96x34): every captured row is exactly 96 columns; a
`/local` result frame plus the `/` menu was captured for the README.

| Task | Evidence |
|---|---|
| 1.1 | `test_the_column_starts_at_the_left_edge` / `test_short_and_long_rows_start_at_the_same_column`: every non-rule row starts at the gutter |
| 1.2 | `test_the_column_is_capped_but_never_wider_than_the_terminal`: 200→120, 80→80, 50→50; the rule stops at the cap |
| 1.3 | `test_cursor_sits_after_the_typed_text`: column = 1 + gutter + prompt + cursor |
| 1.4 | pty capture at 96 columns: long evidence wraps inside the frame; no row is centred |
| 2.1 | `test_sgr_wheel_reports_are_decoded`: `[<64…` → wheelup, `[<65…` → wheeldown, `[<0…` → unknown |
| 2.2 | `test_mouse_reporting_is_enabled_only_while_reading`: exactly `MOUSE_ON`, then `MOUSE_OFF` |
| 2.3 | `test_wheel_scrolls_three_rows_per_notch`; pty run shows `.. 6 lines back` after two notches |
| 2.4 | `test_wheel_never_goes_past_the_oldest_line`; PageUp/PageDown unchanged and covered by the shell tests |
| 3.1 | `cli.COMMANDS` + `command_completions()`; `/help` output byte-identical (`-c /help` vs `492870b`) |
| 3.2 | `test_slash_lists_three_commands_with_descriptions`; pty capture shows three rows |
| 3.3 | `test_tab_completes_the_highlighted_command` → `/scan `; pty run shows the bar completed |
| 3.4 | `test_down_moves_the_highlight_and_tab_accepts_it`, `test_the_highlight_stops_at_the_ends` |
| 3.5 | `test_a_space_dismisses_the_list`, `test_escape_dismisses_the_list`, `test_no_list_without_a_leading_slash` |
| 4.1 | `test_the_frame_names_the_command_and_the_counters`: title = the command, `╭ … ╮` |
| 4.2 | `test_block_keeps_all_content` / `test_narrow_terminal_never_elides_evidence`: every line survives the frame, wrapped |
| 4.3 | `test_every_row_is_the_same_width` at 100/80/40; `_box_counts()` shortens to the non-zero counters |
| 4.4 | `ResultFrame.test_status_colours_are_applied` + `ResultFrameColouring` (renderer re-colours the box); piped output stays plain |
| 4.5 | `test_ascii_fallback_uses_plain_corners`: `+ - |` corners, encodable as cp1252 |
| 5.1 | 51 tests in `tests/test_terminal_ui.py`, 64 in `tests/test_tui.py`; full suite green |
| 5.2 | pty captures at 96x24/96x30/96x34: every row exactly 96 columns |
| 5.3 | `-c /help`, `-c /version`, `-c /findings` byte-identical to `492870b` |
| 5.4 | README (capture, keys table, frames), CHANGELOG bullets, Project Brain v5 + decisions |
