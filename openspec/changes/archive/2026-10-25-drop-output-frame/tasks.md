# Tasks

> Presentation change. Gate: no command, finding, verdict, answer set, exit code
> or contract value moves; the line-oriented fallback is untouched.

## 1. Layout

- [x] 1.1 Remove the output panel borders and label from `build_frame`, drawing transcript lines as plain text in the centred column, and verify no `┌ ┐ └ ┘ │` appears in a frame
- [x] 1.2 Top-align the transcript directly under the header with exactly one blank line, and verify the first output row sits 2-3 rows below the header text
- [x] 1.3 Place the status line, dashed input and hints immediately after the transcript, and verify a short session leaves the remaining rows blank below the hints
- [x] 1.4 Return only real lines from `Transcript.tail(..., fill=False)` so nothing is padded above the first line, and verify an empty session draws no ghost rows
- [x] 1.5 Recompute `content_height()` for the frame-less budget (two rows returned, header spacer removed) and verify the newest line is always visible at 30/24/16/12 rows

## 2. Centring

- [x] 2.1 Add `center_blocks()` and verify each blank-line-separated block is centred on its own width
- [x] 2.2 Verify internal alignment survives: an evidence continuation stays indented relative to its finding after centring
- [x] 2.3 Verify a block wider than the column is left unshifted and unclipped
- [x] 2.4 Verify previous blocks do not move when a wider block is added

## 3. Command separation and renderer

- [x] 3.1 Append one blank line after each command's output and verify two consecutive commands form two distinct blocks
- [x] 3.2 Drop the header's trailing blank row and verify exactly one blank line sits under the banner
- [x] 3.3 Verify the status line, input and hints are unchanged in content and that the caret follows the typed text

## 4. Tests and docs

- [x] 4.1 Update the layout tests for the frame-less composition and add centring/separation tests; verify the suite is green
- [x] 4.2 Capture a real pty frame and update the README, verifying every line of the capture is exactly the terminal width
- [x] 4.3 Add the CHANGELOG entry and update the Project Brain UI topic plus `_decisions.md`
- [x] 4.4 Verify `-c` batch output is byte-identical to the previous commit and that `/help`, `/version`, `/findings` still behave

## Verification log

`python3 -m unittest discover -s tests` → **141 tests, OK (6 skipped)**.
Real pty: `printf '/version\n/clear\n/exit\n' | COLUMNS=96 LINES=22 script -qec "python3 ssldoctor.py" /dev/null`;
every captured row is exactly 96 columns.

| Task | Evidence |
|---|---|
| 1.1 | `test_there_is_no_output_box` asserts no `┌ ┐ └ ┘ │` and no `output` label in a frame |
| 1.2 | `test_transcript_sits_directly_under_the_header`: output is at most 3 rows below the header text (one blank line) |
| 1.3 | `test_chrome_follows_a_short_transcript`: status follows the body and ≥4 rows stay blank below the hints |
| 1.4 | `Transcript.tail(fill=False)` returns only real lines; the renderer uses it, so an empty session draws no ghost rows |
| 1.5 | `test_content_height_floor` + `test_newest_output_is_never_clipped_by_the_layout` (30/24/16/12 rows) |
| 2.1 | `center_blocks` test: each blank-line-separated block centred on its own width |
| 2.2 | `test_blocks_are_centred_but_keep_their_internal_alignment`: the continuation keeps its +8 offset |
| 2.3 | Blocks wider than the column get zero shift; text is clipped only by width, never wrapped by the layout |
| 2.4 | Per-block centring is computed from each block's own width, so earlier blocks are unaffected by later ones |
| 3.1 | `_tui_run` appends one blank line after each command; two commands render as two blocks |
| 3.2 | `_tui_header` no longer appends a blank row; `build_frame` adds exactly one under the banner |
| 3.3 | Status/input/hints content unchanged; caret columns verified by `test_cursor_sits_after_the_typed_text` |
| 4.1 | 43 tests in `tests/test_tui.py`; full suite green (141 tests) |
| 4.2 | README capture regenerated from the pty run, all rows 96 columns |
| 4.3 | CHANGELOG entry + brain v4 + `_decisions.md` (flow vs footer, per-block centring, no frame) |
| 4.4 | `-c` output for `/help`, `/version`, `/findings` byte-identical to the previous commit |
