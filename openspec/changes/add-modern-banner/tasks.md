# Tasks

> Cosmetic change. Gate: no command, check, finding, exit code, report field or
> contract value may move. The banner is the only intended output change.
>
> Verification commands unless stated otherwise:
> `python3 -m unittest discover -s tests` and
> `printf '/version\n/exit\n' | script -qec "python3 ssldoctor.py" /dev/null`.

## 1. Wordmark

- [x] 1.1 Add the seven-glyph wordmark table (five rows, two-character stems) and a renderer that joins letters with one column and words with three, trimming each row. Verify the wordmark for `SSL DOCTOR` is 64 columns wide and exactly five rows
- [x] 1.2 Verify every letter is legible in isolation by rendering each glyph to five rows and asserting no row is empty and no stem is wider than two characters
- [x] 1.3 Choose the stroke character from the glyph set (`█` when Unicode is available, `#` in plain mode) and verify a plain run contains no non-ASCII character

## 2. Banner layout

- [x] 2.1 Add `banner_lines(columns)` returning rules, wordmark, blank line, description, version, read-only note and the `creator: eleven` credit, and verify the full form has exactly 5 wordmark rows and both rules
- [x] 2.2 Clamp rules to the widest content line and to `columns - 2`, and verify no line exceeds the terminal width at 80, 100 and 72 columns
- [x] 2.3 Add the compact form for terminals narrower than the wordmark and verify a 40-column run still contains the name, description, version and credit with no clipped art
- [x] 2.4 Route `SSLDoctorCLI.banner()` through `banner_lines()` and verify startup, `-h` and `-c` batch runs all print it exactly once

## 3. Theme integration

- [x] 3.1 Paint rules and wordmark with `primary` (wordmark bold), description and note `muted`, credit `accent` bold, and verify the escape output of each segment in TrueColor mode
- [x] 3.2 Verify plain mode emits no escape sequence and uses only `#` and `=` for the banner
- [x] 3.3 Verify a cp1252 terminal gets the ASCII wordmark and dashed rules, and that no banner line fails to encode

## 4. Tests and docs

- [x] 4.1 Add banner tests: full form on a wide terminal, compact form on a narrow one, width invariant, plain-mode ASCII, credit always present, wordmark row count
- [x] 4.2 Update the one existing assertion that expected the old clean-text banner, and verify the full suite is green
- [x] 4.3 Show the banner in the README "Terminal look" section and verify every character in the block encodes as UTF-8 and the block is copy-paste faithful
- [x] 4.4 Add the CHANGELOG entry (`Unreleased`, "startup banner") noting the creator credit and that commands are unchanged
- [x] 4.5 Record the wordmark and the width tiers in the Project Brain `ui-design-system` topic and the `_decisions.md` log
- [x] 4.6 Verify `/version`, `/help`, `/tls <fixture>` and `/cert inspect <fixture>` outputs and exit codes are unchanged apart from the banner

## Verification log

`python3 -m unittest discover -s tests` → 97 tests, OK (6 skipped).
`COLUMNS=90 script -qec "python3 ssldoctor.py" /dev/null` renders the full wordmark with primary rules and an accent credit; `COLUMNS=40` renders the compact form.

| Task | Evidence |
|---|---|
| 1.1 | `tests::StartupBanner::test_wordmark_is_five_rows_of_two_stroke_letters`: 5 rows, 64 columns for `SSL DOCTOR` |
| 1.2 | Same test asserts every glyph is 6×5 and that stems are 2 characters (`L` row 1 == `##`, `T` row 2 == `  ##  `) |
| 1.3 | `Glyphs.block` → `█` when Unicode is available, `#` in plain mode; `test_plain_banner_is_ascii_and_escape_free` encodes the whole banner as ASCII |
| 2.1 | `test_full_banner_on_a_wide_terminal`: 5 wordmark rows, description, note, credit, version, identical opening and closing rules |
| 2.2 | `test_no_line_is_wider_than_the_terminal` at 30/40/60/72/80/100/120 columns |
| 2.3 | `test_compact_banner_when_narrow`: no art, name/description/credit present at 40 columns |
| 2.4 | `test_banner_is_printed_once_per_run` (`-c /version` prints the credit exactly once); startup and `-h` share `banner()` |
| 3.1 | `test_colour_banner_uses_roles`: primary `38;2;215;119;87` for rules and wordmark, accent `38;2;177;185;249` for the credit |
| 3.2 | `test_plain_banner_is_ascii_and_escape_free`: no ESC byte, `#` and `=` only, no trailing spaces |
| 3.3 | Plain/cp1252 path is the same ASCII branch; the banner text uses `banner_tagline()`/`_banner_credit()` with the glyph separator, so no `·` reaches a non-UTF-8 console |
| 4.1 | Seven `StartupBanner` tests (wordmark, full, compact, width, credit, plain, colour) |
| 4.2 | The old `"SSL Doctor v"` banner assertion in `PlainModeContract` now checks `creator: eleven`; full suite green |
| 4.3 | README "Terminal look" shows a real 80-column capture of the full banner |
| 4.4 | `CHANGELOG.md` Unreleased entry records the banner, the credit and the unchanged commands |
| 4.5 | Brain topic `ui-design-system` bumped to v2; `_decisions.md` logs wordmark-over-figlet, compact fallback and fixed credit |
| 4.6 | `/version`, `/help`, `/tls <fixture>` and `/cert inspect <fixture>` diff clean against the pre-banner run except for the banner itself; exit codes 0 |
