# Tasks

> Presentation-only change. Gate: no task may modify a check, a correlation
> rule, a status string, a command name, an answer set, an exit code or a
> contract field. If a task seems to need that, stop and amend the proposal.
>
> Verification commands unless stated otherwise:
> `python3 -m unittest discover -s tests` and
> `SSL_DOCTOR_COLOR=never python3 ssldoctor.py -c "/version"`.

## 1. Baseline and token layer

- [ ] 1.1 Capture the current plain-mode output of `/help`, `/version`, `/timeout`, `/findings` and one `/scan --client-only` fixture run as golden text, and verify the capture files are the reference for group 6
- [ ] 1.2 Add the role table (TrueColor / 256 / 16 / plain) and a `ColorMode` resolver following the documented precedence, with `SSL_DOCTOR_COLOR` and `NO_COLOR`, and verify unit tests cover: NO_COLOR + truecolor, piped stdout, `TERM=xterm-256color`, `COLORTERM=truecolor`, and explicit `never`/`always`
- [ ] 1.3 Replace the raw `C.*` colour constants and `paint(text, *codes)` with `paint(text, role)` across the presentation helpers, keep `_USE_COLOR` as a compatibility alias, and verify `grep -n '\\\\033\[' ssl_doctor/*.py` finds escape literals only in the theme table
- [ ] 1.4 Add the glyph selector with an encoding probe and ASCII pairs (`✓/+`, `✗/x`, `⚠/!`, `▸/>`, `•/-`), and verify a test forces `cp1252` and asserts no Unicode box or check glyph is emitted
- [ ] 1.5 Add Windows virtual-terminal enabling with a plain-mode fallback, and verify a test simulating a failed enable produces no escape sequences

## 2. Layout components

- [ ] 2.1 Restyle `banner()`: primary bold title, one-line description, muted read-only note; remove nothing else. Verify `/version`, `-h` and startup still print the version, the command hint and the read-only note
- [ ] 2.2 Restyle `/help` as an aligned two-column listing (primary command, muted description) preserving all 25 rows and their order, and verify a test counts the rows and finds `/server nginx` and `/scan --client-only`
- [ ] 2.3 Introduce the command-block renderer (header label, row indentation, footer counters) and route `print_findings` through it, keeping `print_finding` usable standalone, and verify evidence, detail and `fix:` text are all present and untruncated for a 3-finding block
- [ ] 2.4 Add width detection and evidence wrapping with a hanging indent for terminals narrower than the block floor, and verify a 40-column run contains every evidence string with no ellipsis
- [ ] 2.5 Restyle `/diagnose` (ranked causes, certainty labels, evidence, `fix:`) and the step headers (`▸ Step n/m`), and verify the `/scan` fixture run still prints the same cause summaries and note lines as the baseline

## 3. Prompt and questions

- [ ] 3.1 Implement the dashed input frame with `>` prefix, width clamp (40–72) and terminal-size fallback to 80, and verify a non-tty run prints `ssl-doctor> ` with no frame while a pty run prints the dashed rule
- [ ] 3.2 Print the closing rule when a command returns so the transcript reads as a box, and verify the block header of the command's output follows the closing rule without an extra blank line
- [ ] 3.3 Restyle `prompt()` as a lavender question frame with `[Y]es [N]o` hints and a muted default, and verify the accepted answer sets, the `1=password 2=private key` loop and the `EOFError` default are unchanged by tests
- [ ] 3.4 Add the muted status line (target, counts, timeouts, SSH state) before the interactive prompt only, and verify it is absent under `-c`, under redirected stdout and in plain mode

## 4. Thinking indicator

- [ ] 4.1 Replace the braille spinner with the six-glyph reverse-mirror cycle at 120 ms in primary/shimmer with a per-invocation diagnostic verb, and verify it clears its line before output and stops on exception
- [ ] 4.2 Keep the single muted progress line for plain mode, and verify a redirected run contains exactly one progress line per check invocation and no carriage-return animation
- [ ] 4.3 Verify Ctrl-C during a check prints the existing `interrupted` note with no residual spinner text, by test with an injected slow check

## 5. Report styling

- [ ] 5.1 Restyle `report._CSS` to the shared palette (accent rule, hot-pink mono check ids, semantic pills and badges, subtle separators) with no structural change, and verify every badge/cause class used by `html_from_payload` still has a rule
- [ ] 5.2 Verify the report stays self-contained (no `http`, `src=`, `@import` or `<script`) and that contrast for body text and each pill is at least 4.5:1
- [ ] 5.3 Verify payload equality: build the same findings and diagnosis through `build_payload` before and after, and assert the rendered JSON is identical and the section headings/order are unchanged

## 6. Compatibility and documentation

- [ ] 6.1 Diff the new plain-mode output of `/help`, `/version`, `/timeout`, `/findings` and `/scan --client-only` against the group 1 goldens, and verify the only differences are the intended glyph substitutions and the new hierarchy spacing
- [ ] 6.2 Run the full suite plus `python3 ssldoctor.py -c "/tls <fixture>"` and `-c "/cert inspect <fixture>"`, and verify every verdict, count and exit code matches the pre-change run
- [ ] 6.3 Verify JSON report output is byte-identical to the pre-change run for the same fixture session
- [ ] 6.4 Re-run the batch examples with `NO_COLOR=1`, `TERM=dumb`, a 40-column terminal and a `cp1252` stdout, and verify no escape sequences, no Unicode glyphs and no truncated evidence in each case
- [ ] 6.5 Update the README with a short "terminal look" section and a refreshed example transcript (plain block plus a TrueColor capture), and verify every check id in the example still appears in the README check table
- [ ] 6.6 Add the restyle to `CHANGELOG.md` under an Unreleased heading, noting explicitly that commands, verdicts, exit codes and the findings contract are unchanged
- [ ] 6.7 Record the palette and border grammar as a Project Brain topic (`ui-design-system`) and note the static-frame decision (no shimmer inside `input()`) in `_decisions.md`
