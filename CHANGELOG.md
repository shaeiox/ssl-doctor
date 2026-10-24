# Changelog

## Unreleased — warm terminal interface

Presentation-only restyle, following the Claude Code terminal design language.
**Commands, flags, accepted answers, check ids, verdicts, exit codes, the JSON
report payload and the findings contract are unchanged.**

### What looks different

- **Full-screen application mode**: the interactive session now opens in the
  alternate screen as a centred column — header, scrollable output panel,
  status line, command bar and key hints. Output is captured into the panel
  (wrapped, never truncated), PageUp/PageDown scroll the transcript, and the
  command bar has editing and history. Questions and the spinner live in the
  status line, so the panel only ever shows results.
  Opt out with `--no-tui` or `SSL_DOCTOR_TUI=0`; batch runs, pipes and
  `TERM=dumb` keep the line-oriented REPL unchanged.

- **Startup banner**: a modern two-stroke wordmark spelling `SSL DOCTOR` between
  double rules, with the description, version, read-only note and
  `creator: eleven`. The full wordmark needs 64 columns; narrower terminals get
  a compact text form, and plain mode draws it with `#` and `=`.
- **Semantic colour roles** (`primary`, `tool`, `accent`, `success`, `warning`,
  `error`, `muted`, `subtle`, `surface`) with TrueColor → 256 → 16 → plain
  degradation. `NO_COLOR` wins over everything; new `SSL_DOCTOR_COLOR=never|always`
  exists for demos and captures. Piped output stays plain.
- **One frame per command**: findings print as rows inside a single box for the
  command that produced them, with the passed/failed/warnings/not-tested
  counters as the footer. Evidence, detail and `fix:` text are never truncated;
  narrow terminals wrap with a hanging indent.
- **Dashed ASCII input frame** with a `| > ` prompt and a muted status line
  (`target · 12 findings · 1 fail · timeout 8s · ssh off`) that is suppressed in
  batch (`-c`) runs and in plain mode.
- **Questions to the operator** (SSH setup, host-key trust, mode choice) are
  drawn in a lavender frame with key hints; the accepted answer sets are
  identical.
- **Thinking indicator**: `· ✢ ✳ ✶ ✻ ✽` reverse-mirror spinner in terracotta
  with a per-invocation verb replaces the braille spinner. Plain mode prints a
  single muted line. Progress is still a counter, never a bar.
- **HTML report** adopts the same palette (terracotta title rule, hot-pink check
  ids, semantic status pills). Still one self-contained, printable file with no
  scripts, fonts or remote assets.
- ASCII fallbacks (`+ x ! > -`) apply when the terminal encoding cannot render
  the glyphs; on Windows, ANSI is enabled explicitly and plain mode is used when
  that fails.
- `/diagnose` now prints its overall verdict (`PASS`/`FAIL`/`WARNING`) in words
  next to the title instead of encoding it in the title's colour only.

### Compatibility

- Plain mode output is unchanged apart from the status glyph and the `·` → `-`
  bullet substitution, so existing captured logs, tests and CI output keep
  working.
- `python3 -m unittest discover -s tests` covers the theme resolver, glyph
  fallback, frame content, prompt defaults, spinner lifecycle and report skin
  (`tests/test_terminal_ui.py`).


## v0.3.0 — diagnostic correctness

This release fixes how SSL Doctor diagnoses the most common nginx failure: a
certificate installed **without its intermediate**. Results on servers you
checked before may change. These are intended corrections, listed by check id.

### Root cause fixed

- On Python 3.10–3.12, v0.2.0 could not read the certificate chain the server
  sends, so it always saw "leaf only". A correct install and a broken install
  looked identical.
- When the engineer's machine had the intermediate cached, a leaf-only server
  was diagnosed as overall **PASS**, while customers without that cache failed.
- The Windows root-store check crashed on every real Windows host. Had it run,
  it would have blamed the client for server-side chain faults.

### Changed verdicts by check id

| Check id | Before (v0.2.0) | Now (v0.3.0) |
|---|---|---|
| `tls.chain` | Always "server sends only the leaf" on Python 3.10–3.12 | The chain the server **actually sends** (public API, internal API or `openssl s_client`). `PASS` for a complete, linked chain. `WARNING` for missing intermediates or a wrong intermediate (names the broken position). `NOT TESTED` if the chain can't be read |
| `tls.verify.rootonly` | — (new) | Validation against trusted roots only, with no cached intermediates. `PASS` on `tls.verify` with `FAIL` here pinpoints a missing intermediate that the cache was hiding |
| `tls.verify` | Accepted CN-only certificates | Name check uses subjectAltName only (`hostname_checks_common_name = False`), matching modern clients |
| `tls.hostname` | Fell back to the CN | subjectAltName only. A CN-only certificate is `FAIL`, with evidence that modern clients ignore the CN |
| `cert.hostname` | Fell back to the CN | Same SAN-only rule for inspected files |
| `local.rootca` | Crashed into `NOT TESTED` on Windows; when it did run, it looked up the *intermediate* as if it were the root | Reads the real `(der, encoding, trust)` store entries and looks up the root found by path building. `NOT TESTED` ("presented chain incomplete; anchor cannot be determined") when the chain is incomplete |
| `local.certutil` | Only with `/local <file>` | Also runs during `/scan` and `/local` on Windows, against the presented leaf |
| `nginx.domain` | Ignored the listen port; for duplicate names the last block won; any non-exact match was a `WARNING` | Only blocks on the target port count; first block wins; duplicates and fallbacks are `WARNING`; wildcard/regex matches are `PASS` |
| `nginx.certref` | Only reported when missing | Also reports the resolved paths, including `ssl_certificate` inherited from `http{}` |
| `nginx.chainfile` | Counted `BEGIN CERTIFICATE` (any two certificates passed) | Verifies the leaf comes first and each certificate is issued by the next |

### Diagnosis (`/diagnose`, reports, exit code)

- A missing or wrong intermediate (`tls.chain`, `nginx.chainfile`,
  `tls.verify.rootonly`) is now a **server** cause, ranked ahead of client
  causes, even when validation passes on the engineer's machine.
- `nginx.domain`, `nginx.certref` and `nginx.protocols` now feed the diagnosis.
  Previously no `nginx.*` finding was used.
- The client root-store cause (`local.rootca`) is raised only when the presented
  chain is complete. It is now `probable`, not `confirmed`, because the machine
  running the check may not be the affected client.
- A self-signed certificate is `confirmed` only when the presented chain itself
  shows it.
- "local issuer" validation errors with a *complete* chain are reported as an
  untrusted root, no longer as missing intermediates.
- Check ids are matched exactly; prefix matching would have confused
  `tls.verify` with `tls.verify.rootonly`.

### Other

- One package at the repository root (the v0.1.0 copy was removed), plus
  `pyproject.toml` with an `ssl-doctor` console entry point.
- Regression suite: `python3 -m unittest discover -s tests`. It uses a
  throwaway PKI and local `openssl s_server` fixtures, and skips cleanly
  without `openssl`.
