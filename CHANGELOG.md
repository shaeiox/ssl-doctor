# Changelog

## v0.7.0 — evidence-grounded TLS diagnosis

Diagnosis fixes from the handshake-attribution, evidence-based-probe,
legacy-protocol and legacy-TLS-semantics work. The findings contract moves from
1.1 to **1.5**; every step is additive and 1.0–1.4 stay published.

### Legacy-TLS diagnosis semantics

On a `google.com:443` scan TLS 1.0/1.1 completed a handshake only under
`ALL:@SECLEVEL=0` and their default-policy probes failed locally with
`NO_PROTOCOLS_AVAILABLE`. The classification was already correct, but the
remediation said to "treat legacy TLS as enabled until proven otherwise", the
open warning was reduced to a free-text note plus the generic "some checks report
warnings/failures", and a match among 4 of 7 DNS addresses read as "all 4
comparable endpoints". Findings contract **1.5** (additive; 1.0–1.4 stay published).

#### Root causes fixed

- The default-policy re-probe outcome was folded into `relaxed-only-unverified`
  without recording *why*: a client that never sent the probe (`client-limited`)
  and a probe without an answer read the same. It is now kept per version in
  `facts.probe_policy.default_probe`, and the evidence row says when nothing was
  sent to the server.
- Findings had no place for "why the evidence cannot settle this", so it lived in
  prose. `Finding.uncertainty` now carries it, separate from `evidence`.
- A warning with no justified cause had no structured home in the diagnosis.
  `diagnosis.unresolved` keeps `observed` / `conclusion` / `uncertainty` /
  `recommendation` apart; the generic note now names the unexplained findings.
- The endpoint comparison had no address count, so a partial match could not say
  it was partial. `endpoint_comparison.addresses` and an explicit coverage caveat
  were added.

#### Changed verdicts by check id

| Check id | Before | Now |
|---|---|---|
| `tls.protocols` (unverified legacy) | "Treat legacy TLS as enabled until proven otherwise … then disable them if accepted" | "Not confirmed - verify before changing anything", with a controlled `openssl s_client -tls1` / `-tls1_1` test and its limitations; the server's configuration is named as authoritative |
| `tls.multiip` | "all 4 comparable endpoint(s) present the same certificate facts" | "the 4 comparable endpoint(s) present the same certificate facts; 3 of 7 DNS address(es) were not compared", plus an uncertainty entry |
| diagnosis | note "Deprecated TLS may be enabled …" + "some checks report warnings/failures" | `unresolved` entry for `tls.protocols`; `overall` stays cause-derived |

### Legacy-protocol evidence

A single warning on `tls.protocols` could claim that "deprecated TLS 1.0/1.1 are
accepted by the server" after probing them only with `ALL:@SECLEVEL=0`. A lowered
security level proves that the server's stack can still negotiate a version when
legacy cipher suites are offered; it does not prove that an ordinary,
default-configured client can connect. The findings contract moves to **1.4**
(additive: per-version `support` classes and four new observations; 1.0–1.3 stay
published and keep validating).

#### Root causes fixed

- `check_protocol_matrix` probed TLS 1.0/1.1 exclusively under the relaxed cipher
  policy, so acceptance was reported as ordinary-client support. A default-policy
  probe now runs for every legacy version that answers, and the two facts are
  recorded separately.
- A probe the local client could not perform (`NO_PROTOCOLS_AVAILABLE`,
  `NO_CIPHERS_AVAILABLE`, `CA MD TOO WEAK`, a local SSL-context error) was returned
  as `refused`, i.e. as a server answer. With a modern OpenSSL build the default
  context has no TLS 1.0/1.1 ciphers, so a legitimate client limitation would have
  read as a server refusal.

#### Changed verdicts by check id

| Check id | Before | Now |
|---|---|---|
| `tls.protocols` | TLS 1.0/1.1 were probed only with `ALL:@SECLEVEL=0`; any answer became `[POSSIBLE · server] "deprecated TLS 1.0/1.1 are accepted by the server"` and the generic "protocol configuration carries compatibility/security risks" cause | Four per-version classes (`default`, `relaxed-only`, `relaxed-only-unverified`, `rejected`/`inconclusive`) and four observations. `default` ⇒ ordinary clients can negotiate the version; `relaxed-only` ⇒ a default-configured client is refused, reported with an explicit limitation; `relaxed-only-unverified` ⇒ a note, a WARNING and no cause about server support. Client-side probe limits are reported as a limitation of the test, never as a refusal |

#### Tests

- `tests/test_protocol_policy.py` (new): legacy accepted under the default policy,
  relaxed-only acceptance, an unverifiable default-policy probe, TLS 1.2 default
  support, TLS 1.3 support, refusals, timeouts before/after the handshake, and the
  diagnosis certainty, limitations and remediation that each case earns.
- `tests/test_probe_consistency.py` updated where it pinned the superseded
  semantics (`relaxed`-only tables, `client-limited` local errors, per-row
  inconclusive assertions).

### Evidence-based probes

Three unsupported warnings from a single scan are fixed at their source, and the
diagnosis now separates what was observed from what it infers. Findings contract
moves to **1.3** (additive: `observation`, `limitations`, `endpoints`,
`endpoint_comparison`, `probe_policy`; 1.0-1.2 stay published and keep validating).

#### Root causes fixed

- `check_multi_ip` compared error strings with certificate fingerprints, so an
  unreachable endpoint read as "different certificate"; it also compared only the
  fingerprint and probed addresses `net.tcp` never verified.
- The protocol matrix never saw the protocol the primary handshake negotiated, a
  timeout row was inert, and relaxed-policy acceptance was not separated from
  default-client interoperability.
- An SNI fingerprint difference was promoted to a virtual-host defect although a
  default certificate for clients without SNI is normal.

#### Changed verdicts by check id

| Check id | Before | Now |
|---|---|---|
| `tls.multiip` | Any difference between endpoint result *strings*, including unreachable endpoints, was a WARNING and a probable server cause | Only endpoints that completed a handshake for the same server name are compared, over fingerprint, hostname coverage and chain status. Fewer than two comparable endpoints ⇒ `NOT TESTED` (inconclusive, no cause); a measured difference ⇒ `WARNING` with both values and a listed limitation |
| `tls.sni` | A differing no-SNI certificate was a WARNING with "check virtual-host configuration", promoted to a possible server cause | An observation (`PASS` + `observation=sni-certificate-differs`); no cause; a missing no-SNI probe is `NOT TESTED`; only a failing handshake for the requested name is `FAIL` |
| `tls.protocols` | A stalled probe could be silent or read as a policy result; relaxed acceptance looked like ordinary support | Rows are accepted / accepted under relaxed policy / refused / inconclusive; a version the primary negotiated is never "refused"; inconclusive rows are retried once inside a budget and prevent a clean PASS; a TLS 1.2 default-policy probe states whether a modern client can connect |

### Handshake failure attribution

Fixes a diagnosis that blamed the server's protocol configuration for a stalled
TLS handshake. The findings contract moves to **1.2** (additive; 1.0 and 1.1
stay published and keep validating).

#### Root cause fixed

- `tls.handshake` recorded a timeout and a protocol/cipher rejection identically
  (`FAIL`, prose evidence only), and the diagnosis mapped on the status alone.
  A run with a stalled handshake next to "TLS 1.0–1.3 accepted" was reported as a
  probable **server** protocol/cipher mismatch.
- The handshake and the per-version probes re-resolved the hostname instead of
  using the address `net.tcp` verified, so they could measure a different
  endpoint than the one that was proven reachable.

#### Changed verdicts by check id

| Check id | Before | Now |
|---|---|---|
| `tls.handshake` | Any failure: `FAIL`, evidence "handshake/connect timed out" or "handshake failed", no structured cause | Failures carry `failure_kind`. A timeout is retried once: a recovered stall is `WARNING` (and still yields all certificate facts), a repeated stall is `FAIL`. A rejection is `FAIL` on the first attempt. Evidence names the phase, the probed address and each attempt |
| `tls.protocols` | A timeout was counted as "refused"; the relaxed cipher policy for TLS 1.0–1.2 was undisclosed | Rows are `accepted` / `refused` / `timed out` / `network error`; `failure_kind` is `no-version-accepted` or `no-version-answered`; accepted legacy versions disclose the `ALL:@SECLEVEL=0` policy |
| `tls.handshake` + `tls.protocols` | Contradiction possible: "handshake fails" beside "TLS 1.2/1.3 accepted" | A failed handshake states which versions did answer and that the failure is a stall or rejection on the default path |
| diagnosis | Timeout ⇒ probable **server** protocol/cipher mismatch whenever a version was accepted | Attribution follows `failure_kind`: timeouts and resets are probable **network** causes with path advice; only `tls-alert` can produce a protocol/cipher mismatch (server). Unclassified failures fall back to network with a note |

## v0.6.0 — modern two-stroke startup banner

Adds a modern two-stroke startup banner (wordmark, tagline, credit) sized for
the terminal, with compact fallback for narrow terminals.

## v0.5.0 — warm terminal interface + streaming + typewriter

Presentation-only restyle, following the Claude Code terminal design language.
**Commands, flags, accepted answers, check ids, verdicts, exit codes, the JSON
report payload and the findings contract are unchanged.**

### What looks different

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
