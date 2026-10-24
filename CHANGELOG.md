# Changelog

## Unreleased — handshake failure attribution

Fixes a diagnosis that blamed the server's protocol configuration for a stalled
TLS handshake. The findings contract moves to **1.2** (additive; 1.0 and 1.1
stay published and keep validating).

### Root cause fixed

- `tls.handshake` recorded a timeout and a protocol/cipher rejection identically
  (`FAIL`, prose evidence only), and the diagnosis mapped on the status alone.
  A run with a stalled handshake next to "TLS 1.0–1.3 accepted" was reported as a
  probable **server** protocol/cipher mismatch.
- The handshake and the per-version probes re-resolved the hostname instead of
  using the address `net.tcp` verified, so they could measure a different
  endpoint than the one that was proven reachable.

### Changed verdicts by check id

| Check id | Before | Now |
|---|---|---|
| `tls.handshake` | Any failure: `FAIL`, evidence "handshake/connect timed out" or "handshake failed", no structured cause | Failures carry `failure_kind`. A timeout is retried once: a recovered stall is `WARNING` (and still yields all certificate facts), a repeated stall is `FAIL`. A rejection is `FAIL` on the first attempt. Evidence names the phase, the probed address and each attempt |
| `tls.protocols` | A timeout was counted as "refused"; the relaxed cipher policy for TLS 1.0–1.2 was undisclosed | Rows are `accepted` / `refused` / `timed out` / `network error`; `failure_kind` is `no-version-accepted` or `no-version-answered`; accepted legacy versions disclose the `ALL:@SECLEVEL=0` policy |
| `tls.handshake` + `tls.protocols` | Contradiction possible: "handshake fails" beside "TLS 1.2/1.3 accepted" | A failed handshake states which versions did answer and that the failure is a stall or rejection on the default path |
| diagnosis | Timeout ⇒ probable **server** protocol/cipher mismatch whenever a version was accepted | Attribution follows `failure_kind`: timeouts and resets are probable **network** causes with path advice; only `tls-alert` can produce a protocol/cipher mismatch (server). Unclassified failures fall back to network with a note |

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
