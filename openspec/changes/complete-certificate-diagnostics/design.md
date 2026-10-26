# Design

## Context

See proposal.md (Why). This section records the **verified baseline** at `master` @ 2f70fb0 (v0.10.1, clean tree, 2026-10-26). The audit report (`…/scratchpad/ssl-doctor-45-check-audit.md`) was re-checked against this checkout. Its reproduction scripts were re-run through the production functions, and every reproduced defect below still occurs.

### Execution path (unchanged by this design)

`ssldoctor.py` → `cli.main()` → `SSLDoctorCLI.cmd_scan` → `_gather_remote` (`netchecks.run_remote_diagnostics`) → `cmd_local` → `_scan_server_side` (`ServerSession.overview`, `webserver_detection`, `nginx_scan` → `_certificate_checks` → `_chainfile_finding` / `scan_cert`, `compare_configured_vs_presented`, `log_scan`) → `cmd_diagnose` (`analyze.diagnose`) → reports (`report.py`, `contract.py`).

The server agent runs the same server checks through `server.LocalSession` (`agent.run_server_checks`). Batch exit code: `cli.py:2703`, 1 iff `diagnosis.overall == "FAIL"`.

### Status model today

- `findings.Finding`: status ∈ {PASS, FAIL, WARNING, NOT TESTED}, plus `failure_kind`, `observation` and `uncertainty`.
- `contract.SCHEMA_VERSION = "1.6"`. The request's "findings/1.5" is one version behind; the current version is 1.6 (adds `nginx.path_resolution`).
- `analyze.Diagnosis.overall` comes from causes only: confirmed → FAIL, any → WARNING, none → PASS.

### Baseline classification

| Class | Items (audit IDs) | Evidence |
|---|---|---|
| Verified and complete | #26 live chain capture; #29 SNI | `netchecks.read_presented_chain` + `tests/test_tls_inspection.PresentedChainTests`; `check_sni_difference` + `tests/test_sni_observation` (pass) |
| Partially implemented | #1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 19, 21, 22, 23, 24, 25, 27, 28, 31, 32, 33, 34, 35, 37, 38, 40, 43, 44 | See the traceability table below |
| Missing | #3, 12, 14, 16, 17, 18, 20, 30, 36, 39, 41, 42, 45 | No implementing code in `ssl_doctor/` (grep for ocsp, crl, keyUsage, basicConstraints, certbot, configtest; `is_ca` parsed and unused) |
| Reproduced defects (re-run today) | R1 encrypted key → `srv.keymatch` FAIL (`e3b0c442…`) + confirmed cause; R2 expired intermediate → overall PASS / exit 0; R3 forged, non-CA and expired intermediates → `complete`; R4 expired on-disk leaf → `srv.cert` PASS; R5 verify timeout → FAIL + "certificate" cause; R6 truncated block ignored, corrupt middle block → PASS + WARNING; R7 duplicate → "broken", name-only self-signed → self-signed; R8 DER-encrypted key → FAIL | Scratch scripts `repro.py`, `repro2.py` against throw-away PKI |
| Audit observations not independently reproduced | O1 dual RSA+ECDSA → false `srv.compare` FAIL; O2 stale `last_remote_cert_sha256`; O3 local `match_cert_key` FAIL when the certificate public key is unextractable; O4 family-blind multi-IP selection; O5 `.key`-suffix-only permission rule | Code reading: `server.py:1420`, `:815/1141`, `certs.py:600–614`, `netchecks.py:1116`, `server.py:1209` |

Tests at baseline: `venv/bin/python -m unittest discover -s tests` → 708 run, OK, 24 skipped. The skips are the Windows/Secret-Service/X11 contracts, the release bundle and air-gap, and two permission-denied tests that cannot run as root. PKI fixtures (`tests/fixtures/pki.py`) contain no expired, encrypted, wildcard, EKU, duplicate or forged certificates.

### Constraints that shape the approach

- **The CLI is standard-library-only** (`requirements.txt` header, `pyproject.toml dependencies = []`). The system `openssl` binary is already the cryptographic tool (`certs._openssl`, remote pairing).
- **The server side is read-only:** no sudo, edits, reloads or restarts (spec `nginx-config-discovery` "Discovery is read-only"; README).
- **Unarchived changes still define related behaviour:**
  - `fix-chain-diagnosis-saas-enterprise` delta `tls-certificate-inspection` says linkage is "judged by issuer/subject name and by key identifiers when present".
  - `fix-tls-handshake-timeout-attribution` owns handshake failure classification.

## Goals / Non-Goals

**Goals:**
- One certificate-analysis core, used identically for presented, configured (over SSH or locally on the agent) and supplied certificates.
- Every verdict is backed by verified evidence, or explicitly marked inconclusive.
- Small phases that are each shippable and testable, ordered by correctness, then security, then dependency.

**Non-Goals:**
- Replacing the SSH transport, nginx discovery, TUI, or report layout.
- A pure-Python X.509/ASN.1 signature implementation.
- Prompting for passphrases.
- Fetching or installing intermediates.
- Any server mutation.
- Windows-native (CryptoAPI) chain building beyond the existing `local.certutil`.

## Decisions

### D1. Cryptography through the system `openssl`, analysed locally
Signature, self-signature, Basic Constraints and purpose checks run `openssl verify` on **public** PEM data:
- per link: `-partial_chain -no_check_time -CAfile <parent> <child>`, with `-no-CAstore`/`-no-CApath` where the version supports them, probed once;
- self-signature: `-check_ss_sig`;
- extensions: parsed from `openssl x509 -noout -text`.

Configured certificate files are fetched as public PEM over SSH (as `_chainfile_finding` already does) and analysed by the same local code. Only key operations stay remote.

When local `openssl` is absent (for example a Windows client without OpenSSL), the analysis falls back to the server's `openssl` for configured files. Otherwise the result is `verifier-unavailable`: names-only, WARNING at most, never PASS.

*Alternatives:*
- The `cryptography` package: rejected because it would break the stdlib-only CLI promise and packaging.
- Running all verification remotely: rejected because there would then be two code paths, and presented chains have no server.
- Stdlib `ssl` contexts per link: rejected because they cannot verify an arbitrary certificate offline.

### D2. Module boundaries (additive, no large refactor)
- `certs.py`: parsing only. Strict block accounting, format sniffing, `CertInfo` extended with record fields (role, key details, BC/KU/EKU, AIA/CDP, verification flags). `assess_chain(chain, roots)` stays as a compatibility wrapper over the new builder and keeps its return type.
- `chainval.py` (new): link verification, path building (AKI/SKI candidate ordering, bounded at 8 paths and depth 8), trust evaluation and class, missing-issuer naming.
- `certpolicy.py` (new): validity and threshold logic, the key/algorithm policy table (versioned `policy 1`).
- `revocation.py` (new): stapled-OCSP parsing via `openssl ocsp -respin`, and opt-in online OCSP/CRL.
- `services.py` (new): listener owner (`ss -ltnpH` / `netstat` fallback), Apache/HAProxy detection and path extraction, configtest, reload evidence, renewal discovery. nginx stays in `nginx_discovery.py` and `server.py`.
- `server.py`: key-state probe, multi-pair handling, permission integration, per-run state reset. It composes the modules above and does not duplicate them.
- `analyze.py`: verdict computation, an unexplained-failure pass, and new rules.

*Alternative:* a single `certs.py` rewrite. Rejected: it is already 615 lines and mixes parsing with findings, and new modules keep each phase reviewable.

### D3. Status semantics
| Status | Meaning | Counts toward overall |
|---|---|---|
| PASS | The question was answered with complete evidence, and the answer is good | no |
| FAIL | Directly measured defect (two derived digests differ, signature fails, expired, configtest exit ≠ 0 and not a permission error) | FAIL unless explained; unexplained FAIL with a transport `failure_kind` → WARNING |
| WARNING | Defect that is risky but not broken, or a conclusion limited by its evidence (names-only linkage, an unconfirmed configuration) | WARNING |
| NOT TESTED | Inconclusive or not runnable; `failure_kind` says why (`verifier-unavailable`, `key-encrypted`, `key-unreadable`, `command-failed`, `permission-denied`, existing transport kinds) | never raises the verdict; listed in notes |

"Inconclusive" is not a new status. It is NOT TESTED plus `failure_kind` and `uncertainty`, consistent with the 1.2–1.5 schema conventions. `Diagnosis.unresolved` keeps its role, and the new `Diagnosis.unexplained` lists FAIL/WARNING findings no rule claimed.

### D4. Verdict algorithm
1. Run the rule set. Each rule records the check ids it explains.
2. Every FAIL/WARNING finding not explained and not already in `unresolved` goes into `unexplained`.
3. Overall:
   - FAIL if there is a confirmed cause, or an unexplained FAIL without a transport `failure_kind`;
   - else WARNING if there are causes or unexplained entries;
   - else PASS.
4. The exit code derives from overall (unchanged mapping).

This keeps the "observation never FAIL" guarantees: observations are not FAIL findings.

### D5. Remote command hygiene
Every remote pipeline whose output is judged returns explicit markers and exit statuses (`echo "@@SSLDOCTOR rc=<n> step=<name>"`). No digest is computed over possibly-empty output: the key digest step runs only when `openssl pkey` exits 0. Commands keep `shlex.quote`, the `SAFE_PATH` filters and `command_timeout`, and stay read-only. The key-state probe reads at most the first 4 KiB, through `openssl` and `grep -c`, and returns only a classification token.

### D6. Per-run state
`ServerSession` stores configured fingerprints in a per-scan context created by `nginx_scan` and `/server cert`. `compare_configured_vs_presented` reads only the current context. This removes the stale `last_remote_cert_sha256` (O2). The attribute stays as a read-only alias of the latest context for compatibility.

### D7. Revocation default = stapled only
The default sends no new network destination, so offline and air-gapped behaviour is unchanged. `--revocation=online` enables AIA OCSP, then CRL, under the scan timeout. `--revocation=off` reports `not-checked`.

### D8. Configuration tests run only trusted binaries, in test mode
The configuration test reuses discovery's trust rule (root-owned, not group- or world-writable) and the master's `-p`/`-c`. `nginx -T` is already run today, but its result is discarded (`server.py:666`, `2>/dev/null`). The same invocation now keeps its exit status and stderr, so no additional command is introduced for nginx.

### D9. Contract 1.7 additive
1.7 adds `CHECK_IDS`, `FAILURE_KINDS`, `facts.certificates` and `diagnosis.unexplained`. It changes no existing field. `facts.chain_status = complete` now additionally requires verified links. This is a semantic tightening: it can turn a former `complete` into `broken`, which is the point, and it is documented in CHANGELOG. The service's `monitor.conditions_of` keeps working and optionally reads `chain.validity` / `tls.revocation`.

### Decisions requiring approval before implementation
The specs encode the default shown here; approving otherwise changes the named spec.

- **U1:** supersede the name-based linkage requirement of the unarchived `fix-chain-diagnosis-saas-enterprise` `tls-certificate-inspection` delta, with this change's `certificate-chain-validation` "Every link's signature is verified". Default: supersede; amend that delta's text when it is archived.
- **U2:** exit-code semantics. Default: keep `1 iff FAIL`; FAIL now includes unexplained FAILs. Alternative: a distinct code (2) for "incomplete evidence". Not chosen, to avoid breaking scripts.
- **U3:** passphrases. Default: never accepted. A future opt-in passphrase channel (stdin/askpass, memory only) would be a separate change.
- **U4:** online revocation. Default off (stapled only).
- **U5:** service scope. Default: nginx full, Apache httpd and HAProxy path discovery plus configtest; others named only.
- **U6:** key/algorithm policy thresholds (RSA ≥ 2048 FAIL boundary; SHA-1 FAIL for non-anchors; EC curve list). Default as specified in `certificate-lifecycle-policy`.
- **U7:** an unexplained transport FAIL counts as WARNING, not FAIL.

## Implementation phases

Each phase has an entry and an exit gate. Exit always requires the full suite green with the skip list unchanged (see the test strategy).

| Phase | Scope (audit IDs) | Entry | Exit criteria |
|---|---|---|---|
| P0 Correctness hotfixes + contract 1.7 scaffold | R1, R5, R2, R8, O3 → #1, #5, #22, #7/#13 verdict; CEM registry | Baseline green, baseline test-id list recorded | Encrypted key (PEM/DER, local/SSH) → NOT TESTED `key-encrypted`; verify timeout → NOT TESTED; expired-intermediate scenario → overall FAIL, exit 1; `findings-1.7.schema.json` validates new and old documents; regression tests for R1/R2/R5/R8 added |
| P1 Strict parsing and records | #8, #9, #10, #11, #12, #3 | P0 | Truncated/corrupt/PKCS#7/PKCS#12/duplicate fixtures produce the specified findings; `CertInfo` records populated |
| P2 Verified chains | #4, #15, #16, #17, #18, #19, #21, #2, #6, #20 | P1 | Forged/non-CA/pathlen/EKU/name-only-self-signed fixtures broken/FAIL; cross-signed fixture lists 2 paths; `assess_chain` wrapper keeps existing tests green |
| P3 Trust, lifecycle, policy | #7, #13, #14, #22, #25, #40, #41, #42, #43, #23, #24 | P2 | Every certificate date-checked; `srv.cert` judges dates and SAN; trust class per fixture; threshold option; hostname matcher tests |
| P4 Structured facts and diagnosis rules | CEM facts.certificates, DC validation-reason rules for P1–P3 | P3 | `facts.certificates` populated for presented/configured/supplied chains; every new check id maps to a cause or lands in `unexplained`; agent report shows the new facts |
| P5 Server deployment | #32, #33, #34, #35, #38, #39, #44, #27 | P4 | Dual-certificate fixture; permissions in `/scan`; per-run compare; chain compare; `srv.keystartup`; inventory |
| P6 Service discovery and runtime | #31, #36, #37, #45 | P5 | Listener owner; configtest exit codes kept; reload evidence; renewal discovery; command audit test proves no state-changing command |
| P7 Network extras | #28, #30 | P4 | Family-balanced probing; stapled OCSP states via a local OCSP-stapling fixture; opt-in online check behind a flag with a mocked responder |

P7 depends only on P4, so it can run in parallel with P5/P6.

## Requirement traceability (audit #1–#45)

Spec abbreviations:

| Abbreviation | Spec |
|---|---|
| CFI | certificate-file-inspection |
| PKI | private-key-inspection |
| CCV | certificate-chain-validation |
| CTC | certificate-trust-classification |
| CHC | certificate-hostname-coverage |
| CLP | certificate-lifecycle-policy |
| REV | certificate-revocation |
| TSD | tls-service-discovery |
| SCD | server-certificate-deployment |
| CEM | certificate-evidence-model |
| DC | diagnosis-correlation |
| TND | tls-negotiation-diagnostics |
| EC | endpoint-comparison |
| NCP | nginx-cert-path-resolution |

| ID | Intent | Verified current status | Target behaviour | Spec · requirement | Depends on | Acceptance test (to add) |
|---|---|---|---|---|---|---|
| 1 | Encrypted key detection | Partial: PEM marker local only; SSH false FAIL (R1); DER FAIL (R8) | Key state classified everywhere; encrypted → NOT TESTED | PKI · key state classified; DC · pairing needs conclusive evidence | — | `test_private_key_states`: PEM/PKCS#8/DER-encrypted × local/LocalSession |
| 2 | Full chain in files | Partial (name-based) | Leaf-only vs full with verified links, all sources | CCV · full-chain vs leaf-only | 16, 17 | Existing `ChainFileTests` + signatures-verified evidence |
| 3 | Root file completeness | Missing | Parse and classify CA/root bundles | CFI · root and CA bundle files | 9, 21 | `test_ca_bundle`: root + intermediate bundle; name-only root |
| 4 | Certificate/CA matching | Partial (names, AKI) | Signature-verified links | CCV · every link's signature | 16 | forged.pem → broken |
| 5 | Key/certificate match | Partial; inconclusive → FAIL | SPKI compare; NOT TESTED when underivable | PKI · pairing compares; unextractable digest | 1 | Mismatch FAIL, openssl rc≠0 → NOT TESTED, no openssl → NOT TESTED |
| 6 | Missing intermediate | Partial (strong; anchor assumption) | Incomplete + named missing issuer/AIA; anchored-unknown | CCV · missing intermediates | 16, 19 | e2e table + leaf AIA in evidence |
| 7 | Domain and trust | Partial (live only; `srv.cert` unjudged R4) | Same verdict for configured and presented | CTC · same domain and trust verdict; DC · exit code | 13, 22, 23 | Expired on-disk leaf via LocalSession → FAIL |
| 8 | Format detection | Partial | Content sniffing incl. PKCS#7/12 | CFI · format from content | — | DER-as-.pem, PKCS#7, PKCS#12 without extension |
| 9 | Malformed/incomplete | Partial (R6) | Any bad block → FAIL | CFI · malformed and truncated | 8 | trunc.pem, corrupt.pem, server truncated file |
| 10 | Multiple certificates | Partial | Per-certificate inventory | CFI · every certificate inventoried | 9 | Three-certificate file evidence |
| 11 | Wrong certificate in file | Partial | Role from BC/signatures; CA-first FAIL | CFI · roles classified | 17, 21 | reversed.pem → CA-first FAIL |
| 12 | Duplicates | Missing (R7) | Duplicate WARNING, linkage unaffected | CFI · duplicates | 9 | dup.pem |
| 13 | Expired / not yet valid | Partial (leaf only) | Every certificate | CLP · every certificate's validity | 10 | Expired int live + configured; future notBefore |
| 14 | Key strength | Missing (display only) | Policy table | CLP · key strength | 10 | RSA-1024, P-256, Ed25519 fixtures |
| 15 | Issuer/subject | Partial (string DN) | Canonical name compare | CCV · issuer and subject relationships | 10 | Wrong intermediate; case-variant names |
| 16 | Signature verification | Missing (implicit in tls.verify only) | Per-link verify | CCV · every link's signature | D1 | forged.pem; verifier missing → WARNING |
| 17 | Basic Constraints | Missing (`is_ca` unused) | CA:TRUE and pathLen enforced | CCV · CA eligibility | 10 | nonca.pem; pathlen fixture |
| 18 | KU/EKU | Missing | serverAuth / keyCertSign | CCV · KU and EKU | 10 | clientAuth-only leaf; CA without keyCertSign |
| 19 | AKI/SKI | Partial | AKI-guided selection + ambiguity | CCV · AKI and SKI guide issuer selection | 10, 16 | Two same-name roots |
| 20 | Alternative/cross-signed | Missing | Bounded path enumeration | CCV · alternative and cross-signed paths | 16, 19 | Cross-signed fixture: 2 paths |
| 21 | Self-signed | Partial (names; R7) | Verified self-signature | CCV · self-signed is verified | 16 | fakess.pem; genuine self-signed |
| 22 | Chain to anchor | Partial (live only; R2/R5) | Named trust config; transport inconclusive; configured chains validated | CCV · validation names its anchor; TND · validation handshakes classify; DC · inconclusive validation | 16, 13 | Silent listener → NOT TESTED; expired int → FAIL; store named |
| 23 | SAN hostname | Partial (no IDN/IP rules tested) | SAN-only + IDN, IP, case | CHC · SAN only | — | Hostname matrix unit test |
| 24 | Wildcard | Partial (untested) | Single-label, no partial/public suffix | CHC · wildcards | 23 | Wildcard matrix |
| 25 | Trust classification | Partial (scattered) | `public`/`private`/`self-signed`/`unknown` | CTC · trust class explicit | 22, 21 | Private CA via `ssl_trusted_certificate`; public-looking unknown |
| 26 | Live chain inspection | **Verified** | Unchanged; feeds the new analysis | TND · presented chain feeds analysis | — | Existing `PresentedChainTests` kept; chain flows into `chain.validity` |
| 27 | Local-to-live comparison | Partial (leaf only) | Full ordered chain compare | SCD · full configured chain compared | 35 | Configured B vs presented A |
| 28 | IPv4/IPv6 | Partial | Both families probed and labelled | EC · both families; family differences | — | Mocked 5×v4 + 2×v6; v6-only cert difference |
| 29 | SNI | **Verified** | Unchanged | Existing `sni-behaviour-observation` (no delta) | — | Existing `tests/test_sni_observation` must stay green |
| 30 | OCSP/CRL | Missing | Five explicit states; stapled default | REV · all; TND · stapling | 16 | Local stapling server good/revoked/stale; unreachable responder |
| 31 | Service detection | Partial (nginx) | Listener owner; Apache/HAProxy | TSD · TLS-terminating process; Apache and HAProxy | — | Fake `ss` output; caddy listener |
| 32 | Path discovery | Partial (nginx first pair) | All pairs; Apache/HAProxy paths | SCD · paths for every service; NCP · every pair | 31 | Dual pair; Apache vhost; HAProxy crt |
| 33 | Path validation | Partial (nginx; verdict gap) | All services; verdict propagation | SCD · configured paths validated; NCP · path failures reach the verdict | 32 | Missing Apache key; nginx path FAIL → overall FAIL |
| 34 | Permissions | Partial (`.key`, not in /scan) | Role-based, in /scan, worker account | SCD · permissions by role | 32 | 0644 `.pem` key; unreadable for www-data; present in /scan |
| 35 | On-disk vs active | Partial (O1, O2) | Every configured leaf; per-run state | SCD · active vs every configured certificate | 32, 38 | ECDSA served from dual; stale-state sequence |
| 36 | Config validation | Missing (`-T` rc discarded) | `srv.configtest` with the real exit status | TSD · native configuration test; never a state change | 31 | `nginx -t` rc=1; permission-only failure → NOT TESTED; untrusted binary |
| 37 | Reload state | Partial (weak) | Certificate mtime vs worker start; journal | TSD · reload state evidenced | 31, 32 | Certificate newer than workers → WARNING |
| 38 | Multiple certs/vhosts | Partial | Listen-address selection, RSA+ECDSA | SCD · multiple certificates, vhosts, listeners; NCP · every pair | 32 | Address-specific listen; dual pair |
| 39 | Encrypted key startup | Missing | `srv.keystartup` | SCD · encrypted-key compatibility | 1 | Encrypted key ± `ssl_password_file` |
| 40 | Expiry warning | Partial (hard-coded 30) | Configurable 1–365 | CLP · expiry warnings | 13 | Thresholds 30/14/invalid |
| 41 | Intermediate expiry | Missing (R2) | Expired / earlier-than-leaf reported | CLP · validity; intermediates expiring before the leaf; DC · verdict | 13 | Live expired int → FAIL, exit 1; short-lived int WARNING |
| 42 | Root / trust store | Missing | Anchor validity; store limits | CTC · trust-anchor validity | 22 | Expired root anchor; empty store → NOT TESTED |
| 43 | Deprecated algorithms | Partial (protocol only) | Certificate signature policy | CLP · deprecated signature algorithms | 14 | SHA-1 intermediate FAIL; SHA-1 root not judged |
| 44 | Unexpected certificates | Partial | `srv.inventory` | SCD · other configured certificates | 32, 35 | Second block covering the domain |
| 45 | Renewal discovery | Missing | `srv.renewal` only when linked | TSD · renewal tooling | 32 | certbot renewal conf naming the path; installed but unlinked; none |

Cross-cutting specs: CEM (contract 1.7) is required by every new check id. DC MODIFIED "Existing verdict semantics are preserved" governs R2 for all IDs.

## Test strategy

### Fixtures (deterministic, offline)
Extend `tests/fixtures/pki.py`, which already shells out to `openssl` and caches per run, with:
- an expired / not-yet-valid leaf and intermediate (via `-not_before` / `-not_after` where available; otherwise `openssl ca -startdate/-enddate` with a temporary CA database)
- a forged intermediate (same DN and SKI, other key)
- a non-CA issuer, a pathLen-violating chain, a clientAuth-only leaf, a CA without keyCertSign
- a name-only self-signed certificate, a cross-signed intermediate with two roots, two same-name roots
- RSA-1024 / P-256 / Ed25519 leaves and a SHA-1 signed intermediate
- PEM / DER / PKCS#8-encrypted / legacy-encrypted keys
- PKCS#7 and PKCS#12 files, truncated, corrupt, duplicate and mixed certificate+key files

A fixture the local `openssl` cannot build is skipped *with a named reason*, and never silently passes.

### Test layers
| Layer | Mechanism | Covers |
|---|---|---|
| Unit | Pure functions over fixture PEM: parser, roles, dedup, matcher, policy, path builder (verify calls real `openssl`) | #3, #8–#24, #40–#43 |
| Regression (one per reproduced defect R1–R8, O1–O5) | Named `test_regression_<id>`; reuses the scratch reproductions as tests | D-list in proposal |
| Server (fake host) | `tests/fixtures/nginx_host.py` / `fake_server.py` extended with `openssl pkey/verify`, `ss`, `stat`, `journalctl`, Apache/HAProxy configs; `LocalSession` runs real `/bin/sh` scripts | #1, #5, #31–#39, #44, #45 |
| Integration TLS | `tests/fixtures/tls_server.py` gains modes: expired-int, eku-client, dual RSA/ECDSA (two contexts by SNI or cipher), OCSP staple (pre-generated `openssl ocsp` response loaded with the server context's stapling callback, or `openssl s_server -status_file`) | #7, #13, #22, #26, #27, #29, #30, #35 |
| IPv4/IPv6 | Mocked `getaddrinfo` and `_probe_endpoint` (as `test_endpoint_comparison` does); a real `::1` listener when `socket.has_ipv6` and loopback v6 works, skipped with a reason otherwise | #28 |
| Verdict and exit code | Table test: findings set → `overall` → `cli.main(["-c", …])` exit status, for R2/R5/observation-only/NOT TESTED-only | DC |
| Contract | Validate every new-scan document against 1.7, and every stored 1.0–1.6 sample against its own schema; agent-report equality test | CEM |
| Security | Scan outputs (stdout, JSON, HTML, agent report, upload payload) grepped for every line of each fixture key and passphrase file; a command audit test asserts no state-changing command (`reload`, `restart`, `kill`, `sudo`, `systemctl start/stop/restart/reload`, `-s `) is issued | PKI, TSD, CEM |

### Platform handling
- Windows-only behaviour (`local.certutil`) keeps its existing skip.
- `verifier-unavailable` paths are tested by masking `openssl` from `PATH`, so they run everywhere.
- Permission-denied tests need a non-root run: CI gets a non-root job, and locally the skip names "root reads everything", as today.

### Guarding against weakened tests
- Record the baseline before P0: `unittest discover -s tests -v` → test-id list and skip list (`708 run, 24 skipped`).
- Every phase exit compares the run against the baseline. No test id may disappear and no new skip may appear without an entry in tasks.md naming the reason.
- `git diff --stat tests/` is reviewed for deleted assertions. Assertion changes to existing tests are allowed only where a spec here explicitly changes behaviour (listed per task).

## Risks / Trade-offs

- **`openssl` CLI differences (1.1.1 vs 3.x; LibreSSL on macOS)** → probe flags once (`-no-CAstore`, `-not_after`); parse `-text` defensively; CI on 1.1.1 and 3.x; unknown output → `verifier-unavailable`, not PASS.
- **Performance:** about 2–3 `openssl` calls per certificate and a trust-store scan → decode roots lazily (SKI only for name-matching candidates); cache per run; bound path enumeration (8 paths, depth 8). Target: under 2 s added for a 3-certificate chain on a laptop.
- **Trust-store differences:**
  - Linux `capath`-only stores return no `get_ca_certs` until loaded; the existing fallback is kept.
  - Windows trust is the platform store; verdicts there stay labelled as this machine's.
  - Classification is always "for this trust configuration", never "for every client".
- **Root expiry semantics:** clients differ (some ignore anchor expiry; RFC 5280 does not require checking it) → `anchor expired` is WARNING with a limitation, never FAIL by itself.
- **Revocation:** online checks leak the queried certificate to the CA's responder and can hang → off by default; bounded by the scan timeout; any failure → `inconclusive`. CRLs can be large → size cap (10 MiB) or `inconclusive`.
- **`nginx -t` / `-T` side effects:** as a non-root account, nginx may try to open log files and can create them if a directory is writable. The behaviour already exists with `-T`. Keep the trusted-binary rule, document it in README, and classify permission-only failures as NOT TESTED.
- **Listener-owner visibility:** `ss -p` shows owners only for the account's own processes unless privileged → NOT TESTED, with the binaries on PATH still listed.
- **Apache/HAProxy parsing is shallow** (no full `Include`/`Define` semantics in phase P5) → findings are capped at `candidate` evidence level and causes at `probable`, mirroring nginx's unconfirmed-configuration rule.
- **Verdict tightening changes outcomes:** some scans that were PASS become FAIL (exit 1) → CHANGELOG entry with examples; the `unexplained` list makes the reason visible; U7 keeps transport issues at WARNING.
- **`chain_status` tightening affects monitoring alerts:** a previously `complete` name-linked chain may become `broken` → intended; the release note tells service operators to expect new chain alerts on genuinely broken chains.
- **Secrets:** new remote commands touch key files → only `openssl` reads them; only classification tokens and digests are returned; the security grep test covers every export path.

## Migration Plan

- Ship by phase; each phase is a minor version with a CHANGELOG entry. The contract becomes 1.7 in P0. P0 registers every new check id, `failure_kind` and the optional `facts.certificates` / `diagnosis.unexplained` fields, so later phases only start emitting registered values and the schema never changes mid-change.
- Rollback: each phase is independently revertible. Documents written as 1.7 remain readable by 1.7+ only; the service stores them as-is and older dashboards ignore unknown fields.
- README, the commands reference and the brain topics (`chain-diagnosis`, `server-ssh-nginx`) are updated per phase.

## Open Questions

- Exact OCSP stapling fixture technique (Python `ssl` has no server-side stapling API; `openssl s_server -status_file` is the likely fixture). Deferrable to P7 without changing the specs.
- Whether CI already has a Windows runner (`fix-chain-diagnosis-saas-enterprise` task 1.5 is open). Only affects where `verifier-unavailable` is exercised natively.
