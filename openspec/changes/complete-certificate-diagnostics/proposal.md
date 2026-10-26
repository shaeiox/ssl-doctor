# Proposal

## Why

SSL Doctor's job is to tell an operator, often a novice, *which* certificate, key, chain, service or network path is wrong and what to do about it. The 45-requirement audit (2026-10-26, `master` @ 2f70fb0) was re-checked against the current checkout (same commit, clean tree). Every reproduction still holds. The tool currently gives verdicts its evidence does not support:

- **False confirmed FAIL.** An encrypted private key on the server is reported as "the configured private key does NOT match", with *confirmed* certainty. The SSH pipeline hashes the empty output of a failed `openssl pkey` (`e3b0c442…`) (`server.py:1155–1190`, `analyze.py:370`).
- **False PASS.** A live endpoint that serves an expired intermediate gets `tls.verify` FAIL, yet the diagnosis is `overall: PASS` and the exit code is 0. `Diagnosis.overall` (`analyze.py:76–81`) is computed only from matched causes, and `analyze.py:342` drops "expired" as "covered" by the leaf-only validity rule.
- **Names treated as proof.** `certs.issued_by`, `assess_chain` and `is_self_signed` (`certs.py:94,291,350`) never check a signature or a CA flag. A forged intermediate (same name and SKI, different key), a non-CA "intermediate" and an expired intermediate are all reported `complete` / PASS.
- **Unjudged on-disk facts.** An expired configured certificate gets `srv.cert` PASS (`server.py:1142`). Only the first certificate of any file is date-checked.
- **Transport reported as certificate.** A timeout in the validation handshake becomes `tls.verify` FAIL plus a probable *certificate* cause (`netchecks.py:532,577`).
- **Lenient parsing.** A truncated trailing PEM block is ignored, and a corrupt middle block still yields `cert.parse` PASS. A duplicated certificate is reported as a misordered chain. A DER-encoded encrypted key is FAIL instead of NOT TESTED.

The audit also found 13 capabilities with no implementation:
- root/CA file parsing
- duplicate detection
- key and algorithm policy
- signature verification
- Basic Constraints
- KU/EKU
- alternative chains
- revocation
- configuration validation
- encrypted-key service compatibility
- intermediate expiry
- root/trust-store expiry
- renewal discovery

A further 30 capabilities exist but are incomplete or unverified. Only live chain capture (#26) and SNI (#29) are complete and verified.

This change defines the end state: every certificate SSL Doctor reads, whether presented, configured or supplied, goes through one verified analysis. Transport gaps stay inconclusive. A genuine failure can never vanish from the overall verdict.

## What Changes

**Diagnostic correctness (fixes reproduced defects)**
- The private-key state is classified (`readable`, `encrypted`, `unreadable`, `unsupported`) before any pairing. Encrypted or unextractable keys make pairing NOT TESTED, never FAIL, locally (PEM and DER) and over SSH. Remote commands are judged by exit status, not by hashing their output.
- The overall verdict and the CLI exit code account for every FAIL finding. A FAIL that no correlation rule explains raises an *unexplained failure* entry and keeps the overall at FAIL. Inconclusive results never raise the verdict to FAIL on their own. **Behaviour change:** scans that are PASS today with a FAIL finding become FAIL (exit 1).
- Timeouts and network errors during `tls.verify` / `tls.verify.rootonly` are NOT TESTED with a `failure_kind`, and never support a certificate cause.
- Certificate validity, signature, Basic Constraints and EKU are judged for **every** certificate in presented and configured chains. `srv.cert` judges the on-disk certificate's dates and SAN.
- Strict PEM/DER parsing: unterminated, undecodable or trailing-garbage blocks are FAIL; duplicates are reported as duplicates.

**New verified certificate analysis (shared by local, SSH and agent workflows)**
- Each certificate gets a structured record with its role (leaf / intermediate / root / unrelated): position, fingerprints, names, validity, key type/size/curve, signature algorithm, Basic Constraints, KU/EKU, SKI/AKI, AIA and CRL distribution points.
- Chain building is cryptographic: per-link signature verification and a verified self-signature through the system `openssl` (the CLI stays standard-library-only). It uses AKI/SKI-guided issuer selection and enumerates alternative and cross-signed paths.
- Trust evaluation against a named trust configuration. Classification as `public`, `private`, `self-signed` or `unknown` is never inferred from issuer names.
- An explicit certificate algorithm and key-strength policy, with configurable expiry-warning thresholds (default 30 days, unchanged).
- Revocation status (`good`, `revoked`, `unavailable`, `not-checked`, `inconclusive`) from the stapled OCSP response by default. A live OCSP query is opt-in.

**Server-side service and certificate discovery**
- A listener-owner probe names the process that terminates TLS on the target port. Read-only detection covers Apache httpd and HAProxy in addition to the existing nginx discovery.
- Handling of multiple `ssl_certificate`/`ssl_certificate_key` pairs (RSA + ECDSA). An inventory of every configured certificate, with the one actually served flagged.
- Configured-vs-served comparison per certificate and over the full chain. Comparison state is reset per run.
- Role-based permission and ownership checks inside `/scan` and the server agent, including service-account readability, without reading key content.
- The native configuration test result (`nginx -t`, `apachectl -t`, `haproxy -c`) is recorded with its real exit status and a redacted stderr summary.
- Reload/restart evidence: certificate mtime vs worker start, and service journal lines when readable. Services are never reloaded or restarted.
- Encrypted-key startup compatibility (`ssl_password_file` / `SSLPassPhraseDialog` presence, never content).
- Read-only discovery of renewal tooling (certbot, acme.sh, lego, timers/cron) linked to the configured paths.
- Per-address-family endpoint probing: at least one IPv4 and one IPv6 address when both exist, with family labels.

**Contract and reporting**
- `findings/1.7`: additive only. New check ids, failure kinds, observations and a `facts.certificates` block. Existing 1.6 fields keep their meaning; 1.0–1.6 documents stay loadable.

## Capabilities

### New Capabilities
- `certificate-file-inspection`: content-based format detection, strict parsing of malformed/truncated input, per-certificate inventory and role classification, duplicate detection, root/CA bundle parsing (audit #3, #8, #9, #10, #11, #12).
- `private-key-inspection`: key-state classification, encrypted-key handling, and cryptographic certificate/key pairing that never reports an inconclusive result as a mismatch (audit #1, #5).
- `certificate-chain-validation`: issuer/subject and AKI/SKI relationships, per-link signature verification, Basic Constraints, KU/EKU, verified self-signature, path building with alternative/cross-signed chains, missing-intermediate detection, and validation to a named trust anchor (audit #2, #4, #6, #15–#22).
- `certificate-trust-classification`: domain plus trust verdict for configured and presented certificates, the public/private/self-signed/unknown class, and trust-anchor and trust-store limitations (audit #7, #25, #42).
- `certificate-hostname-coverage`: SAN-only and wildcard matching rules with IDN, IP and case handling (audit #23, #24).
- `certificate-lifecycle-policy`: per-certificate validity, intermediate expiry relative to the leaf, configurable expiry thresholds, and the key-strength and signature-algorithm policy (audit #13, #14, #40, #41, #43).
- `certificate-revocation`: OCSP/CRL revocation states and their sources (audit #30).
- `tls-service-discovery`: which service terminates TLS, the native configuration test result, reload/restart evidence, and renewal tooling (audit #31, #36, #37, #45).
- `server-certificate-deployment`: configured certificate/key/chain inventory across services and vhosts, file permissions and ownership, configured-vs-active comparison, encrypted-key startup compatibility, and unexpected certificates (audit #27, #32, #33, #34, #35, #38, #39, #44).
- `certificate-evidence-model`: the `findings/1.7` additive contract for structured certificate facts and new check ids (supports all of the above).

### Modified Capabilities
- `diagnosis-correlation`: the verdict rule "no cause gives PASS" is replaced. Unexplained FAIL findings count, inconclusive verification never becomes a certificate cause, and pairing failures need conclusive key evidence (D2, D5, D1; audit #5, #7, #22).
- `tls-negotiation-diagnostics`: validation handshakes classify transport failures, share the verified address, and feed the presented chain to the verified chain analysis (audit #22, #26).
- `endpoint-comparison`: address-family coverage and family labels (audit #28).
- `nginx-cert-path-resolution`: multiple certificate/key pairs per server block are resolved and validated, not only the first (audit #32, #38).

Requirements #26 (live chain inspection) and #29 (SNI) are already verified. #26 gains one integration requirement in `tls-negotiation-diagnostics`. #29 is unchanged: it stays governed by `sni-behaviour-observation` and is protected by the existing tests, which this change must keep green.

## Impact

- **Code:**
  - `ssl_doctor/certs.py`: records and strict parsing; `assess_chain` stays as a compatibility wrapper.
  - New `ssl_doctor/chainval.py` (verification, path building, trust), `ssl_doctor/certpolicy.py` (policy, thresholds), `ssl_doctor/revocation.py`, `ssl_doctor/services.py` (non-nginx service, listener, renewal discovery).
  - `ssl_doctor/server.py`: key states, multi-pair, permissions, compare, configtest.
  - `ssl_doctor/nginx_discovery.py`: configtest status; multiple directive values.
  - `ssl_doctor/netchecks.py`: verify transport classification, family coverage, stapled OCSP.
  - `ssl_doctor/analyze.py`: verdict, unexplained failures, new rules.
  - `ssl_doctor/contract.py` + `schemas/findings-1.7.schema.json`; `ssl_doctor/cli.py` (exit code, options); `ssl_doctor/agent.py`; `ssl_doctor/report.py`.
  - `service/ssldoctor_service/monitor.py`: alert conditions read the new facts additively.
- **Dependencies:** none added. Cryptographic checks use the system `openssl` already used by the CLI. Where it is missing, those checks are NOT TESTED with a reason, never PASS.
- **Interfaces:**
  - Exit code: 1 iff overall FAIL, but FAIL now also covers unexplained FAIL findings.
  - New CLI options: `--expiry-warn-days`, `--revocation=staple|online|off` (default `staple`).
  - New `/server` subcommands: none. The existing `/server` subcommands and `/scan` gain findings.
- **Coordination:**
  - Supersedes the linkage rule "judged by issuer/subject name and by key identifiers" in the unarchived `fix-chain-diagnosis-saas-enterprise` delta `tls-certificate-inspection`. Recorded as decision U1 in design.md.
  - Builds on, and does not replace, the unarchived `fix-tls-handshake-timeout-attribution` requirements.
- **Out of scope:**
  - Modifying, reloading or restarting any service.
  - Prompting for or storing key passphrases (see design U3).
  - Fetching missing intermediates to "repair" chains.
  - IIS, Tomcat, Traefik and Caddy configuration parsing (listener-owner detection still names them).
