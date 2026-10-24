# Tasks

> Phase gate: groups 1–5 (Phase 1) must be complete, with `python3 -m unittest discover -s tests` green on Python 3.10, 3.12 and 3.13, before group 6 starts.

## 1. Consolidate the package and test harness

- [x] 1.1 Make `ssl-doctor/ssl_doctor/` (v0.2.0) the single package at the repo root, remove the v0.1.0 tree and the stray `__pycache__`, and verify `python3 ssldoctor.py /version` prints the version and `/help` lists `/server nginx`
- [x] 1.2 Add `pyproject.toml` (no runtime dependencies, `ssl-doctor` console entry point) and verify `pip install .` into a clean venv and running `ssl-doctor /version` succeed
- [x] 1.3 Add `tests/fixtures/pki.py`, which generates a throwaway root → intermediate → leaf, a CN-only leaf and a wrong-intermediate pair; verify a test asserts `openssl verify` succeeds for the valid chain
- [x] 1.4 Add `tests/fixtures/tls_server.py`, which starts `openssl s_server` on an ephemeral port in leaf-only, full-chain and wrong-intermediate modes, with automatic teardown; verify a smoke test connects to each mode, and the suite skips cleanly when `openssl` is absent
- [ ] 1.5 Add a CI matrix (Python 3.10, 3.12, 3.13 on Linux; 3.12 on Windows) running the suite, and verify the pipeline runs on a no-op change

## 2. TLS certificate inspection (spec: tls-certificate-inspection)

- [x] 2.1 Implement the layered chain reader in `netchecks.check_tls_basic` (public API → `_sslobj` → `openssl s_client -showcerts` → NOT TESTED) and record the reader used; verify tests show full-chain = 2 certs and leaf-only = 1 on 3.12 and 3.13
- [x] 2.2 Replace the leaf-only fallback with a NOT TESTED chain finding when no reader succeeds; verify a test with all readers disabled yields NOT TESTED and no "only the leaf" evidence
- [x] 2.3 Implement completeness and linkage judgement (issuer DN, plus AKI/SKI when available) for the presented chain; verify the wrong-intermediate fixture yields WARNING naming position 1
- [x] 2.4 Add root-only validation (D2) as a separate `tls.verify.rootonly` finding; verify that leaf-only plus a trust bundle containing the intermediate gives full-store PASS and root-only FAIL
- [x] 2.5 Make hostname coverage SAN-only in `certs.CertInfo.matches_hostname`, and set `hostname_checks_common_name = False` on validation contexts; verify the CN-only fixture is FAIL and the SAN fixture PASS
- [x] 2.6 Document the new and changed checks in the README check table, and verify every new check id appears there

## 3. Windows client checks (spec: windows-client-checks)

- [x] 3.1 Fix `local.check_issuer_in_windows_root` to unpack `(der, encoding, trust)`; verify a test with an injected 3-tuple `enum_certificates` returns PASS or FAIL, not NOT TESTED
- [x] 3.2 Replace `cli.cmd_local`'s `chain[-1].issuer` with the path-built anchor from 2.3, and return NOT TESTED when the chain is incomplete or unread; verify that leaf-only gives `local.rootca` NOT TESTED and full-chain looks up the root DN
- [ ] 3.3 Run `certutil -verify` against the presented leaf (written to a temp file) during `/scan` on Windows; verify on the Windows CI job that a `local.certutil` finding is recorded with no certificate argument
- [ ] 3.4 Document the Windows behavior changes in the README, and verify the documented `/scan` example output matches a Windows CI run

## 4. Nginx configuration analysis (spec: nginx-config-analysis)

- [x] 4.1 Rework `server._match_nginx_server` to filter by target port, apply nginx precedence with first-match-wins, and warn on duplicate names; verify parser tests for duplicates, cross-port `default_server` and wildcard order
- [x] 4.2 Resolve `ssl_certificate`/`ssl_certificate_key` inherited from `http{}`; verify a fixture config with only http-level certs reports the inherited path
- [x] 4.3 Replace the `grep -c BEGIN CERTIFICATE` chain-file check with linkage verification of the file contents, reusing 2.3; verify that leaf-only, wrong-intermediate and correct files produce WARNING, WARNING and PASS
- [x] 4.4 Pass the target port from `/scan` and `/server nginx` into matching, and document it; verify `/server nginx shop.test` on a fixture config selects the 443 block

## 5. Diagnosis correlation (spec: diagnosis-correlation)

- [x] 5.1 Add the server-chain rule block (D3), consuming `tls.chain`, `tls.verify.rootonly`, `nginx.chainfile`, `nginx.domain`, `nginx.certref` and `nginx.protocols`, ranked ahead of client rules; verify the reproduced customer scenario (leaf-only plus cached intermediate) gives overall ≠ PASS with a top server-origin cause
- [x] 5.2 Gate the `local.rootca` client cause on a captured, complete chain; verify that full-chain with the root present gives no client cause, and leaf-only gives no client cause
- [x] 5.3 Apply the certainty mapping (confirmed only with direct evidence); verify a test that a local-validation-only inference is "probable"
- [x] 5.4 Add an end-to-end regression test that runs `/scan --client-only` against all three fixture servers and asserts the expected verdicts from the reproduction table; verify it fails on the v0.2.0 baseline and passes now
- [x] 5.5 Write the v0.3.0 release notes listing the intended verdict changes, and verify they cite each changed check id

## 6. Findings contract (spec: findings-contract)

- [x] 6.1 Publish JSON Schema `findings/1.0`, with `schema_version` and a documented check-id registry, and emit it from `report.write_json`; verify exported reports validate against the schema in a test
- [x] 6.2 Implement major-version rejection in a shared loader; verify a 2.x document is rejected with both versions named
- [x] 6.3 Add a serialization-time redaction guard and test; verify that a password-auth server scan's export does not contain the test password

## 7. Scan agents (spec: scan-agents)

- [x] 7.1 Add `agent` mode to the package (enroll, long-poll, run allowlisted checks, upload), with no new runtime dependencies; verify an agent against a local control-plane stub completes a client-role job
- [x] 7.2 Implement one-time enrollment tokens and per-agent mTLS credentials in the control plane; verify that token reuse is refused and successful enrollment registers the agent to its organization
- [x] 7.3 Enforce agent roles and the read-only server allowlist; verify a server job sent to a client agent is declined, and an unreadable nginx config yields NOT TESTED with the reason
- [x] 7.4 Implement agent revocation; verify a revoked agent's upload is refused and nothing is stored
- [ ] 7.5 Document agent install and enrollment for Linux (systemd) and Windows (service); verify by following the doc on clean VMs

## 8. Tenant workspaces (spec: tenant-workspaces)

- [x] 8.1 Scaffold the control plane (FastAPI, PostgreSQL, migrations), with `org_id` on all tables and RLS policies; verify migrations apply on an empty database
- [x] 8.2 Implement the target, scan-job (SKIP LOCKED queue) and immutable result-history APIs; verify that two scans of one target are both retrievable and comparable
- [x] 8.3 Add automated cross-tenant tests for every endpoint; verify that org A requesting org B's objects gets not-found for each
- [x] 8.4 Build the dashboard views (targets, scan history, diagnosis, report export); verify exported JSON validates against `findings/1.0`

## 9. Certificate monitoring (spec: certificate-monitoring)

- [x] 9.1 Implement the scheduler, with per-target interval and plan minimum; verify with a time-controlled test that a 24 h target is scanned once per simulated day
- [x] 9.2 Implement result diffing for expiry, leaf change, chain regression and endpoint inconsistency; verify each condition with fixture result pairs
- [x] 9.3 Implement alert dedup state, plus email and signed-webhook channels; verify three identical regressions send exactly one alert

## 10. Identity and access (spec: identity-access)

- [ ] 10.1 Implement OIDC and SAML SSO, with per-organization enforcement; verify that password sign-in under enforced SSO is refused
- [ ] 10.2 Implement roles and a central permission check; verify that a viewer starting a scan and an engineer revoking an agent are both forbidden
- [ ] 10.3 Implement SCIM deprovisioning and token revocation on removal; verify a removed member's API token is refused

## 11. Audit logging (spec: audit-logging)

- [ ] 11.1 Record audit entries for all listed actions, through one helper; verify that agent revocation produces the expected entry
- [ ] 11.2 Implement the per-organization hash chain, an insert-only DB role and an integrity-verification command; verify that altering a stored entry is detected at that entry
- [ ] 11.3 Implement JSONL audit export by date range for owners and admins; verify the export contains only that organization's entries for the range

## 12. Self-hosted deployment (spec: self-hosted-deployment)

- [ ] 12.1 Add `ssldoctor-server` with embedded PostgreSQL (`init`, `run`, `upgrade`, `backup`, `verify-audit`); verify `init` + `run` on an empty data dir answers `/healthz`
- [ ] 12.2 Add PyInstaller build specs for `ssl-doctor`, `ssl-doctor-agent` and `ssldoctor-server`, and build the Linux binaries; verify each runs from the bundle with no Python on PATH (`env -i`), and that the server binary passes its health check
- [ ] 12.3 Add a Windows CI job building the three `.exe` files plus Windows service registration (agent, server); verify on the Windows runner that the service installs, starts and answers health checks
- [ ] 12.4 Build the signed offline bundle (`SHA256SUMS` + Ed25519 signature + CycloneDX SBOM + public key + offline verification instructions); verify that a modified bundle fails `openssl pkeyutl -verify`
- [ ] 12.5 Run an air-gapped install test (network namespace with no egress) from the bundle and scan an internal fixture target; verify installation and the scan succeed
- [ ] 12.6 Add an upgrade test from the previous minor version's data dir; verify that results and audit integrity survive the upgrade

## 13. Integration

- [ ] 13.1 End-to-end: client agent plus server agent scan a leaf-only nginx in a lab tenant; verify the dashboard diagnosis names the server chain as the top cause, and a chain-regression alert fires after a full-chain → leaf-only change

## Workflow follow-up

- Consider splitting Phases 2–3 into separate OpenSpec changes after Phase 1 is archived, if review prefers smaller units.
- Archive the change after review requirements are met, and verify the archived specs under `openspec/specs/`.
