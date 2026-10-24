# Design

## Context

See `proposal.md` (Why) for the reproduced defects. Constraints that shape this design:

- **Two package trees today.** The CLI is a stdlib-only Python package (3.10+), with the `openssl` and `ssh` binaries used when present. It exists twice: `ssl_doctor/` (v0.1.0) and `ssl-doctor/ssl_doctor/` (v0.2.0, with nginx support). v0.2.0 is the superset.
- **No tests.** There is no test suite, no packaging metadata and no git history.
- **Python 3.12 chain gap.** On 3.12 the public `SSLSocket.get_unverified_chain` does not exist; it was added in 3.13. The private `SSLSocket._sslobj.get_unverified_chain()` does exist on 3.10–3.12 (checked on the 3.12.3 runtime).
- **Windows store shape.** Windows `ssl.enum_certificates` returns `(der, encoding, trust)` 3-tuples (stdlib `ssl.py:518`). `local.py:124` unpacks 2, which crashes.
- **Masking intermediate cache.** On Windows, `load_default_certs` also loads the "CA" intermediate store (stdlib `ssl.py:425`). That cache hides servers that send no intermediates.
- **Existing seams to reuse.** Findings are already a flat model (`findings.Finding`), and `report.write_json` already serializes them. This is the natural seam for the shared contract.

## Goals / Non-Goals

**Goals:**
- One diagnostic core. The CLI, both agent roles, and the service all run the same check and correlation code, so verdicts can't diverge.
- Phase 1 ships as a CLI release on its own merits, before any platform work.
- The CLI and agent stay stdlib-only, so they can be installed on locked-down customer machines and nginx hosts.

**Non-Goals:**
- Web servers other than nginx (Apache/IIS stay at today's best-effort level).
- Active remediation. Nothing edits configuration or restarts services, in any mode.
- Billing and payments implementation; plan limits are configuration only.
- A non-Python agent.

## Decisions

### D1 — Chain capture: layered readers, honest failure
Order of attempts:
1. Public `get_unverified_chain()` (3.13+).
2. `ssock._sslobj.get_unverified_chain()` (3.10–3.12), guarded by a capability check.
3. `openssl s_client -showcerts -servername <sni>` parsed with the existing `extract_pem_blocks`.
4. Otherwise NOT TESTED.

The facts dict records which reader succeeded, as evidence.
*Alternatives:* `cryptography`/pyOpenSSL breaks the stdlib-only constraint; openssl-only fails on Windows hosts without OpenSSL.

### D2 — Chain completeness and anchor via path building
Each link is judged by issuer DN = next subject DN, and by AKI = next SKI when key identifiers are available (from `openssl x509 -ext` enrichment).
- The "expected anchor" is the issuer of the topmost presented certificate, and only when that certificate is a CA whose issuer is absent from the presented set.
- A chain is **complete** when its top certificate is self-signed, or is issued by a known root.
- A chain is **incomplete** when its top certificate is a leaf, or a CA whose issuer is not a root.

The root-only validation builds a separate `SSLContext` holding ROOT anchors only:
- Windows: `enum_certificates("ROOT")`, with no "CA" store.
- Linux and macOS: the system CA bundle from `ssl.get_default_verify_paths()`. By distribution convention it holds roots only; the evidence names the bundle used.

*Alternative:* one validation that disables the cache. Rejected: the full-store result is still useful, because it shows what real cached clients see.

### D3 — Correlation rule ordering
`analyze.diagnose` gets an explicit "server chain" rule block, evaluated before the client trust rules. Its inputs are `tls.chain`, `nginx.chainfile`, `nginx.domain`, `nginx.certref` and `nginx.protocols`.
- The `local.rootca` rule is gated: it may raise a client cause only when the chain is captured and complete.
- Certainty mapping: "confirmed" requires direct evidence (for example, the served chain is measured incomplete). Inferences from the local environment are capped at "probable".

The rules stay pure functions over findings, so the service can re-run them on stored results.

### D4 — One package, regression suite from the reproduction
- `ssl-doctor/ssl_doctor/` (v0.2.0) becomes canonical at the repo root, and the v0.1.0 tree is removed.
- Add `pyproject.toml`, with no runtime dependencies.
- Tests use stdlib `unittest`. TLS fixtures generate a throwaway root → intermediate → leaf PKI and spawn `openssl s_server` on ephemeral ports, in leaf-only and full-chain modes, reusing the reproduction scenarios. Windows paths are tested by injecting a fake `enum_certificates` that returns real 3-tuples.

*Alternative:* pytest. Deferred; it adds a dev dependency for little gain at this size.

### D5 — Findings contract
- JSON Schema `findings/1.0`, with a `schema_version` field. Check identifiers become a documented, stable registry.
- Minor versions only add fields. Major versions may rename or remove.
- The redaction rule (no secrets) is enforced at serialization, with a test that scans output for known secret values.

### D6 — Platform shape
- **Control plane:** Python service reusing the diagnostic core: FastAPI + PostgreSQL.
- **Tenant isolation:** `org_id` on every row, plus PostgreSQL row-level security set per request. RLS is defense in depth behind application checks.
- **Job queue:** a Postgres table drained with `SELECT … FOR UPDATE SKIP LOCKED`, which avoids extra infrastructure in self-hosted installs.

*Alternatives:* schema-per-tenant (operationally heavy); a separate broker such as Redis or RabbitMQ (one more component to ship air-gapped).

### D7 — Agents: same core, outbound long-poll, per-agent credential
- The agent is the stdlib package run in `agent` mode.
- **Enrollment:** a one-time token (hashed at rest, 24 h expiry) is exchanged atomically (`app.enroll_agent`) for a per-agent random credential, stored only as a SHA-256 hash. The agent keeps it in a `0600` state file. Revocation is checked on every request.
- **Amended during implementation:** the original plan was a per-agent client certificate from an installation CA (mTLS). Issuing certificates needs `cryptography`, or CA logic driven through the `openssl` CLI, on both sides, and the spec only requires "its own credential". mTLS remains available as a deployment-layer control (TLS-terminating proxy requiring client certificates) and can be added as an extra factor later without changing the protocol.
- **Transport:** HTTPS long-poll for jobs, and POST for results in the findings contract.
- **Server-role agents** replace SSH in SaaS mode, so customers never hand us SSH passwords. SSH mode remains for CLI users.

*Alternatives:* inbound SSH from the cloud (credential custody, firewall changes); a WebSocket push channel (possible later; long-poll is simpler through proxies).

### D8 — Identity and RBAC
- **SSO:** OIDC (authorization code + PKCE) and SAML 2.0 via maintained libraries (Authlib, python3-saml). SCIM 2.0 handles deprovisioning.
- **RBAC:** fixed roles (owner, admin, engineer, viewer), with a permission table checked in one authorization layer.
- **API tokens:** scoped to a member, revoked when the member is removed.

*Alternative:* custom roles, deferred until there is customer demand.

### D9 — Tamper-evident audit
- Per-organization hash chain: `hash = SHA-256(prev_hash || canonical_json(entry))`.
- An insert-only database role stores entries, and an integrity verification command walks the chain.
- Export format is JSON Lines.

*Alternative:* external WORM storage. Offered later as an export target, not a requirement, so air-gapped installs stay simple.

### D10 — Monitoring
- A scheduler in the control plane enqueues scans at each target's interval.
- Alert conditions are computed by diffing consecutive results: leaf fingerprint, chain completeness, multi-endpoint consistency, days to expiry.
- Deduplication keeps a per (target, condition) open/closed state.
- Channels: email and signed webhook first.

### D11 — Self-hosted and air-gapped: native executables (no containers)
*Amended at the user's request: the platform ships as executables, not container images.*
- **Three PyInstaller executables per OS** (Windows `.exe`, Linux binary):
  - `ssl-doctor`: the CLI;
  - `ssl-doctor-agent`: the agent;
  - `ssldoctor-server`: control plane API + dashboard + scheduler/dispatcher in one process, supervising an **embedded PostgreSQL** (bundled server binaries, own data directory, loopback-only).

  Server subcommands: `init` (data dir, roles, migrations, first org and token), `run`, `upgrade` (backup + migrations), `backup`, `verify-audit`.
- **Services:** on Windows the agent and server register as Windows services (via the bundled `pywin32` service host, in the executable build only; the Python package stays stdlib-only). On Linux, systemd units ship in the bundle.
- **Builds:** PyInstaller can't cross-compile. Linux binaries build on Linux, and Windows `.exe` files on a Windows CI runner, from the same spec files.
- **Offline bundle:** executables + `SHA256SUMS` + `SHA256SUMS.sig` (an Ed25519 signature) + CycloneDX SBOM (`cyclonedx-py`) + `RELEASE-KEY.pub`. Customers verify with `openssl pkeyutl -verify`, already present on their hosts. Nothing to download, no transparency log. *Alternative:* cosign, rejected because it's an extra binary in air-gapped networks.
- Telemetry doesn't exist in any build.
- Database migrations are forward-only; `upgrade` takes a `pg_dump` backup first.

## Risks / Trade-offs

- **[Private API on 3.10–3.12]** `_sslobj` could change in a patch release → capability check plus the openssl fallback, and a CI matrix on 3.10–3.13.
- **[Behavior change in verdicts]** Engineers will see new WARNING/FAIL results on servers previously reported PASS → document in release notes, as intended corrections.
- **[AKI/SKI needs the openssl binary]** Without it, linkage falls back to DN-only, which can't tell apart cross-signed intermediates with the same name → the evidence states which method was used.
- **[Scope breadth]** Phases 2–3 are large → phase gates. Phase 1 must ship and pass the regression suite before platform work starts. Each phase can be archived separately if the change is later split.
- **[Agent as an attack surface]** A compromised control plane could task agents → agents run read-only, allowlisted check types only. No arbitrary command execution exists in the job protocol.
- **[RLS misconfiguration]** → automated cross-tenant tests in CI for every endpoint.

## Migration Plan

1. **Phase 1:**
   - Merge the trees and tag the v0.2.0 baseline.
   - Land the fixes behind the regression suite and release CLI v0.3.0.
   - Rollback: reinstall v0.2.0. There is no persisted state.
2. **Phase 2:**
   - Deploy the control plane with an empty database.
   - Agents opt in, and the CLI keeps working standalone.
   - Rollback: disable agent enrollment. Agents stop polling, and the CLI is unaffected.
3. **Phase 3:**
   - SSO and RBAC go live behind per-organization flags. Existing members default to "owner" for the creator and "engineer" for everyone else.
   - The audit chain starts at enablement time; there is no back-filled history.

## Open Questions

- Minimum monitoring interval per plan tier (a configuration value; doesn't change the specs).
- First hosting region(s) for the SaaS deployment.
- Additional alert channels beyond email and webhook (Slack, Teams, PagerDuty) — the channel design is pluggable.
