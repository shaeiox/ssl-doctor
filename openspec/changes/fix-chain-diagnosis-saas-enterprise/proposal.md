# Proposal

## Why

SSL Doctor gets wrong the most common failure in its core scenario: a customer certificate installed on nginx without its intermediate. A reproduction against real TLS servers on the project runtime (Python 3.12.3) showed:

- The tool cannot read the chain the server presents. A correct full-chain install and a broken leaf-only install produce identical findings.
- When the engineer's machine has the intermediate cached, a broken leaf-only server is diagnosed as overall **PASS**.
- The Windows root-store check crashes on every Windows host (3-tuple unpack) and silently reports NOT TESTED.
- Once that crash is removed, the root-store check blames the client (as "confirmed") for server-side chain faults, and even for a correctly installed full-chain server.
- No `nginx.*` server finding ever reaches the diagnosis.

A tool that blames the customer's PC for our nginx misconfiguration can't be sold as a SaaS or enterprise product. Diagnostic correctness has to come first. The product can then grow from a single-engineer CLI into a multi-tenant service with remote agents, monitoring, and enterprise controls.

## What Changes

**Phase 1 — Diagnostic correctness (prerequisite for everything else)**
- Capture the certificate chain the server really presents, on every supported Python version (3.10+). Report NOT TESTED when it can't be read, instead of making up a one-element chain.
- Detect an incomplete or wrongly linked chain from what the server sends, independent of the engineer's own trust store.
- Find the client's trust anchor by building the issuer path. Stop assuming the last certificate sent is the one directly below the root.
- Fix the Windows root-store read so it works on real Windows hosts.
- Feed every nginx server-side finding into the diagnosis. A server-side chain or vhost fault must outrank client-side causes.
- Flag CN-only certificates (no SAN) that modern clients reject.
- Run the Windows chain-engine check as part of the guided scan.
- Correct nginx vhost selection: the first duplicate wins, the listen port must match, and `ssl_certificate` is inherited from the `http` level.
- Merge the duplicate `ssl_doctor/` (v0.1.0) and `ssl-doctor/` (v0.2.0) trees into one package, with a regression test suite.

**Phase 2 — SaaS platform**
- A versioned, machine-readable findings/diagnosis format that the CLI, agents and service all share.
- A hosted multi-tenant service: organizations, targets, scan jobs, results history, and a web dashboard.
- Scan agents installed in the customer network (client side) and on the nginx host (server side). They connect outbound only and report results. Server-side checks then need no SSH credentials handed to us.
- Continuous monitoring: scheduled re-scans, expiry and chain-drift detection, and alerts.

**Phase 3 — Enterprise**
- SSO (OIDC and SAML) and role-based access control.
- A tamper-evident audit log of every scan, configuration change and access to results.
- Self-hosted and air-gapped deployment of the full platform as native Windows and Linux executables (no Docker, no Python install, embedded database).

The existing CLI stays fully usable offline. No breaking change to CLI commands is planned. Two behavior changes are intended: verdicts in the reproduced chain scenarios become correct, and `local.rootca` stops reporting FAIL for intermediates.

## Capabilities

### New Capabilities
- `tls-certificate-inspection`: capturing the certificate chain the server presents, judging its completeness and linkage, and checking hostname coverage the way modern clients do.
- `diagnosis-correlation`: turning findings into ranked root causes with correct client vs. server attribution.
- `windows-client-checks`: reading the Windows trust stores and chain engine on the client machine.
- `nginx-config-analysis`: selecting the nginx server block that answers for a domain, and checking its certificate configuration.
- `findings-contract`: the versioned, machine-readable results format shared by the CLI, agents and service.
- `scan-agents`: enrolling remote agents that run client-side and server-side checks and report results.
- `tenant-workspaces`: organizations, targets, scan jobs and results history in the hosted service, with strict tenant isolation.
- `certificate-monitoring`: scheduled re-scans, expiry and chain-drift detection, and alerting.
- `identity-access`: SSO login and role-based permissions.
- `audit-logging`: a tamper-evident record of security-relevant actions.
- `self-hosted-deployment`: running the full platform on customer infrastructure, including air-gapped.

### Modified Capabilities
- None. There are no existing specs in `openspec/specs/`.

## Impact

- **Code (Phase 1):** `netchecks.py` (chain capture and checks), `analyze.py` (correlation rules), `local.py` (Windows root-store read, anchor logic), `cli.py` (scan flow, anchor selection), `server.py` (vhost matching, chain-file linkage), `certs.py` (SAN-only hostname policy). The two package trees are merged into one.
- **New components (Phases 2–3):** a hosted API/control plane, a database, a web dashboard, an agent package, an identity provider integration, and deployment artefacts (native Windows/Linux executables with an embedded database, and a signed air-gap bundle; no containers).
- **Dependencies:** the CLI and agent stay standard-library-only. The hosted service adds server-side dependencies (web framework, database, identity libraries).
- **Security:** SSH passwords are never sent to the hosted service. Agents use outbound-only connections with per-agent credentials. Tenant data is isolated per organization.
