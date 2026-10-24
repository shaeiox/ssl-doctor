# Proposal

## Why

A real run (captured in `ssl-doctor-report-20261024-124452.html`) produced a self-contradicting diagnosis:

| Report line | Check | Result |
|---|---|---|
| 49 | `tls.handshake` | **FAIL** — "handshake/connect timed out after 8s" |
| 50 | `tls.protocols` | **WARNING** — TLS 1.0, 1.1, 1.2 and 1.3: "accepted" |
| 36 | diagnosis #10 | **[probable · server]** "TLS handshake fails for modern clients but some protocol versions work - protocol/cipher mismatch" |

The same run also recorded `net.tcp` PASS to `192.178.25.238:443` and a client timezone of `+0330`. A server that completes four version-pinned handshakes moments later is not rejecting the client's protocols; the generic handshake **stalled**. The tool blamed the server anyway and recommended a server-side protocol/cipher change that would not fix anything.

### Trace of the defect

1. **Failure modes are lost at the call site.** `ssl_doctor/netchecks.py:207-216` (`_handshake`) performs `socket.create_connection(...)` and `ctx.wrap_socket(...)` in one function, so a TCP-connect timeout and a stalled TLS negotiation cannot be told apart by callers. `check_tls_basic` (`netchecks.py:279-295`) catches `socket.timeout` (`:282-288`) and `(ssl.SSLError, OSError)` (`:289-295`). Both paths emit the identical identity tuple — `check="tls.handshake"`, `status=FAIL`, `scope="remote-net"` — and differ only in free-text evidence. `Finding` (`ssl_doctor/findings.py:31-49`) has no structured failure field.
2. **The correlation rule only looks at the status.** `ssl_doctor/analyze.py:99-112` maps on `hs.status == F.FAIL` and then tests whether the matrix evidence text contains the substring `"accepted"`. It never inspects *how* the handshake failed. Reproduced with the real `diagnose()`:

   ```text
   timeout evidence  → #10 probable server | …protocol/cipher mismatch
   SSL alert evidence→ #10 probable server | …protocol/cipher mismatch
   identical summaries: True
   ```

   A deterministic `sslv3 alert handshake failure` and an 8-second stall are therefore indistinguishable to the diagnosis, even though they have opposite owners (server configuration vs. network path).
3. **The probe weakened its own evidence.** The matrix (`netchecks.py:441-493`) reports a timeout as `"network error"` and files it under `refused` (`:469-471`), so a stall inside the matrix is silently downgraded to a protocol refusal. For TLS 1.0–1.2 it also sets `ciphers="ALL:@SECLEVEL=0"` (`:457-460`) without saying so in the evidence, and "accepted" therefore does not mean "accepted by a modern client". TLS 1.0/1.1 "accepted" for `google.com` is implausible for a public endpoint and points to path interception rather than server configuration.
4. **The probes may not test the same endpoint.** `check_tcp` connects to the address it resolved (`netchecks.py:148-154`, called with `ip=ips[0]` at `:753`), but `check_tls_basic` (`:281`) and `check_protocol_matrix` (`:462`) call `_handshake` **without** `connect_ip`, so they re-resolve and may reach a different A/AAAA record than the one TCP verified. Only `check_multi_ip` pins the address (`:556-557`). The handshake finding does not name the address it used, so this run cannot be reconstructed — which is itself part of the defect.
5. **No confirmation before a hard FAIL.** A single stalled connection raises `FAIL` immediately, even though the four version probes that follow each opened fresh connections successfully.

### Verdict

The **root cause is the diagnosis logic** (`analyze.py:99-112`): it conflates a timeout with a protocol/cipher rejection. Contributing defects in the probe make the wrong conclusion reachable and unfalsifiable — untyped failures, no retry, matrix timeouts classified as refusals, unpinned probe addresses, and evidence that omits the relaxed cipher policy.

The *reason* for the observed stall (intermittent path behaviour vs. a TLS-inspecting middle-box) is deliberately **not** asserted by this change; the fix is to attribute it correctly and to collect the evidence needed to settle it on the next run.

## What Changes

- **Type the failure.** `tls.handshake` failures carry a machine-readable `failure_kind`: `connect-timeout`, `negotiation-timeout`, `tls-alert`, or `network-error`. Findings contract moves 1.1 → 1.2 (additive, optional field).
- **Name the phase and the address.** Connect timeouts and negotiation stalls produce distinct evidence, and every probe states the address it connected to.
- **Pin the verified address.** The handshake and the protocol matrix connect to the address `net.tcp` proved reachable; other addresses stay the job of `tls.multiip`.
- **Confirm a stall.** A timeout-class failure is retried once on a fresh connection. A recovered stall becomes a `WARNING` ("completed on attempt 2"), not a `FAIL`; a TLS alert is never retried.
- **Classify matrix rows.** `accepted` / `refused` / `timed out` / `network error`, with the relaxed-cipher policy disclosed, and `failure_kind` on the matrix when nothing answered.
- **Attribute by failure mode.** `diagnose()` gains distinct branches: a stall with working version probes becomes a **probable network** cause (repeat measurement, inspect TLS-inspection/idle-timeout devices); a TLS alert with working version probes keeps the server protocol/cipher cause. A protocol/cipher mismatch can never be raised from timeout-class evidence.
- **Prove it with tests.** A regression test reproduces the exact report pair (timeout + all versions accepted) and asserts the cause is not server-origin; a stalling fixture exercises classification and retry.

## Capabilities

### New Capabilities
- `tls-negotiation-diagnostics`: how the handshake and per-version probes classify, confirm and report their failures, and how their findings are kept mutually consistent.

### Modified Capabilities
- `diagnosis-correlation`: attribution rules become failure-mode aware. The capability's baseline requirements live in the pending change `fix-chain-diagnosis-saas-enterprise` (nothing is archived under `openspec/specs/` yet), so this change adds requirements that build on that delta rather than rewriting it.

## Impact

- **Code:** `ssl_doctor/netchecks.py` (handshake phases, retry, address pinning, matrix classification), `ssl_doctor/analyze.py` (attribution branches), `ssl_doctor/findings.py` (optional field), `ssl_doctor/contract.py` + `schemas/findings-1.2.schema.json` (contract bump), `ssl_doctor/report.py` (render the field).
- **Tests:** new `tests/test_handshake_failure_attribution.py`; new stall/flaky fixtures in `tests/fixtures/`; existing `test_scan_e2e.py` and `test_diagnosis.py` stay green.
- **Docs:** `docs/execution-flow.md` (handshake failure flow), `docs/findings-contract.md` (new field), `README.md` (check table), `CHANGELOG.md`.
- **Behavior change:** runs where a stall previously produced `FAIL` may now produce `WARNING`; runs where a stall was blamed on the server now name the network path. Client-visible diagnosis text changes; CLI commands, flags and check identifiers do not.
- **Dependencies:** none. Standard library only, no new check ids, no new major contract version.

## Out of Scope

- Explaining *why* the observed stall happened on that specific path (needs repeat runs; the new evidence is what makes it decidable).
- Enumerating full cipher support per protocol version, or adding TLS 1.3 cipher pinning.
- Changing default timeouts, the `/timeout` command, or SNI handling (SNI is already applied on every probe, `netchecks.py:462`).
- Automatic remediation, retries for every check, or connection re-use.
