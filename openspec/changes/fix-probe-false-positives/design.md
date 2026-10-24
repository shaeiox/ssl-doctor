# Design

## Context

See `proposal.md` (Why) for the traces and reproductions. Constraints that shape this design:

- **Findings are flat and serialized.** `Finding` (`ssl_doctor/findings.py:31-49`) already carries `failure_kind`, `detail` and `target`. Anything the diagnosis needs must live on the finding or in `facts`, because `analyze.diagnose()` is a pure function over findings and is re-run by the service on stored documents.
- **Contract is at 1.2.** `contract.SCHEMA_VERSION == "1.2"` with `failure_kind` and the handshake facts; 1.0–1.1 stay published. New keys must be additive and optional, with published schemas untouched.
- **The primary handshake is the strongest evidence in the scan.** It is the only TCP+TLS exchange that the rest of the suite depends on (`facts["protocol"]`, `cert`, `chain`), and every other probe re-connects. A later probe cannot invalidate it; at most it can be inconclusive.
- **Address-level probing already exists.** `check_tcp(ip=…)` and `_handshake(connect_ip=…)` pin an address; `check_multi_ip` is the only check that deliberately iterates addresses.
- **No new dependencies, no CLI surface change.** `/timeout` stays the single knob for probe deadlines.

## Goals / Non-Goals

**Goals**
- A transport failure can never be read as a certificate or protocol fact.
- Every probe states its outcome state, and an inconclusive outcome is visible in findings, diagnosis notes and reports.
- Confidence labels are derived from a documented evidence rule, with limitations attached.
- Genuine defects (mixed certificates on two reachable nodes, hostname mismatch, deprecated TLS acceptance) stay detectable and keep their current names and check ids.

**Non-Goals**
- Address-family policy, DNS preference, or probing more endpoints.
- Cipher-level introspection or a full protocol/cipher matrix.
- Replacing the verdict rules or re-ranking unrelated causes.

## Decisions

### D1 — Endpoint outcomes become states, not strings

`check_multi_ip` (`netchecks.py:712-745`) stops building a fingerprint-string dictionary. Each endpoint yields a small record:

| State | Meaning | Comparable? |
|---|---|---|
| `negotiated` | handshake completed; leaf certificate and chain captured | **yes** |
| `tls-rejected` | peer answered with a TLS alert | no |
| `tcp-unreachable` | connect failed: `ENETUNREACH`, `EHOSTUNREACH`, refused, DNS/routing error | no |
| `timed-out` | connect or negotiation exceeded the deadline | no |
| `probe-unavailable` | no certificate could be read from a completed handshake | no |

Evidence renders one row per endpoint with its state, and unreachable endpoints keep their OS error text (that is the raw evidence; it is simply not a certificate fact).

### D2 — Only comparable endpoints are compared

For endpoints in state `negotiated`, compare:

- leaf SHA-256 (identity),
- hostname coverage of the requested SNI (`CertInfo.matches_hostname`),
- chain status (`complete` / `incomplete` / `broken`, reusing `certs.assess_chain` as `check_presented_chain` does).

Comparison result:

| Comparable endpoints | Difference found | Finding |
|---|---|---|
| ≥ 2 | yes | `WARNING` — "endpoints present different certificate results", naming the addresses, the differing attribute (identity / hostname coverage / chain) and each value |
| ≥ 2 | no | `PASS` — "N endpoints present the same certificate, hostname coverage and chain status" |
| exactly 1 | — | `NOT TESTED` — "endpoint comparison inconclusive: 1 of N endpoints yielded a certificate (the others: …)"; `failure_kind="probe-inconclusive"` |
| 0 | — | `NOT TESTED` — "no endpoint yielded a certificate"; `failure_kind="endpoint-unreachable"` when every failure was transport-level |

The addresses that did not yield a certificate are listed with their state in the evidence, but they never contribute to the difference decision. `facts["endpoints"]` records `[{"ip", "state", "detail", "sha256"?}]` for consumers and reports.

*Why a state enum rather than "compare only successes":* the state is what the diagnosis and the report need in order to say *why* the comparison is inconclusive; deriving it later from messages would repeat the original defect.

### D3 — Probe rows are reconciled with the primary handshake

`check_protocol_matrix` gains an optional `negotiated` argument (the protocol the primary handshake established, from `facts["protocol"]`). Its rows become explicit outcomes:

```
TLS 1.2: accepted (TLSv1.2)
TLS 1.3: accepted (TLSv1.3)
TLS 1.1: accepted under relaxed cipher policy (TLSv1.1)
TLS 1.0: refused (alert handshake failure)
TLS 1.3: inconclusive - probe timed out after 8s
```

Rules:

1. A version the primary handshake negotiated SHALL NOT be reported as refused or unsupported. If its probe stalls or errors, the row is `inconclusive` and cites the primary success: "inconclusive - probe timed out after 8s, although the primary handshake negotiated TLSv1.3".
2. An `inconclusive` row keeps the version out of the "refused"/"unsupported" accounting and out of the hardening verdict, but it does keep the finding from being a clean `PASS`: status becomes `WARNING` with `detail` naming the inconclusive versions, and `failure_kind="probe-inconclusive"`.
3. Retry: each inconclusive version is retried **once** on a fresh connection with the same parameters (mirrors `_HANDSHAKE_RETRIES` in `check_tls_basic`). A successful retry replaces the row with `accepted … (after 1 retry)` and the version counts as accepted; a repeated failure stays `inconclusive` with both attempts in the row.
4. Budget: the matrix bounds itself with `PROBE_BUDGET_FACTOR` (default 2) — total matrix wall time is capped at `timeout × PROBE_BUDGET_FACTOR × len(versions)`. When the budget is exhausted, remaining retries are skipped and the affected rows say so ("retry skipped: probe budget exhausted"). Four versions with one retry each therefore cost at most `8 × timeout`, and `/timeout` remains the single knob.
5. The same address (`connect_ip`), SNI and timeout are used by every probe, and the finding evidence states them once (`probed <ip>:<port>, SNI '<name>', timeout 8s`). This makes "same target, same path" auditable instead of assumed.

### D4 — Relaxed policy is a property of the probe, recorded per row

The version table becomes `(label, version, policy)` where policy is `default` or `relaxed` (`ALL:@SECLEVEL=0`, today's `:606-612`). Consequences:

- Row text always names the policy when it is relaxed.
- Two distinct facts are reported: **server protocol support** (a version answered) and **default-client interoperability** (the same version answers when the client offers default security settings). For TLS 1.2 both are probed (relaxed and default); for TLS 1.0/1.1 the default-policy probe usually fails on any modern client stack, so when the relaxed probe accepts and the default probe refuses, the row reads `accepted only under relaxed cipher policy - a default-configured modern client is refused` and the finding keeps a WARNING with that exact wording.
- The security conclusion (deprecated versions are enabled on the server) is retained, because the server did negotiate them; the limitation (it needed a lowered security level, so a stock client may still fail) is stated in `detail`, in the evidence, and in the cause's `limitations`.
- No `SECLEVEL` change is made to the primary handshake or to any other check.

### D5 — SNI difference is an observation with a fixed vocabulary

`check_sni_difference` (`:665-709`) returns one of:

| Observation | Status | Wording | Never says |
|---|---|---|---|
| same certificate | `PASS` | "the same certificate is served with and without SNI" | — |
| different certificate, no-SNI probe succeeded | `PASS` with an explicit observation row | "observation: without SNI the server serves a different certificate (default vhost/CDN behaviour is legitimate)" | "misconfiguration", "wrong certificate" |
| cannot probe without SNI (server requires SNI / resets) | `NOT TESTED` (was WARNING) | "without SNI the probe failed (<reason>); SNI dependence could not be determined" | "very old clients will fail here" as a defect |
| with-SNI handshake fails | `FAIL` | unchanged (the endpoint genuinely does not serve the requested name) | — |

The observation row is the correlation hook: `analyze` may use it only as corroboration for a cause that has independent evidence, and the finding carries `failure_kind=""` because nothing failed.

Title change `SNI dependence` → `Behaviour with and without SNI` keeps the check id `tls.sni`.

### D6 — Evidence-strength certainty and limitations

`analyze` gains one helper and one rule table instead of ad-hoc labels:

```text
confirmed  direct measurement of the fault, complete evidence
           (e.g. two reachable endpoints serve different leaves; the requested
           name is not covered by the certificate that was served)
probable   direct measurement with a material gap
           (e.g. one comparable endpoint only; a single sample; a fault
           inferred from this machine's trust store)
possible   observation or corroboration only; no measurement of the fault
           (e.g. SNI difference, inconclusive probe, policy warning)
```

Hard rules added:

- Transport failures (`tcp-unreachable`, `timed-out`) and `probe-inconclusive` outcomes never raise a `confirmed` or `probable` configuration cause; they raise at most a `possible` cause or a diagnosis note.
- A certificate-inconsistency cause requires ≥ 2 comparable endpoints **and** a measured difference; with one comparable endpoint the diagnosis says "inconclusive" in `notes`.
- An SNI observation alone never yields a cause; it is appended to an existing cause's evidence when that cause already exists on independent grounds.
- Relaxed-policy acceptance yields a `possible` security cause whose `limitations` state the policy.

`Cause` gains `limitations: List[str] = []` (contract 1.3, optional). Each rule that can over-claim fills it: one comparable endpoint, single sample, relaxed probe, no-SNI probe unavailable, probe budget exhausted.

`Diagnosis.overall` is deliberately **not** changed: `confirmed` ⇒ FAIL, any cause ⇒ WARNING, else PASS. A `possible`-only scan therefore still returns WARNING, and tests pin that so no observation silently becomes a PASS either.

### D7 — Findings contract 1.3 (additive)

- `Cause.limitations` (array of strings, optional).
- `failure_kind` registry grows with `probe-inconclusive` and `endpoint-unreachable`.
- `facts.endpoints`: array of `{ip, state, detail?}` with `state` in the D1 enum.
- `facts.probe_policy`: `{"relaxed_versions": [...], "negotiated": "TLSv1.3"}` (optional).
- `SCHEMA_VERSION` becomes `"1.3"`, `schemas/findings-1.3.schema.json` published; 1.0–1.2 untouched and still valid, and documents without the new keys keep validating (all new properties optional).

*Alternatives rejected:* new check ids (`tls.multiip.state`, `tls.a`/`tls.aaaa`) would break the id registry and dashboards for a reporting-only change; putting the states in `detail` would put machine-readable facts back into prose, which is the defect this change removes.

### D8 — Tests are the acceptance criteria

| Acceptance | Test |
|---|---|
| unreachable IPv6 never implies inconsistency | `test_endpoint_comparison.py`: one reachable + two `ENETUNREACH` ⇒ NOT TESTED/inconclusive, no inconsistency text, no server cause |
| inconsistency only from comparable evidence | two reachable, different leaves ⇒ WARNING with both fingerprints; two reachable, same leaf but one `incomplete` chain ⇒ WARNING naming the chain attribute |
| single comparable endpoint is inconclusive | one reachable, others timed out ⇒ `probe-inconclusive`, notes say inconclusive |
| primary TLS 1.3 not contradicted by a probe timeout | `test_probe_consistency.py`: patched 1.3 probe stall ⇒ row `inconclusive`, cites primary TLSv1.3, no "unsupported"/"refused" wording, diagnosis adds no server protocol cause |
| both probes succeed | unchanged PASS path |
| explicit rejection | fixture that refuses a version ⇒ `refused`, security accounting unchanged |
| close without handshake | fixture that drops the connection ⇒ `inconclusive` (not refused) |
| subprocess/timeout error | simulated `_NegotiationTimeout` and `OSError` ⇒ inconclusive rows, budget respected |
| retries bounded | assert probe count and wall time ≤ budget for four stalling versions |
| SNI observation | `test_sni_observation.py`: correct cert + different default ⇒ no cause; wrong cert even with SNI ⇒ hostname cause; identical ⇒ PASS, no observation row; no-SNI probe fails ⇒ NOT TESTED; insufficient evidence ⇒ no cause |
| relaxed policy | relaxed accept + default refuse ⇒ explicit interop limitation; default accept ⇒ ordinary compatibility; rejection ⇒ unchanged |
| certainty and verdict | `test_diagnosis.py` additions: observation-only scan is WARNING, never FAIL; confirmed chain fault still FAIL; limitations present on the gapped causes |

## Risks / Trade-offs

- **[More scans change from WARNING to NOT TESTED]** endpoint comparison with a single reachable address no longer warns → a real mixed pool reachable on only one address is no longer flagged. Mitigation: the inconclusive finding names the missing endpoints and the new note tells the engineer to retest from a network with the same address family; `tls.multiip` keeps WARNING for two comparable endpoints.
- **[Extra probe traffic]** one retry per version plus a TLS 1.2 default-policy probe → up to 10 short connections instead of 4, bounded by the D3 budget. Read-only and unauthenticated, as today.
- **[Contract 1.3]** another minor version in one release cycle (1.1 → 1.2 → 1.3) → both are additive and the loader accepts any `1.x`; the changelog names both. Consumers that pin an exact minor must be told, as with 1.2.
- **[`NOT TESTED` on SNI when the server requires SNI]** previously a WARNING → engineers who valued the signal lose a warning. Mitigation: the row still says the server requires SNI and names the failing reason; an nginx/vhost finding can carry the actionable part when it exists.
- **[Certainty table is a policy, not a proof]** labels can still be argued → every label now carries `limitations`, and the rules are pinned by tests.

## Migration Plan

1. Contract 1.3 + `Cause.limitations` + new failure kinds, rendering in JSON/HTML; no behavior change yet.
2. `check_multi_ip` states and comparable-only comparison (D1/D2) with its tests.
3. Matrix reconciliation, retries and budget (D3) with `test_probe_consistency.py`.
4. Relaxed/default policy split (D4).
5. SNI observation semantics and the correlation change (D5).
6. Certainty helper + limitations (D6), then `analyze` rule updates for endpoints and SNI.
7. Docs, changelog, project brain; full suite.
8. Rollback: revert the change directory. Every new contract key is optional, so 1.3 documents still load on a 1.2-era build.

## Open Questions

- Should the default-policy TLS 1.2 probe run always, or only when the relaxed probe accepted? (Default: only when relaxed accepted — it is the only case where the distinction changes the verdict.)
- Should the endpoint comparison retry an unreachable address once before declaring it unreachable? (Default: no — reachability is already covered by `net.tcp` and retries multiply scan time; the state text is explicit.)
- Is `PASS` with an observation row the right status for a legitimate SNI default certificate, or should it be `NOT TESTED`? (Default: `PASS` with an observation row, because the requested hostname was served correctly; the row is what carries the nuance.)
