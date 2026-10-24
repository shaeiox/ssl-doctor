# Proposal

## Why

A scan of `google.com:443` produced correct core results — TLS 1.3 negotiated, hostname match, validity, system validation and presented chain all PASS — and still emitted three warnings that the evidence does not support:

| # | Finding | Reported conclusion | What the evidence actually shows |
|---|---|---|---|
| 1 | `tls.multiip` WARNING | "endpoints present DIFFERENT results (load-balanced pools with inconsistent certificates…)" | one IPv4 answered; three IPv6 endpoints were `Network is unreachable` |
| 2 | `tls.protocols` | "TLS 1.3: timed out after 8s (no response)" | the same scan's primary handshake negotiated **TLSv1.3** |
| 3 | `tls.sni` WARNING | "the server presents DIFFERENT certificates with and without SNI" → probable/possible vhost defect | a CDN or shared host legitimately serves a default certificate to clients that send no SNI |

Each defect was reproduced against the current tree (CPython 3.11.2, `openssl` fixtures), not inferred from the report alone.

### Trace 1 — transport failures are compared as if they were certificates

`ssl_doctor/netchecks.py:712-745` (`check_multi_ip`) collects **one string per endpoint**:

```python
fp = certs.decode_der(der, enrich=False).sha256 if der else "(no cert)"
...
except (ssl.SSLError, OSError) as exc:
    fp = f"handshake failed: {str(exc).splitlines()[0][:60]}"
fps[ip] = fp
...
distinct = {v for v in fps.values()}
if len(distinct) == 1: PASS else WARNING "endpoints present DIFFERENT results"
```

An error string is just another set member, so `{<fingerprint>, "handshake failed: [Errno 101] Network is unreachable"}` has `len(distinct) == 2` and is reported as certificate inconsistency. `ssl_doctor/analyze.py:302-306` then promotes that WARNING to a **probable server** cause.

Reproduced (`check_multi_ip` with `["127.0.0.1", "2001:db8::64", "2001:db8::65"]` against a full-chain fixture):

```text
status: WARNING
   endpoints present DIFFERENT results (load-balanced pools with inconsistent certificates…
   127.0.0.1: 4c484bdda4eceec423d0e514ee04d594
   2001:db8::64: handshake failed: [Errno 101] Network is unreachable
   2001:db8::65: handshake failed: [Errno 101] Network is unreachable
diagnosis: [('probable', 'server', 'Load-balanced endpoints present different certificates - …')]
```

Two further flaws in the same function: it compares only the leaf fingerprint, never hostname coverage or chain status, so a pool that serves the same certificate for the wrong names, or the same leaf without intermediates, compares as PASS; and it probes up to four addresses (`uniq[:4]`, `:722`) while only one was verified reachable by `check_tcp` (`:944`).

### Trace 2 — the dedicated probe is never reconciled with the primary handshake

`ssl_doctor/netchecks.py:395-484` (`check_tls_basic`) negotiates with default settings and records `facts["protocol"]`. `check_protocol_matrix` (`:588-662`) runs later, in a fresh connection per version with `min_v = max_v = <version>`. Nothing compares the two results:

- the matrix has no access to the negotiated protocol, so a row cannot be flagged as contradicting a successful handshake;
- a timeout row (`:618-621`) is classified correctly but is otherwise inert: `status` is computed from `supported`/refused only (`:629-643`), so the matrix in the reproduction returned **PASS**;
- `analyze` has no rule for a `PASS` handshake plus an inconclusive row, so the contradiction disappeared from the diagnosis entirely.

Reproduced by making only the TLS 1.3 context stall (primary handshake unmodified):

```text
primary: PASS | TLSv1.3
matrix status: PASS | kind: ""
   TLS 1.2: accepted (TLSv1.2)
   TLS 1.3: timed out after 2s (no response)
diagnosis causes: NONE
notes: ['All executed checks passed. …']
```

That is the mirror image of the reported symptom: earlier the timeout was read as evidence about the server's protocol policy; here it is dropped. Both violate the same requirement — a timeout is *inconclusive* and must be reported as such, or bounded-retried, never reinterpreted.

Cost is unbounded in the other direction too: each version gets a full timeout and no retry, so four stalled probes cost 4 × timeout with no attempt to distinguish a transient stall from a policy.

### Trace 3 — an SNI observation is treated as a configuration defect

`check_sni_difference` (`:665-709`) compares two fingerprints and returns `WARNING` with "the server presents DIFFERENT certificates with and without SNI" and the advice "Check virtual-host configuration and the default SSL site" (`:697-706`). `analyze.py:297-301` maps any such WARNING to a server-origin "SNI/virtual-host inconsistency" cause.

Nothing in that path consults the evidence that would make it a defect: whether the certificate served **with** the correct SNI covers the requested hostname (already measured as `tls.hostname`, `:1000-1012`), whether validation passed, or whether nginx reports a real vhost problem. Serving a default certificate to a client that sends no SNI is normal for CDNs, shared hosting and any TLS terminator with a default vhost.

### Trace 4 — relaxed-policy acceptance is not ordinary interoperability

`check_protocol_matrix` probes TLS 1.0–1.2 with `ALL:@SECLEVEL=0` (`:606-612`) and now discloses that in evidence (`:652-656`). The distinction is still missing where it matters: the row text says `TLS 1.0: accepted (TLSv1)`, the finding's `detail` and the diagnosis summary speak of "deprecated TLS 1.0/1.1 are enabled", with no statement that this is acceptance *under a lowered security level* rather than what a default-configured modern client would obtain. Security findings must be kept, but their scope must be stated.

### Trace 5 — confidence labels are assigned per rule, not per evidence

`analyze.py` hard-codes `"probable"`/`"possible"` in each rule (`:302-306` probable server from one comparable endpoint + transport errors; `:332-336` possible server from a WARNING whose rows may be inconclusive). `Cause` has no field for the limits of its evidence, and `Diagnosis.overall` (`:48-54`) turns any cause into at least WARNING. Raw observations (fingerprints differ, a probe timed out) and inferred causes (a misconfigured pool) are not separated anywhere in the model.

## What Changes

- **Endpoint comparison becomes evidence-based.** `check_multi_ip` records a state per endpoint (`negotiated`, `tcp-unreachable`, `tls-rejected`, `timed-out`, `probe-unavailable`), compares only endpoints that yielded a certificate, and compares fingerprint **plus** hostname coverage and chain status. Inconsistency requires at least two comparable endpoints with a meaningful difference; one comparable endpoint is reported as inconclusive; transport failures stay as separate, clearly-labelled evidence and can never be proof that a certificate differs.
- **Probes are reconciled with the primary handshake.** The matrix receives the negotiated protocol, marks a row that contradicts it as an inconsistent-probe result, retries each inconclusive version once inside a bounded budget (configurable through the existing `/timeout` value), and reports the outcome as inconclusive rather than as unsupported or as a policy risk.
- **SNI difference becomes an observation.** `tls.sni` reports what was seen (same certificate / different certificate / could not probe without SNI) and never asserts a vhost defect. Correlation may use it only together with independent evidence (hostname mismatch, unexpected certificate, nginx vhost findings).
- **Relaxed-policy results state their scope.** Rows and details say "accepted with relaxed cipher policy (`ALL:@SECLEVEL=0`)", and a default-policy interop probe distinguishes "modern clients can connect" from "only a lowered security level can". Security warnings about TLS 1.0/1.1 are retained.
- **Confidence follows evidence strength.** Certainty is derived by a documented rule (direct measurement vs. consistent-but-gapped vs. observation-only), each cause carries its limitations, and transport failures or inconclusive probes are never promoted to a probable configuration defect. The overall verdict rules stay as they are, with tests pinning them.
- **Findings contract 1.3 (additive):** `limitations` on a cause, new `failure_kind` values (`probe-inconclusive`, `endpoint-unreachable`) and a structured endpoint-state block in `facts`. 1.0–1.2 stay published and keep validating.

## Capabilities

### New Capabilities
- `endpoint-comparison`: probing several addresses returned by DNS, classifying each outcome, and deciding whether a certificate difference is established.
- `sni-behaviour-observation`: recording how a server answers with and without SNI, and what may and may not be concluded from it.

### Modified Capabilities
- `tls-negotiation-diagnostics`: adds primary-versus-probe reconciliation, bounded retries for inconclusive probes, and relaxed-policy scope for version rows. This capability is introduced by the pending change `fix-tls-handshake-timeout-attribution`; this delta adds requirements to it rather than replacing any.
- `diagnosis-correlation`: adds evidence-strength certainty, per-cause limitations, and the raw-observation/inferred-cause separation, plus the correlation rules for endpoints and SNI.

## Impact

- **Code:** `ssl_doctor/netchecks.py` (`check_multi_ip`, `check_sni_difference`, `check_protocol_matrix`, `run_remote_diagnostics`, `export_facts`), `ssl_doctor/analyze.py` (endpoint and SNI rules, certainty helper, limitations), `ssl_doctor/findings.py` (optional fields), `ssl_doctor/contract.py` + `schemas/findings-1.3.schema.json`, `ssl_doctor/report.py` (render limitations and endpoint states).
- **Tests:** new `tests/test_endpoint_comparison.py`, `tests/test_sni_observation.py`, `tests/test_probe_consistency.py`; new fixtures for a pool with two valid endpoints, a pool with mixed certificates, a default-certificate-without-SNI endpoint, and a server that closes without a handshake. Existing suites (`test_scan_e2e`, `test_diagnosis`, `test_tls_inspection`, `test_handshake_failure_attribution`) must stay green.
- **Behavior change:** scans whose only "pool" difference came from unreachable addresses stop reporting a server cause; SNI differences stop producing a cause on their own; a stalled version probe stops being invisible. Genuine findings (mixed certificates across two reachable nodes, hostname mismatch, TLS 1.0 acceptance) remain.
- **Dependencies:** none. Standard library only, no new check ids, no new major contract version, no CLI change.

## Out of Scope

- Probing more than the four addresses the current cap allows, or implementing a happy-eyeballs/address-family preference policy.
- Enumerating cipher suites per protocol version, or identifying *which* cipher a legacy probe negotiated.
- Explaining why a specific path stalls a specific probe (the report must say "inconclusive" and cite the primary success).
- Changing `nginx.protocols` / `nginx.ciphers` semantics, or the overall verdict rules.
- Any remediation action; all probes stay read-only.
