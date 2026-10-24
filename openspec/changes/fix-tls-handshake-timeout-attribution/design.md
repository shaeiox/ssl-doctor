# Design

## Context

See `proposal.md` (Why) for the trace. Constraints that shape this design:

- **Single finding identity.** `tls.handshake` is one check id in the published registry (`ssl_doctor/contract.py:31`) and in `docs/findings-contract.md`. The fix must not rename it or split the status semantics consumers already read.
- **Contract is versioned.** `contract.SCHEMA_VERSION = "1.1"` (`contract.py:24`); `findings-1.0` and `findings-1.1` are published under `schemas/` and must stay valid. Validation is a stdlib subset validator (`contract.validate`, `contract.py:173`) that ignores unknown keys, so an added optional property needs an explicit schema entry to be meaningful to consumers.
- **Rules stay pure.** `analyze.diagnose(items, context)` is a pure function over findings so the service can re-run it on stored results (`design.md` D3 of the chain-diagnosis change). Any attribution input must travel **inside** the finding, not in a side channel.
- **Existing style parses evidence strings.** `analyze.py` already greps evidence text in several rules (`:124-126`, `:187-191`, `:207`). That style is what produced this defect; new logic must not add another substring test where a typed value is available.
- **Stdlib only, no network fixtures beyond `openssl s_server`.** `tests/fixtures/tls_server.py` spawns real endpoints; `tests/fixtures/fake_server.py` fabricates findings. A stall fixture needs a plain TCP listener, not another TLS server.

## Goals / Non-Goals

**Goals**
- A timeout never produces a server protocol/cipher cause when version-pinned probes succeed.
- The next report of this shape is self-explanatory: it says which phase stalled, on which address, on which attempt, and what the per-version probes proved.
- The change is additive to the findings contract (minor bump) and to the diagnosis capability.
- Every behavior change is covered by a test that fails on the current code.

**Non-Goals**
- Diagnosing the specific middle-box or path fault.
- Making the matrix authoritative about cipher support.
- Guaranteeing that a single scan distinguishes a flaky path from a permanently stalling one (a retry narrows it, evidence names it).

## Decisions

### D1 — Failure mode is data, not prose

Add an optional `failure_kind: str = ""` to `findings.Finding` (`findings.py:31-49`), serialized by `to_dict()` as `failure_kind` and rendered in both report formats when non-empty.

Registry, declared once in `ssl_doctor/contract.py` next to `CHECK_IDS`:

| `failure_kind` | Set by | Meaning |
|---|---|---|
| `""` | any check | no classified failure (also the value on PASS) |
| `connect-timeout` | `tls.handshake` | the TCP connect to the verified address timed out |
| `negotiation-timeout` | `tls.handshake` | the socket opened, but the peer sent no (or an incomplete) TLS response before the timeout |
| `tls-alert` | `tls.handshake` | the peer rejected the offer with a TLS/SSL alert or cipher error |
| `network-error` | `tls.handshake` | reset, unreachable host, or another transport error during negotiation |
| `no-version-accepted` | `tls.protocols` | every version probe was refused |
| `no-version-answered` | `tls.protocols` | every version probe stalled or errored without a TLS answer |

Semantics: `failure_kind` describes **what went wrong**, `status` describes **the outcome**. `tls.handshake` = `WARNING` with `failure_kind="negotiation-timeout"` therefore means "the first attempt stalled, a retry completed".

`SCHEMA_VERSION` becomes `"1.2"`; `schemas/findings-1.2.schema.json` adds the optional property with an `enum` of the registry values. `findings-1.0/1.1` stay byte-identical; documents without the field keep validating, so 1.2 is a strict superset.

*Alternatives rejected:* keep parsing evidence strings (the current defect); put the value in `detail` (free text, same problem); add a new check id `tls.handshake.timeout` (renames the finding identity consumers key on, and duplicates the check).

### D2 — Name the phase

Split the handshake into two observable steps inside `netchecks`:

```text
_connect(host, port, timeout, connect_ip)   -> socket        # may raise _ConnectTimeout
_negotiate(sock, ctx, server_hostname)      -> ssl.SSLSocket # may raise _NegotiationTimeout
_handshake(...)                              -> composes both, unchanged public signature
```

`_ConnectTimeout` / `_NegotiationTimeout` are private classes raised from the existing OSError, carrying the original message. `check_tls_basic` maps them to `failure_kind` and to distinct evidence:

- `connect-timeout` → "TCP connect to 192.178.25.238:443 timed out after 8s"
- `negotiation-timeout` → "TCP connected to 192.178.25.238:443; TLS negotiation stalled for 8s with no server response"
- `tls-alert` → "TLS negotiation failed: [SSL: …] …" (`failure_kind="tls-alert"`)
- reset/unreachable during negotiation → "network-error"

Evidence always names the address and the elapsed time. This is what lets the engineer (and the report) distinguish "the port is not TLS" from "something on the path eats the ClientHello".

*Alternative rejected:* one "timed out" message and infer the phase from `net.tcp` (the TCP check and the handshake may use different addresses today — see D3).

### D3 — Probe the address that was verified

`check_tls_basic` and `check_protocol_matrix` accept a `connect_ip` and receive `ips[0]` (the address `check_tcp` proved reachable) from `run_remote_diagnostics` (`netchecks.py:753, 761, 765, 820`). Evidence names the address; `facts["handshake_ip"]` records it.

Rationale: the observed run proved TCP reachability to `192.178.25.238` and then let the TLS probes re-resolve, so a stall could have been measured against a different A/AAAA record. Comparing across endpoints is `tls.multiip`'s job (`:543-576`), which already pins addresses. Consistency across checks is a prerequisite for a diagnosis that claims to compare them.

*Alternative rejected:* return early when `tls.multiip` reports differences. It runs after the handshake and cannot explain a first-connection stall.

### D4 — Confirm a stall, never retry a rejection

On a timeout-class failure only, retry the generic handshake **once**, on a fresh connection, same context and timeout (`_HANDSHAKE_RETRIES = 1`, module constant). TLS alerts and verified-rejection errors are deterministic and are not retried.

| Attempt 1 | Attempt 2 | `status` | `failure_kind` | Evidence |
|---|---|---|---|---|
| stall | completes | `WARNING` | `negotiation-timeout` | both attempts, elapsed, negotiated protocol/cipher, chain |
| stall | stall | `FAIL` | `negotiation-timeout` | both attempts, elapsed |
| alert | — | `FAIL` | `tls-alert` | the alert text |

`facts["handshake_attempts"]` records the count. A `WARNING` finding must still carry the facts `check_tls_basic` produces today (protocol, cipher, cert, chain) so downstream checks (`tls.chain`, `tls.hostname`, `tls.verify`, validity) keep running — the current early return (`:764-766`) stays keyed on `FAIL`.

*Alternatives rejected:* three retries (costs up to 24 s of the engineer's timeout budget for a fault that is usually persistent); retry inside `_handshake` (hides the attempt count from the evidence).

### D5 — The matrix classifies its rows and discloses its policy

`check_protocol_matrix` changes only in its evidence and its `failure_kind`:

- rows become `"{label}: accepted ({version})"`, `"{label}: refused ({alert})"`, `"{label}: timed out after {t}s (no response)"`, `"{label}: network error ({exc})"`;
- a timeout no longer lands in `refused` (today's `:469-471`), so "all versions refused" and "nothing answered" are distinguishable;
- when TLS 1.0–1.2 probes ran with `ALL:@SECLEVEL=0`, the finding carries the evidence line "TLS 1.0–1.2 probes used relaxed cipher policy (ALL:@SECLEVEL=0); 'accepted' is not proof that a modern client succeeds", and `detail` repeats it when such a version was accepted;
- `failure_kind` is `no-version-answered` when every row timed out or errored, `no-version-accepted` when every row was refused, `""` otherwise;
- `status` logic is unchanged (`:473-487`), so PASS/WARNING/FAIL meanings do not move for existing consumers.

The orchestrator then appends one coherence line to a failed handshake finding when the matrix proved at least one version works: "per-version probes completed for TLS 1.2, TLS 1.3 - the failure is a stall on the default path, not a protocol/cipher rejection".

### D6 — Attribution table in `analyze.diagnose`

Replace `analyze.py:100-112` with a failure-mode driven block. Let `accepted = matrix is not None and matrix.status in (PASS, WARNING)` (the matrix is `FAIL` only when nothing was supported, `:475-477`).

| `hs.status` | `hs.failure_kind` | `accepted` | certainty | origin | Summary / recommendation |
|---|---|---|---|---|---|
| FAIL | `negotiation-timeout` | yes | probable | **network** | "The TLS handshake stalls, although version-pinned handshakes complete - an intermittent stall or a middle-box on the path, not a protocol/cipher mismatch" → repeat the measurement, retest from another network, inspect TLS-inspection devices and idle timeouts |
| FAIL | `connect-timeout` | yes | probable | **network** | "TCP connects to the endpoint but the TLS probe's connection attempt timed out - path instability or an inspection device" → repeat; compare addresses |
| FAIL | `tls-alert` | yes | probable | server | today's "protocol/cipher mismatch" text, plus a note that the matrix accepted N versions and which cipher policy was used |
| FAIL | `no-version-*` (matrix) or none accepted | no | probable | network | today's "no TLS version completes a handshake" text, with the matrix's own classification in the evidence |
| FAIL | `network-error` | yes | probable | network | "the connection is reset or dropped during TLS negotiation - an inspection device or a load balancer is the likely cause" |
| WARNING | `negotiation-timeout`/`connect-timeout` | any | probable | network | "the handshake stalled and completed on retry - intermittent path behaviour"; no server-config recommendation |
| FAIL | `""` (unknown/legacy finding) | yes | probable | network | conservative fallback: never claim a protocol mismatch without typed evidence |

Rules that make the defect unreachable:

- A cause whose summary contains "protocol/cipher mismatch" requires `failure_kind == "tls-alert"`.
- A timeout-class failure may not produce a **server**-origin cause at all; the server chain/vhost rules still run independently, so a genuinely broken chain is still reported.
- Stalls are never `confirmed` (one sample is not proof); certainty stays `probable`.
- The cause evidence always includes the failure kind and the matrix rows, so a report can be audited without re-running.

*Alternative rejected:* keep one rule and only change the wording. It leaves origin wrong (`server`), and the SaaS/monitoring consumers act on `origin`.

### D7 — Regression proof first

New tests (`stdlib unittest`, existing fixtures):

1. **Unit matrix** over `{negotiation-timeout, connect-timeout, tls-alert, network-error} × {matrix accepted, matrix FAIL, matrix absent}` asserting origin, certainty, and the no-server-blame invariant.
2. **Exact reproduction** of the artifact pair: handshake FAIL with "timed out after 8s" + matrix with four accepted rows → assert no cause mentions "protocol/cipher mismatch" and the top cause origin is `network`. This test must fail on today's code.
3. **Stall fixture** (`tests/fixtures/tls_server.py` gains a `stall` mode: a plain `socket` listener that accepts and never replies) → `check_tls_basic` returns FAIL, `failure_kind="negotiation-timeout"`, evidence names the address and both attempts.
4. **Flaky fixture** (`stall-once` mode: first connection accepted and dropped, second proxied to the real `openssl s_server`) → handshake is `WARNING`, downstream checks still run.
5. **Alert fixture**: request a version the fixture server refuses → `failure_kind="tls-alert"` and the server cause survives.
6. **Contract test**: a document carrying `failure_kind` validates against `findings/1.2`; the shipped 1.1 documents still validate unchanged.

## Risks / Trade-offs

- **[Extra latency on a stalled path]** one retry can consume a second timeout window (default 8 s) → only timeout-class failures retry, and evidence states the total elapsed time.
- **[New contract minor version]** consumers pinned to a literal `schema_version == "1.1"` would reject 1.2 → the loader accepts any `1.x` minor (`SUPPORTED_MAJOR = 1`), and the release notes name the bump.
- **[Behavior change in verdicts]** some previously `FAIL` handshakes become `WARNING`, and server-blame causes become network causes → documented in `CHANGELOG.md` and the README; existing end-to-end verdict table (`tests/test_scan_e2e.py`) is unaffected because those fixtures have no stalls.
- **[Retry can mask a real one-shot failure]** the `WARNING` status and the attempt evidence keep the fact visible; a diagnosis cause is still raised, so the run is never a clean PASS.
- **[Address pinning changes which endpoint is measured]** for multi-record names, the handshake now follows `tls.multiip`'s first address instead of whatever the resolver returns → evidence names the address, and `tls.multiip` still covers the rest.
- **[Elapsed-time measurement across platforms]** `time.monotonic()` only; no wall-clock dependence in evidence.

## Migration Plan

1. Land D1 (field + schema 1.2 + contract test) with no rule changes; the field is populated by `tls.handshake` only.
2. Land D2/D3/D5 (probe changes) behind the existing check ids; run the full suite.
3. Land D4 (retry) together with tests 3 and 4; the `WARNING` path is inert for healthy endpoints.
4. Land D6 (attribution) with tests 1, 2 and 5; test 2 is the gate — it must fail before this step.
5. Update docs and `CHANGELOG.md`.
6. Rollback: revert the change directory; the contract field is optional, so documents produced with 1.2 still load on a 1.1-era build under `SUPPORTED_MAJOR = 1`.

## Open Questions

- Should the retry budget be exposed in `/timeout` (for example `/timeout 8 20 1`), or stay a module constant for the first release? (Default: constant, to keep the CLI surface unchanged.)
- Should a `WARNING`-level stall also lower the overall verdict for monitoring targets, or only raise a cause? (Default: it raises a cause, so `overall` is at least `WARNING` — monitoring keeps detecting it.)
