# Design

## Context

- `check_protocol_matrix` (`ssl_doctor/netchecks.py`) is a pure probe function:
  it opens one connection per version and returns a `Finding`. Everything the
  diagnosis may use must be on that finding or in `facts`, because
  `analyze.diagnose()` is re-run over stored documents by the service.
- Before this change the version table carried a policy flag per version
  (`relaxed` for 1.0–1.2), and the row vocabulary conflated "the server answered
  this way" with "this client could not ask".
- No new dependency and no CLI surface change: `/timeout` remains the only knob.

## Decisions

### D1 — Two questions per version, kept apart

For each version ask (a) can the server negotiate it at all, and (b) can an
ordinary default-configured client negotiate it. Legacy versions are probed
relaxed first because that is the only way this client can still offer them; if
that answers `accepted`, a second default-policy probe runs for the same version.
TLS 1.2 and 1.3 are probed under the default policy first, so their rows already
answer (b). Only (b) may be described as ordinary-client support.

### D2 — Typed per-version classes, not prose

`support[version]` is one of:

| class | meaning |
|---|---|
| `default` | accepted with the default cipher policy |
| `relaxed-only` | answered under `ALL:@SECLEVEL=0`; the default-policy probe was refused |
| `relaxed-only-unverified` | answered under `ALL:@SECLEVEL=0`; the default-policy probe was client-limited or inconclusive |
| `rejected` | the peer answered with a refusal |
| `inconclusive` | no answer (timeout, reset, local limit) |

`facts.probe_policy` additionally carries `confirmed_legacy` (`default` only) and
`unverified_legacy`.

### D3 — Client limitations are a separate state

`_is_local_probe_limitation()` recognises `NO_PROTOCOLS_AVAILABLE`,
`NO_CIPHERS_AVAILABLE`, `CA MD TOO WEAK` and SSL-context construction errors and
returns `client-limited`. It is never folded into `refused`: the server was never
asked, so the probe says nothing about it.

### D4 — The diagnosis branches on observation classes

The finding's `observation` is one of `legacy-accepted-default`,
`legacy-accepted-relaxed-only`, `legacy-accepted-unverified`,
`probe-inconclusive` (or `""`). `analyze.diagnose()` maps:

- `legacy-accepted-default` ⇒ `possible` server cause ("ordinary clients can
  negotiate them"), no limitation about policy;
- `legacy-accepted-relaxed-only` ⇒ `possible` server cause with the limitation
  "legacy acceptance requires the relaxed cipher policy (ALL:@SECLEVEL=0); an
  ordinary client cannot reach it";
- `legacy-accepted-unverified` ⇒ a diagnosis note only, no server cause, status
  stays WARNING;
- `tls12-relaxed-only` ⇒ `possible` server cause with the limitation that TLS 1.2
  needed `ALL:@SECLEVEL=0`, so default-configured clients cannot negotiate it;
- `probe-inconclusive` (`failure_kind`) ⇒ a note keyed on the failing rows, never a
  claim that a version is unsupported.

The class order is legacy-default, legacy-relaxed-only, legacy-unverified,
TLS 1.2-relaxed-only, inconclusive: a legacy conclusion is the stronger one, and it
already carries the relaxed-policy limitation that applies to the whole matrix.

No evidence string is parsed in the diagnosis layer; the earlier attempt to derive
support by parsing rows was removed for that reason.

### D5 — Contract 1.4 is additive

1.0–1.3 schemas stay published and untouched; every new key is optional, so stored
1.3 documents keep validating. `probe_policy` gains `support`,
`confirmed_legacy` and `unverified_legacy`; the observation enum gains the three
legacy classes and `tls12-relaxed-only`.

### D6 — Budget scales with the extra probes

The default-policy legacy probe roughly doubles the number of connections, so the
retry budget becomes `PROBE_BUDGET_FACTOR * (len(versions) + 3)` attempts within
`timeout * PROBE_BUDGET_FACTOR * (len(versions) + 3)` seconds. Refusals are never
retried; an inconclusive probe is retried once while budget remains.

## Risks

- A server that answers legacy versions only through an unusual cipher set could
  land in `relaxed-only-unverified`; that is the intended, conservative outcome.
- Extra connections lengthen the check on hostile endpoints; the budget bound
  keeps it finite.
