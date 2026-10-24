---
project: ssl-doctor
topic: protocol-policy-evidence
tags: [tls, protocol-matrix, cipher-policy, diagnosis, confidence, contract]
status: verified
trust: human
last_done: 2026-10-24
version: 1
---

**Problem:** `/scan google.com` reported `[possible · server] Protocol configuration carries
compatibility/security risks` with the detail "deprecated TLS 1.0/1.1 are accepted by the
server". Replaying the probe call log showed TLS 1.0/1.1 were probed **only** with
`ALL:@SECLEVEL=0`; their default-policy probes never ran.

**Root causes**
- `check_protocol_matrix` treated a relaxed-policy handshake as proof of ordinary-client
  support. A lowered security level proves only that the server's stack can still negotiate
  the version when legacy cipher suites are offered.
- `_probe_version` mapped client-side failures (`NO_PROTOCOLS_AVAILABLE`,
  `NO_CIPHERS_AVAILABLE`, `CA MD TOO WEAK`, local SSL-context errors) to `refused`, i.e. a
  statement about the server. With OpenSSL 3.x the default context has no TLS 1.0/1.1
  ciphers, so this is the *normal* outcome of a default-policy legacy probe here.
- `analyze` derived the cause from `status == WARNING` alone and reconstructed policy
  limitations by scanning row prose.

**Solution (v1)**
- Per-version classes in `facts.probe_policy.support`: `default`, `relaxed-only`,
  `relaxed-only-unverified`, `rejected`, `inconclusive`; `confirmed_legacy` /
  `unverified_legacy` summarise the deprecated versions.
- Legacy versions that answer relaxed are re-probed with the client's default policy;
  TLS 1.2 default success stays plain `default` (PASS), TLS 1.2 relaxed-only is a WARNING
  about interoperability.
- `client-limited` state + `_is_local_probe_limitation()`: a probe the client cannot build is
  never reported as refused. Version-the-primary-negotiated is still never refused.
- `analyze` branches on typed observations — `legacy-accepted-default`,
  `legacy-accepted-relaxed-only` (cause `possible` + policy limitation),
  `legacy-accepted-unverified` (note only, no server cause), `tls12-relaxed-only`
  (cause `possible` + policy limitation), `probe-inconclusive` (note keyed on the rows).
  No evidence prose is parsed.
- Contract 1.4 (additive): the four observations and `probe_policy.support` /
  `confirmed_legacy` / `unverified_legacy`; 1.0–1.3 stay published and valid.

**Tests:** `tests/test_protocol_policy.py` (14; 10 of them fail on the pre-change code),
`tests/test_probe_consistency.py` reconciled, `tests/test_contract.py` covers the 1.4
classes. Suite: 139 tests, OK (6 skipped).

**Notes:** the local `TLSServer` fixture refuses TLS 1.0/1.1 under both policies, so relaxed
acceptance is exercised through the `_probe_version` seam (8 positional args, queued
`(state, detail)` tuples). `Diagnosis.overall` is cause-derived, so an unverified legacy
observation keeps its WARNING finding and note but does not raise the diagnosis to WARNING.
