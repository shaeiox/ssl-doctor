# Proposal

## Why

A scan of `google.com:443` reported `[POSSIBLE · server] Protocol configuration
carries compatibility/security risks` with the detail "deprecated TLS 1.0/1.1 are
accepted by the server". Replaying the probe call log showed that TLS 1.0 and
TLS 1.1 were probed **only** under `ALL:@SECLEVEL=0`; their default-policy probes
never ran. The warning therefore claimed ordinary-client support from evidence
that a deliberately weakened client produced.

Two distinct defects sit behind that output:

1. **A lowered security level is treated as interoperability evidence.** A
   relaxed-policy handshake proves the server's TLS stack can still negotiate the
   version when legacy cipher suites are offered. It does not prove that a
   default-configured client can.
2. **A client that cannot build the offer is reported as a server refusal.** With
   OpenSSL 3.x the default context holds no TLS 1.0/1.1 ciphers, so a default-policy
   legacy probe legitimately fails locally with `NO_PROTOCOLS_AVAILABLE`. That was
   mapped to `refused`, i.e. an assertion about the server.

## What changes

- Every legacy version that answers under the relaxed policy is re-probed with the
  client's default policy. The result is a typed per-version class
  (`default`, `relaxed-only`, `relaxed-only-unverified`, `rejected`,
  `inconclusive`) recorded in `facts.probe_policy.support`.
- Local probe limitations (`NO_PROTOCOLS_AVAILABLE`, `NO_CIPHERS_AVAILABLE`,
  `CA MD TOO WEAK`, SSL-context errors) become a distinct `client-limited` state
  and are never reported as a refusal or as a negative fact about the server.
- The diagnosis branches on a typed `observation`
  (`legacy-accepted-default`, `legacy-accepted-relaxed-only`,
  `legacy-accepted-unverified`, `tls12-relaxed-only`, `probe-inconclusive`)
  instead of on status alone. `default`, `relaxed-only` and `tls12-relaxed-only`
  raise a server cause (the latter two with the policy limitation);
  `relaxed-only-unverified` and `probe-inconclusive` produce a note only.
- Findings contract 1.4 (additive). CLI, check ids and report layout are unchanged.

## Out of scope

- Cipher-suite introspection beyond what the version probes need.
- Probing more endpoints, or address-family policy.
- Changing severity for genuine deprecated-TLS acceptance: it stays a WARNING.
- Provider-specific behaviour of any kind.

## Evidence

- Mock replay of the reported scan reproduced the exact wording and the call log
  `[('TLS 1.0','relaxed'),('TLS 1.1','relaxed'),('TLS 1.2','relaxed'),
  ('TLS 1.3','default'),('TLS 1.2','default')]`.
- A default-policy TLS 1.0 probe against the local TLS fixture returns
  `('refused', '...NO_PROTOCOLS_AVAILABLE...')` before this change — a local,
  client-side condition reported as a server answer.
- The local fixture refuses TLS 1.0/1.1 under both policies, so relaxed-only
  acceptance is exercised through the `_probe_version` seam, not a live server.

## Files

`ssl_doctor/netchecks.py` (`check_protocol_matrix`, `_probe_version`,
`_is_local_probe_limitation`, `SUPPORT_*`), `ssl_doctor/analyze.py` (protocol
observation branch, inconclusive note), `ssl_doctor/contract.py` +
`schemas/findings-1.4.schema.json`, `tests/test_protocol_policy.py` (new),
`tests/test_probe_consistency.py`, `tests/test_contract.py`,
`docs/findings-contract.md`, `docs/execution-flow.md`, `CHANGELOG.md`.
