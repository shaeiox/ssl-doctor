---
project: ssl-doctor
topic: evidence-based-probes
tags: [tls, endpoints, sni, protocol-matrix, diagnosis, confidence, contract]
status: verified
trust: human
last_done: 2026-10-24
version: 1
---

**Problem:** one `/scan google.com` emitted three warnings the evidence did not support: an
"inconsistent load-balanced endpoints" server cause from unreachable IPv6 addresses, a
TLS 1.3 probe timeout contradicting a successful TLS 1.3 handshake, and an SNI fingerprint
difference promoted to a virtual-host defect.

**Root causes**
- `netchecks.check_multi_ip` stored one *string* per endpoint and compared them as a set, so an
  error message competed with a fingerprint; only the fingerprint was compared; addresses
  `net.tcp` never verified were probed.
- `check_protocol_matrix` never learned the primary negotiated protocol, timeout rows did not
  affect the verdict, and relaxed-policy acceptance was not distinguished from default-policy
  interoperability.
- `check_sni_difference` treated a fingerprint difference as evidence of misconfiguration, and
  `analyze` hard-coded certainty per rule with no way to state evidence gaps.

**Solution (v1)**
- Endpoint states per address (`negotiated`, `tls-rejected`, `tcp-unreachable`, `timed-out`,
  `probe-unavailable`), recorded in `facts["endpoints"]`; only `negotiated` endpoints with the
  same server name are compared, over fingerprint + hostname coverage + chain status; `< 2`
  comparable ⇒ NOT TESTED + `observation=endpoint-comparison-inconclusive`, no cause.
- Protocol rows: accepted / accepted under relaxed policy / refused / inconclusive; a version the
  primary handshake negotiated is never refused or unsupported; one bounded retry
  (`PROBE_BUDGET_FACTOR`); TLS 1.2 default-policy probe states modern-client interoperability;
  inconclusive ⇒ WARNING + `observation=probe-inconclusive` + a diagnosis note.
- SNI is an observation (`sni-certificate-differs`), never a defect claim; `tls.hostname`/
  `tls.verify` remain the authorities; a failing handshake for the requested name stays FAIL.
- `Cause.limitations` + evidence-strength labels; contract 1.3 (`observation`, `limitations`,
  `endpoints`, `endpoint_comparison`, `probe_policy`, all optional).

**Tests:** `tests/test_endpoint_comparison.py` (15), `tests/test_sni_observation.py` (8),
`tests/test_probe_consistency.py` (16), plus contract/registry updates. Suite: 125 tests, 6 skipped.

**Notes:** Probe seams (`_probe_endpoint`, `_probe_version`, `_sni_cert`) exist so tests stay
offline and deterministic; one real-socket test still exercises an unroutable IPv6 address.
