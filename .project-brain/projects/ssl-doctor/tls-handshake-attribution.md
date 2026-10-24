---
project: ssl-doctor
topic: tls-handshake-attribution
tags: [tls, handshake, timeout, failure-classification, diagnosis, contract]
status: verified
trust: human
last_done: 2026-10-24
version: 1
---

**Problem:** A report showed `tls.handshake` FAIL "handshake/connect timed out after 8s" next to
`tls.protocols` with TLS 1.0–1.3 all "accepted", diagnosed as *[probable · server]* "protocol/cipher
mismatch". The diagnosis blamed the server for a stall. (Report: `ssl-doctor-report-20261024-124452.html`.)

**Root cause:** `analyze` mapped on `hs.status == FAIL` plus the substring "accepted" in the matrix
evidence. `Finding` had no structured failure field, so a timeout and an SSL alert were identical
inputs. Contributing probe defects: `_handshake` fused connect and negotiate; the matrix filed
timeouts under `refused` and hid its `ALL:@SECLEVEL=0` relaxation; `check_tls_basic` and
`check_protocol_matrix` re-resolved the hostname instead of using the address `net.tcp` verified.

**Solution (v1):**
- `Finding.failure_kind` (+ facts `handshake_ip`, `handshake_failure`), registry in
  `contract.FAILURE_KINDS`; contract 1.1 → **1.2** (additive; 1.0/1.1 stay published).
- Probe split into `_connect` / `_negotiate` with `_ConnectTimeout` / `_NegotiationTimeout`.
  Evidence names phase, address, elapsed time and each attempt.
- One retry for timeout-class failures only: recovered stall → `WARNING` with all certificate facts
  kept; repeated stall → `FAIL`; `tls-alert` / `network-error` are never retried.
- Matrix rows are accepted / refused / timed out / network error; `no-version-accepted` vs
  `no-version-answered`; relaxed-cipher policy disclosed.
- All handshake probes pinned to the verified address.
- `analyze` attributes from `failure_kind`: timeouts/resets → probable **network**; only
  `tls-alert` may produce a protocol/cipher-mismatch **server** cause; unclassified → network + note.
  Independent server causes (chain, vhost) are not suppressed.

**Tests:** `tests/test_handshake_failure_attribution.py` (26 cases) + `FailureKindTests` in
`tests/test_contract.py`; fault fixtures in `tests/fixtures/fault_server.py` (`stall`, `stall-once`,
`alert`). The reproduction test fails against the old `analyze.py`.

**Notes:** A stall is never "confirmed" (one sample is not proof). Suite: 86 tests, 6 skipped.
