---
project: ssl-doctor
topic: revocation
tags: [ocsp, crl, stapling, ipv6, endpoints]
status: done
trust: ai-inferred
last_done: 2026-10-26
version: 1
---

**Problem:** Revocation status and per-address-family endpoint coverage (complete-certificate-diagnostics P7; moved from cert-analysis-internals v3, unchanged).

**v3 (P7, trust: ai-inferred):**
- `ssl_doctor/revocation.py`:
  - Mode staple | online | off (`--revocation`, job option `revocation`).
  - Stapled: `openssl s_client -status -msg`; DER extracted by CertificateStatus shape (0x01 + uint24 + DER SEQUENCE of that length; TLS 1.2 and 1.3 alike).
  - `evaluate` = `openssl ocsp -respin -issuer -cert -CAfile issuer -partial_chain -no_nonce`, then the time window checked in Python (`-attime` does not fail stale responses).
  - Online: `openssl ocsp -url`, falling back to CRL (`urllib`, 10 MiB cap, `openssl crl -CAfile issuer`), for each non-root certificate.
- `netchecks.revocation_finding` → `tls.revocation`; `facts.certificates.presented.revocation`.
- Multi-IP: `_family_balanced`, `family` on endpoint records, `_family_notes` / `_family_difference`.
- Gotcha: flipping a byte near the end of an OCSP response hits the embedded responder certificate, not the signature; the test uses a response signed by another CA instead.
