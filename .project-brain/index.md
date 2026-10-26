# Project Brain — index

> Read this first. Drill into projects/<name>/<topic>.md only when you need detail.

## ssl-doctor  (Python · TLS/SSL diagnostics · CLI · SSH · Nginx/Apache · Windows)

- (no topics yet)

> resume 2026-10-26 · done: complete-certificate-diagnostics P0–P7 + integration gate (63/63 tasks, verification.md) on branch feat/complete-certificate-diagnostics · next: review, archive older changes then this one, merge · blocker: none

- architecture-and-scope → Project layout, modes, security behavior   [✓ verified 2026-10-25 · v2] → projects/ssl-doctor/architecture-and-scope.md
- chain-diagnosis → Chain reading, verify vs rootonly, SAN-only, Windows rootca   [✓ done 2026-10-26 · v2] → projects/ssl-doctor/chain-diagnosis.md
- server-ssh-nginx → Read-only SSH, nginx vhost resolution, chain linkage, configured-vs-presented   [✓ done 2026-10-26 · v6] → projects/ssl-doctor/server-ssh-nginx.md
- commands-reference → Actual executed commands documented (local/remote, traced to source)   [✓ verified 2026-10-25 · v2] → projects/ssl-doctor/commands-reference.md
- evidence-based-probes → Endpoint states, comparable-only comparison, SNI observations, probe reconciliation, cause limitations   [✓ verified 2026-10-24 · v1] → projects/ssl-doctor/evidence-based-probes.md
- protocol-policy-evidence → Relaxed vs default cipher policy, per-version support classes, client-limited probes, contract 1.4   [✓ verified 2026-10-24 · v1] → projects/ssl-doctor/protocol-policy-evidence.md
- legacy-tls-diagnosis-semantics → default_probe states, Finding.uncertainty, diagnosis.unresolved, verify-first remediation, endpoint coverage, contract 1.5   [✓ done 2026-10-24 · v1] → projects/ssl-doctor/legacy-tls-diagnosis-semantics.md
- tls-handshake-attribution → failure_kind classification, stall retry, probe address pinning, network-vs-server attribution   [✓ verified 2026-10-24 · v1] → projects/ssl-doctor/tls-handshake-attribution.md
- agent-report → /report agent: AI-ready md+json from the redacted contract doc, verbatim prompt, atomic write   [✓ done 2026-10-24 · v1] → projects/ssl-doctor/agent-report.md
- copy-to-clipboard → drag-to-copy, /copy, Ctrl-Y; native Win32/X11 clipboard, tools, OSC 52; Windows ReadConsoleInputW mouse   [✓ done 2026-10-25 · v3] → projects/ssl-doctor/copy-to-clipboard.md
- ui-design-system → Theme, full-screen shell, result frames, streaming into frames, centred banner, chat composer   [✓ done 2026-10-25 · v8] → projects/ssl-doctor/ui-design-system.md
- remembered-servers → SSH server profiles + passwords in OS vault (Win Credential Manager / Secret Service), host-key bound; ADR-001 Accepted, implemented   [⚠ in-progress 2026-10-25 · v4] → projects/ssl-doctor/remembered-servers.md
- certificate-diagnostics → 45-check audit remediation: verdict/unexplained, key states, verify transport, contract 1.7, phases P0–P7, gate 45/45   [✓ done 2026-10-26 · v4] → projects/ssl-doctor/certificate-diagnostics.md
- cert-analysis-internals → certs/chainval/certpolicy/hostnames internals: strict parsing, verify_link, roles, trust class, policy, gotchas   [⚠ in-progress 2026-10-26 · v3] → projects/ssl-doctor/cert-analysis-internals.md
- revocation → stapled OCSP via s_client -status + openssl ocsp validation, online OCSP/CRL opt-in, IPv4/IPv6 endpoint balance   [✓ done 2026-10-26 · v1] → projects/ssl-doctor/revocation.md
- _decisions → One-line decision log: colours, frames, static input, report pills   [✓ verified 2026-10-24 · v1] → projects/ssl-doctor/_decisions.md
