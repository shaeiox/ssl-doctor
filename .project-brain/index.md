# Project Brain — index

> Read this first. Drill into projects/<name>/<topic>.md only when you need detail.

## ssl-doctor  (Python · TLS/SSL diagnostics · CLI · SSH · Nginx/Apache · Windows)

- (no topics yet)

> resume 2026-10-25 · done: v0.9.3 (nginx config discovery from the running master) merged to master, tagged & pushed · next: archive fix-nginx-config-discovery; user re-runs /scan on the /opt/pvm server; remembered-servers still needs Windows CI (6.1) + manual vault checks (6.2) · blocker: none

- architecture-and-scope → Project layout, modes, security behavior   [✓ verified 2026-10-25 · v2] → projects/ssl-doctor/architecture-and-scope.md
- chain-diagnosis → Chain reading, verify vs rootonly, SAN-only, Windows rootca   [✓ verified 2026-10-24 · v1] → projects/ssl-doctor/chain-diagnosis.md
- server-ssh-nginx → Read-only SSH, nginx vhost resolution, chain linkage, configured-vs-presented   [✓ done 2026-10-25 · v3] → projects/ssl-doctor/server-ssh-nginx.md
- commands-reference → Actual executed commands documented (local/remote, traced to source)   [✓ verified 2026-10-25 · v2] → projects/ssl-doctor/commands-reference.md
- evidence-based-probes → Endpoint states, comparable-only comparison, SNI observations, probe reconciliation, cause limitations   [✓ verified 2026-10-24 · v1] → projects/ssl-doctor/evidence-based-probes.md
- protocol-policy-evidence → Relaxed vs default cipher policy, per-version support classes, client-limited probes, contract 1.4   [✓ verified 2026-10-24 · v1] → projects/ssl-doctor/protocol-policy-evidence.md
- legacy-tls-diagnosis-semantics → default_probe states, Finding.uncertainty, diagnosis.unresolved, verify-first remediation, endpoint coverage, contract 1.5   [✓ done 2026-10-24 · v1] → projects/ssl-doctor/legacy-tls-diagnosis-semantics.md
- tls-handshake-attribution → failure_kind classification, stall retry, probe address pinning, network-vs-server attribution   [✓ verified 2026-10-24 · v1] → projects/ssl-doctor/tls-handshake-attribution.md
- agent-report → /report agent: AI-ready md+json from the redacted contract doc, verbatim prompt, atomic write   [✓ done 2026-10-24 · v1] → projects/ssl-doctor/agent-report.md
- copy-to-clipboard → drag-to-copy, /copy, Ctrl-Y; native Win32/X11 clipboard, tools, OSC 52; Windows ReadConsoleInputW mouse   [✓ done 2026-10-25 · v3] → projects/ssl-doctor/copy-to-clipboard.md
- ui-design-system → Theme, full-screen shell, result frames, streaming into frames, centred banner, chat composer   [✓ done 2026-10-25 · v7] → projects/ssl-doctor/ui-design-system.md
- remembered-servers → SSH server profiles + passwords in OS vault (Win Credential Manager / Secret Service), host-key bound; ADR-001 Accepted, implemented   [⚠ in-progress 2026-10-25 · v3] → projects/ssl-doctor/remembered-servers.md
- _decisions → One-line decision log: colours, frames, static input, report pills   [✓ verified 2026-10-24 · v1] → projects/ssl-doctor/_decisions.md
