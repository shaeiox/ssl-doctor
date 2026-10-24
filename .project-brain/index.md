# Project Brain — index

> Read this first. Drill into projects/<name>/<topic>.md only when you need detail.

## ssl-doctor  (Python · TLS/SSL diagnostics · CLI · SSH · Nginx/Apache · Windows)

- (no topics yet)

> resume 2026-10-24 · done: merged TLS diagnosis branch into master as v0.7.0 (contract 1.5), tagged locally, not pushed · next: push master + v0.7.0 · blocker: none

- architecture-and-scope → Project layout, modes, security behavior   [✓ verified 2026-10-24 · v1] → projects/ssl-doctor/architecture-and-scope.md
- chain-diagnosis → Chain reading, verify vs rootonly, SAN-only, Windows rootca   [✓ verified 2026-10-24 · v1] → projects/ssl-doctor/chain-diagnosis.md
- server-ssh-nginx → Read-only SSH, nginx vhost resolution, chain linkage, configured-vs-presented   [✓ verified 2026-10-24 · v1] → projects/ssl-doctor/server-ssh-nginx.md
- commands-reference → Actual executed commands documented (local/remote, traced to source)   [✓ verified 2026-10-24 · v1] → projects/ssl-doctor/commands-reference.md
- evidence-based-probes → Endpoint states, comparable-only comparison, SNI observations, probe reconciliation, cause limitations   [✓ verified 2026-10-24 · v1] → projects/ssl-doctor/evidence-based-probes.md
- protocol-policy-evidence → Relaxed vs default cipher policy, per-version support classes, client-limited probes, contract 1.4   [✓ verified 2026-10-24 · v1] → projects/ssl-doctor/protocol-policy-evidence.md
- legacy-tls-diagnosis-semantics → default_probe states, Finding.uncertainty, diagnosis.unresolved, verify-first remediation, endpoint coverage, contract 1.5   [✓ done 2026-10-24 · v1] → projects/ssl-doctor/legacy-tls-diagnosis-semantics.md
- tls-handshake-attribution → failure_kind classification, stall retry, probe address pinning, network-vs-server attribution   [✓ verified 2026-10-24 · v1] → projects/ssl-doctor/tls-handshake-attribution.md
- ui-design-system → Claude Code-inspired theme, frames, prompts, spinner, plain-mode guarantees   [✓ verified 2026-10-24 · v1] → projects/ssl-doctor/ui-design-system.md
- _decisions → One-line decision log: colours, frames, static input, report pills   [✓ verified 2026-10-24 · v1] → projects/ssl-doctor/_decisions.md
