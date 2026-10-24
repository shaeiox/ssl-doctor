"""Report rendering: JSON for tooling, self-contained HTML for humans."""

from __future__ import annotations

import dataclasses
import html
import json
import time
from typing import Any, Dict, Iterable, List, Optional

from . import APP_NAME, __version__
from . import contract
from . import findings as F
from .analyze import Diagnosis


def build_payload(findings: List[F.Finding], diagnosis: Optional[Diagnosis],
                  meta: Dict[str, Any], secrets: Iterable[str] = (),
                  facts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Findings-contract document; `secrets` are scrubbed before it is returned.

    `facts` is the optional structured block (see netchecks.export_facts).
    """
    counts = {F.PASS: 0, F.FAIL: 0, F.WARNING: 0, F.NOT_TESTED: 0}
    for f in findings:
        counts[f.status] = counts.get(f.status, 0) + 1
    return contract.redact({
        "schema_version": contract.SCHEMA_VERSION,
        "tool": f"{APP_NAME} {__version__}",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "meta": meta,
        "summary": counts,
        "diagnosis": diagnosis.to_dict() if diagnosis else None,
        "findings": [f.to_dict() for f in findings],
        "disclaimer": "All checks are read-only. No credentials are included in "
                      "this report.",
        **({"facts": facts} if facts else {}),
    }, secrets)


# The analysis prompt an agent report ends with. It is part of the feature's
# specification and is reproduced verbatim: report-specific detail belongs in
# the sections before it, never in edits to this text.
AGENT_ANALYSIS_PROMPT = """\
You are a senior TLS/PKI engineer and network troubleshooting specialist. Analyze the SSL Doctor report as evidence, not as unquestionable truth.

Your objective is to identify the most likely root cause of the reported problem, determine what is actually established by the available evidence, and recommend the safest next diagnostic steps.

Follow these rules:

1. Separate confirmed facts, probable explanations, unresolved hypotheses, and observations. Never present an unverified hypothesis as a confirmed root cause.

2. For every proposed root cause, provide:
   - A concise explanation.
   - Supporting evidence from the report.
   - Contradicting evidence or missing evidence.
   - Confidence level and justification.
   - The next test that would best confirm or reject it.

3. Interpret TLS protocol probes carefully. A successful handshake under a relaxed OpenSSL security policy does not, by itself, establish compatibility with ordinary clients. A `NO_PROTOCOLS_AVAILABLE` error can indicate a client-side limitation rather than a server rejection. Distinguish client limitations, server rejections, timeouts, and unreachable endpoints.

4. Evaluate certificate subject and SAN coverage, hostname matching, validity dates, trust-chain validation, intermediate certificates, SNI behavior, and differences between endpoints. Do not treat a different certificate without SNI as a defect by itself.

5. Interpret endpoint comparisons according to actual coverage. Do not generalize results from a subset of DNS addresses to all endpoints. Do not infer certificate mismatch when an endpoint never completed a comparable TLS handshake.

6. Distinguish TLS negotiation failures from HTTP redirects, application-layer errors, DNS problems, TCP connectivity failures, and local trust-store limitations.

7. Consider the local environment, including the operating system, OpenSSL version, proxy configuration, system clock, and client security policy. Explain how these factors may affect the observations.

8. Prioritize hypotheses by evidence strength and practical impact. Do not manufacture a root cause simply because the report contains a warning.

9. Recommend a minimal, ordered troubleshooting plan. Start with safe, read-only checks and tests that distinguish competing hypotheses. Explain what each test would prove and how to interpret its outcomes.

10. Recommend configuration changes only when evidence supports them. Identify the relevant component (for example, the TLS terminator, reverse proxy, load balancer, web server, certificate chain, or client trust store). Clearly distinguish verification steps from remediation steps.

11. Explicitly list the additional information required if the current report is insufficient. Never fabricate command output, server configuration, certificate properties, network conditions, or test results.

12. End with:
   - Most likely root cause, or state that the evidence is insufficient.
   - Confidence level.
   - Strongest supporting evidence.
   - Most important uncertainty.
   - Three prioritized next actions.
   - A clear statement of whether a server-side configuration change is justified by the current evidence.

Use precise technical language. Be concise but thorough. Reference exact report fields and observed values whenever possible.
"""


# Scan facts an agent report carries in `meta`; the contract's `facts` block
# keeps only the monitoring subset (see netchecks.export_facts).
_AGENT_SCAN_KEYS = ("host", "port", "sni", "ips", "handshake_ip", "protocol",
                    "cipher", "final_url")


def _iso(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def agent_environment() -> Dict[str, Any]:
    """The reporting process's own runtime (the CLI ran the scan in it)."""
    import platform
    import ssl
    return {"tool": f"{APP_NAME} {__version__}",
            "python": platform.python_version(),
            "openssl": ssl.OPENSSL_VERSION,
            "platform": platform.platform()}


def agent_meta(meta: Dict[str, Any], scan_facts: Dict[str, Any],
               findings: List[F.Finding],
               environment: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """`meta` for an agent report: the run context plus what the scan observed.

    Values the scan did not record are `None`, never inferred. `local.os`
    evidence, when present, is the scan-time record of the client machine.
    """
    local_os = next((f for f in reversed(findings) if f.check == "local.os"), None)
    env = dict(environment if environment is not None else agent_environment())
    env["local_os_evidence"] = list(local_os.evidence) if local_os else None
    stamps = [f.ts for f in findings]
    scan = {key: scan_facts.get(key) for key in _AGENT_SCAN_KEYS}
    scan.update({
        "first_finding_utc": _iso(min(stamps)) if stamps else None,
        "last_finding_utc": _iso(max(stamps)) if stamps else None,
        "targets": list(dict.fromkeys(f.target for f in findings if f.target)),
    })
    return {**meta, "report_kind": "agent", "agent_report": {
        "scan": scan,
        "environment": env,
        "configuration": {key: meta.get(key) for key in
                          ("network_timeout", "command_timeout", "ssh_connected")},
    }}


def write_json(path: str, findings: List[F.Finding],
               diagnosis: Optional[Diagnosis], meta: Dict[str, Any],
               secrets: Iterable[str] = (),
               facts: Optional[Dict[str, Any]] = None) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build_payload(findings, diagnosis, meta, secrets, facts), fh, indent=2,
                  default=str)


# ------------------------------------------------------------- agent report
#
# The Markdown is rendered only from the redacted contract document that is
# also written as agent-report.json, so both files describe the same scan and
# the renderer cannot reach anything the JSON lacks. Every sentence that is not
# a value from that document is fixed framing; nothing here interprets results.

# Evidence areas, in report order: (heading, check-id prefixes, empty text)
_AGENT_AREAS = (
    ("DNS and TCP connectivity", ("net.dns", "net.tcp"),
     "no DNS/TCP finding in this session"),
    ("TLS handshake", ("tls.handshake",), "no TLS handshake finding in this session"),
    ("Certificate and trust", ("tls.certvalid", "tls.hostname", "tls.chain",
                               "tls.verify", "cert."),
     "no certificate or trust finding in this session"),
    ("SNI behaviour", ("tls.sni",), "SNI behaviour was not collected in this session"),
    ("Protocol-version probes", ("tls.protocols",),
     "protocol-version probes were not run in this session"),
    ("Cipher acceptance", ("tls.weakcipher",),
     "cipher acceptance was not tested in this session"),
    ("Endpoint comparison", ("tls.multiip",),
     "endpoint comparison was not run in this session"),
    ("HTTPS response and redirects", ("https.",),
     "the HTTPS layer was not checked in this session"),
    ("Local machine checks", ("local.",), "no local machine checks were run (/local)"),
    ("Server-side checks (authorized, read-only)", ("ssh.", "srv.", "nginx."),
     "no server-side checks were run (no authorized SSH session)"),
)

_SUPPORT_LABELS = {
    "default": "accepted with this client's default settings",
    "relaxed-only": "accepted only under the relaxed policy; a default-configured "
                    "probe was refused by the server",
    "relaxed-only-unverified": "accepted only under the relaxed policy; the "
                               "default-settings probe produced no server answer, so "
                               "ordinary-client compatibility is NOT established",
    "rejected": "refused by the server",
    "inconclusive": "no definite result - no conclusion about server support",
}

_DEFAULT_PROBE_LABELS = {
    "accepted": "accepted with this client's default settings",
    "refused": "refused - the server answered with an error",
    "client-limited": "not sent - this client could not offer the version under its "
                      "default settings; a limitation of this client, not a server "
                      "rejection",
    "inconclusive": "no definite answer (timeout or local error) - no conclusion",
    "unsupported": "this Python/OpenSSL build cannot pin the version",
}

_UNREACHED_ENDPOINT_STATES = ("tcp-unreachable", "timed-out")


def _fence(lines: Iterable[str], indent: str = "  ") -> List[str]:
    """Verbatim text in a fenced block, so values are never read as Markdown."""
    lines = [str(line) for line in lines]
    fence = "````" if any("```" in line for line in lines) else "```"
    return [f"{indent}{fence}text", *(f"{indent}{line}" for line in lines),
            f"{indent}{fence}"]


def _value(value: Any) -> str:
    """A recorded value; `None` is "not recorded", an empty list is "none"."""
    if value is None or value == "":
        return "not recorded"
    if isinstance(value, list):
        if not value:
            return "none"
        return ", ".join(f"`{v}`" for v in value)
    return f"`{value}`"


def _agent_finding(f: Dict[str, Any]) -> List[str]:
    target = f" · target `{f['target']}`" if f.get("target") else ""
    out = [f"- **{f['status']}** · `{f['check']}` · {f['title']} "
           f"(scope: {f['scope']}{target})"]
    if f.get("evidence"):
        out += ["  - evidence:", *_fence(f["evidence"], "    ")]
    if f.get("failure_kind"):
        meaning = contract.FAILURE_KINDS.get(f["failure_kind"], "")
        out.append(f"  - failure kind: `{f['failure_kind']}` - {meaning}")
    if f.get("observation"):
        meaning = contract.OBSERVATIONS.get(f["observation"], "")
        out.append(f"  - observation: `{f['observation']}` - {meaning}")
    for line in f.get("uncertainty") or []:
        out.append(f"  - uncertainty: {line}")
    if f.get("detail"):
        out += ["  - detail:", *_fence([f["detail"]], "    ")]
    if f.get("recommendation"):
        out.append(f"  - recorded remediation: {f['recommendation']}")
    return out


def _probe_policy_lines(policy: Optional[Dict[str, Any]]) -> List[str]:
    from .netchecks import _RELAXED_CIPHER_POLICY
    if not policy:
        return []
    out = ["", f"Probe policy: versions in `relaxed_versions` "
               f"({_value(policy.get('relaxed_versions'))}) are probed first with "
               f"SSL Doctor's relaxed cipher policy `{_RELAXED_CIPHER_POLICY}`; a "
               f"version that answers is probed again with this client's default "
               f"settings. Negotiated by the primary handshake: "
               f"{_value(policy.get('negotiated'))}.", "",
           "| Version | Support class | Default-settings probe |", "|---|---|---|"]
    defaults = policy.get("default_probe") or {}
    for version, cls in (policy.get("support") or {}).items():
        state = defaults.get(version)
        probe = (f"`{state}` - {_DEFAULT_PROBE_LABELS.get(state, '')}" if state
                 else "not run (only versions that answered are re-probed)")
        out.append(f"| {version} | `{cls}` - {_SUPPORT_LABELS.get(cls, '')} | {probe} |")
    out += ["", f"Deprecated versions confirmed for ordinary clients: "
                f"{_value(policy.get('confirmed_legacy'))}. Deprecated versions "
                f"accepted only under the relaxed policy and unverified for ordinary "
                f"clients: {_value(policy.get('unverified_legacy'))}."]
    return out


def _endpoint_lines(facts: Dict[str, Any]) -> List[str]:
    cmp_ = facts.get("endpoint_comparison")
    if not cmp_:
        return []
    endpoints = facts.get("endpoints") or []
    reachable = sum(1 for e in endpoints if e.get("state") not in _UNREACHED_ENDPOINT_STATES)
    addresses = cmp_.get("addresses")
    out = ["", f"Coverage: {addresses if addresses is not None else 'not recorded'} "
               f"address(es) resolved, {cmp_.get('probed', 0)} probed, {reachable} "
               f"reachable, {cmp_.get('comparable', 0)} comparable "
               f"(completed a handshake for the same server name). Results apply to "
               f"the comparable endpoints only.", ""]
    if cmp_.get("difference"):
        out.append(f"Measured difference in: {cmp_.get('attribute') or 'not recorded'}.")
    for e in endpoints:
        detail = f" - {e['detail']}" if e.get("detail") else ""
        out.append(f"- `{e.get('ip')}`: `{e.get('state') or 'unknown'}`{detail}")
    return out


def _cause_lines(c: Dict[str, Any]) -> List[str]:
    out = [f"- **{c['certainty'].upper()}** (rank {c['rank']}, origin: {c['origin']}): "
           f"{c['summary']}"]
    if c.get("evidence"):
        out += ["  - supporting evidence:", *_fence(c["evidence"], "    ")]
    out.append("  - contradicting evidence: SSL Doctor did not record contradicting "
               "evidence for this cause.")
    for lim in c.get("limitations") or []:
        out.append(f"  - limitation: {lim}")
    if c.get("recommendation"):
        out.append(f"  - recorded remediation: {c['recommendation']}")
    return out


def agent_markdown(payload: Dict[str, Any]) -> str:
    """Render agent-report.md from the (redacted) contract document."""
    meta = payload.get("meta") or {}
    agent = meta.get("agent_report") or {}
    scan, env = agent.get("scan") or {}, agent.get("environment") or {}
    conf = agent.get("configuration") or {}
    findings = payload.get("findings") or []
    facts = payload.get("facts") or {}
    diag = payload.get("diagnosis") or {"overall": "not computed", "causes": [],
                                        "notes": [], "unresolved": []}
    causes, unresolved = diag.get("causes") or [], diag.get("unresolved") or []
    counts = payload.get("summary") or {}
    target = (f"{scan.get('host')}:{scan.get('port')}" if scan.get("host")
              else meta.get("target") or "not recorded")
    by_certainty = {k: [c for c in causes if c.get("certainty") == k]
                    for k in ("confirmed", "probable", "possible")}
    lines: List[str] = [f"# SSL Doctor agent report - {target}", ""]

    lines += ["## 1. Report metadata", "",
              f"- SSL Doctor version: {payload.get('tool', 'not recorded')}",
              f"- Report schema version: findings/{payload.get('schema_version')}",
              f"- Report generated (UTC): {payload.get('generated_utc')}",
              f"- Scan findings recorded (UTC): {scan.get('first_finding_utc') or 'not recorded'}"
              f" to {scan.get('last_finding_utc') or 'not recorded'}",
              f"- Target: `{target}` (SNI: {_value(scan.get('sni'))})",
              f"- Targets of all findings in this session: {_value(scan.get('targets'))}",
              f"- Scan configuration: network timeout {_value(conf.get('network_timeout'))} s, "
              f"remote command timeout {_value(conf.get('command_timeout'))} s, "
              f"SSH session connected: {_value(conf.get('ssh_connected'))}",
              f"- Execution environment: Python {_value(env.get('python'))}, "
              f"{_value(env.get('openssl'))}, platform {_value(env.get('platform'))}",
              "- Source: every value below comes from the companion "
              "`agent-report.json` (same scan, same redaction). SSL Doctor's checks are "
              "read-only; nothing was re-measured to produce this report.", ""]

    lines += ["## 2. Executive summary", "",
              f"- Overall status (from SSL Doctor's diagnosis): **{diag.get('overall')}** "
              f"(derived from causes only; a warning without a justified cause is listed "
              f"as an unresolved finding, not folded into this status)",
              f"- Checks: {counts.get(F.PASS, 0)} PASS · {counts.get(F.FAIL, 0)} FAIL · "
              f"{counts.get(F.WARNING, 0)} WARNING · {counts.get(F.NOT_TESTED, 0)} NOT TESTED",
              f"- Confirmed causes: {len(by_certainty['confirmed'])} · probable causes: "
              f"{len(by_certainty['probable'])} · possible causes (hypotheses): "
              f"{len(by_certainty['possible'])} · unresolved findings: {len(unresolved)}"]
    for c in causes:
        lines.append(f"  - {c['certainty']}: {c['summary']}")
    for u in unresolved:
        lines.append(f"  - unresolved (`{u['check']}`, {u['status']}): {u['observed']}")
    lines.append("")

    lines += ["## 3. Target and environment", "",
              f"- Hostname: {_value(scan.get('host'))} · port: {_value(scan.get('port'))} "
              f"· SNI sent: {_value(scan.get('sni'))}",
              f"- Resolved addresses: {_value(scan.get('ips'))}",
              f"- Address the TLS probes connected to: {_value(scan.get('handshake_ip'))}",
              f"- Negotiated protocol / cipher: {_value(scan.get('protocol'))} / "
              f"{_value(scan.get('cipher'))}",
              f"- Final URL after redirects: {_value(scan.get('final_url'))}",
              f"- Reporting process: {_value(env.get('tool'))}, Python "
              f"{_value(env.get('python'))}, {_value(env.get('openssl'))}, "
              f"{_value(env.get('platform'))}"]
    if env.get("local_os_evidence"):
        lines += ["- Client machine at scan time (`local.os`):",
                  *_fence(env["local_os_evidence"])]
    else:
        lines.append("- Client machine at scan time: not collected (`/local` did not run)")
    lines.append("")

    lines += ["## 4. Detailed evidence", ""]
    placed = set()
    for heading, prefixes, empty in _AGENT_AREAS:
        group = [f for f in findings
                 if any(f["check"] == p or (p.endswith(".") and f["check"].startswith(p))
                        for p in prefixes)]
        placed.update(id(f) for f in group)
        lines += [f"### {heading}", ""]
        if not group:
            lines += [f"- {empty}.", ""]
        for f in group:
            lines += _agent_finding(f)
        if heading == "Protocol-version probes":
            lines += _probe_policy_lines(facts.get("probe_policy"))
        if heading == "Endpoint comparison":
            lines += _endpoint_lines(facts)
        if group:
            lines.append("")
    rest = [f for f in findings if id(f) not in placed]
    if rest:
        lines += ["### Other findings", ""]
        for f in rest:
            lines += _agent_finding(f)
        lines.append("")

    lines += ["## 5. Findings and diagnosis", "",
              "Observations are what the checks recorded. Possible causes are "
              "hypotheses; probable and confirmed causes carry SSL Doctor's stated "
              "certainty. Unresolved findings are warnings for which no cause is "
              "justified by the evidence.", "",
              "### 5.1 Observations (status of every check)", ""]
    for f in findings:
        lines.append(f"- {f['status']} · `{f['check']}` · {f['title']}")
    for title, key in (("5.2 Confirmed causes", "confirmed"),
                       ("5.3 Probable causes", "probable"),
                       ("5.4 Possible causes (hypotheses)", "possible")):
        lines += ["", f"### {title}", ""]
        group = by_certainty[key]
        if not group:
            lines.append("- none recorded")
        for c in group:
            lines += _cause_lines(c)
    lines += ["", "### 5.5 Unresolved findings", ""]
    if not unresolved:
        lines.append("- none recorded")
    for u in unresolved:
        lines.append(f"- `{u['check']}` ({u['status']}"
                     + (f", observation `{u['observation']}`" if u.get("observation") else "")
                     + ")")
        lines.append(f"  - observed: {u['observed']}")
        lines.append(f"  - supported conclusion: {u['conclusion']}")
        for unc in u.get("uncertainty") or []:
            lines.append(f"  - uncertainty: {unc}")
        if u.get("recommendation"):
            lines.append(f"  - recorded next step: {u['recommendation']}")
    failed = [f for f in findings if f["status"] in (F.FAIL, F.NOT_TESTED)
              or f.get("failure_kind")]
    lines += ["", "### 5.6 Failed or inconclusive probes", ""]
    if not failed:
        lines.append("- none recorded")
    for f in failed:
        kind = f" · failure kind `{f['failure_kind']}`" if f.get("failure_kind") else ""
        lines.append(f"- {f['status']} · `{f['check']}` · {f['title']}{kind}")
    lines += ["", "### 5.7 Diagnosis notes", ""]
    lines += [f"- {n}" for n in diag.get("notes") or []] or ["- none recorded"]
    lines.append("")

    lines += ["## 6. Recommended next steps", "",
              "SSL Doctor's recorded guidance, in this order: causes, unresolved "
              "findings, then individual findings. Prefer the read-only verification "
              "steps first; a configuration change is supported only where a recorded "
              "cause calls for it.", ""]
    steps = list(dict.fromkeys(
        [c["recommendation"] for c in causes if c.get("recommendation")]
        + [u["recommendation"] for u in unresolved if u.get("recommendation")]
        + [f["recommendation"] for f in findings if f.get("recommendation")]))
    lines += [f"{i}. {step}" for i, step in enumerate(steps, 1)] or ["- none recorded"]
    lines += ["", "### Missing evidence", ""]
    missing = list(dict.fromkeys(
        [f"`{u['check']}`: {unc}" for u in unresolved for unc in u.get("uncertainty") or []]
        + [f"`{f['check']}`: {unc}" for f in findings for unc in f.get("uncertainty") or []]
        + [f"`{f['check']}` was NOT TESTED"
           + (f": {f['evidence'][0]}" if f.get("evidence") else "")
           for f in findings if f["status"] == F.NOT_TESTED]))
    lines += [f"- {m}" for m in missing] or ["- none recorded"]
    lines.append("")

    lines += ["## 7. AI analysis instructions", "",
              "Give this whole file to the AI model. The prompt below is reproduced "
              "verbatim; the sections above are the report it refers to.", "",
              AGENT_ANALYSIS_PROMPT]
    return "\n".join(lines)


AGENT_REPORT_FILES = ("agent-report.md", "agent-report.json")


def write_agent_report(directory: str, markdown: str, json_text: str) -> List[str]:
    """Write both agent-report files into `directory`, or neither.

    Existing report files are never overwritten. Both are written to temporary
    files first and moved into place; on any error everything this call created
    (temporary files, moved files, a directory it made) is removed and the
    error is re-raised. Returns the two paths (Markdown, JSON).
    """
    import errno
    import os
    import tempfile
    paths = [os.path.join(directory, name) for name in AGENT_REPORT_FILES]
    for path in paths:
        if os.path.exists(path):
            raise FileExistsError(errno.EEXIST, "a report already exists", path)
    made_dir = not os.path.isdir(directory)
    os.makedirs(directory, exist_ok=True)
    created: List[str] = []
    try:
        temps = []
        for text in (markdown, json_text):
            fd, tmp = tempfile.mkstemp(prefix=".agent-report-", dir=directory)
            created.append(tmp)
            temps.append(tmp)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
        for tmp, path in zip(temps, paths):
            os.replace(tmp, path)
            created[created.index(tmp)] = path
    except BaseException:
        for path in created:
            try:
                os.unlink(path)
            except OSError:
                pass
        if made_dir:
            try:
                os.rmdir(directory)
            except OSError:
                pass
        raise
    return paths


_CSS = """
/* Claude Code-inspired skin: warm terracotta accent, hot-pink identifiers and
   status colours from the same roles the terminal uses. Light, printable and
   fully inline — a report must render with no network access. */
:root{
  --ink:#1f2328;--muted:#57534e;--rule:#e7e0d8;--bg:#faf7f4;--card:#fff;
  --accent:#d77757;--tool:#fd5db1;
  --pass:#4eba65;--warn:#ffc107;--fail:#ff6b80;--nt:#888888;
  --pill-ink:#1a1a1a;
}
*{box-sizing:border-box}
body{font-family:-apple-system,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;
margin:0;color:var(--ink);background:var(--bg);font-size:14px;line-height:1.5}
.wrap{max-width:1000px;margin:0 auto;padding:24px}
h1{font-size:23px;margin:0 0 10px;font-weight:700;letter-spacing:-.01em;
color:var(--ink);border-bottom:2px solid var(--accent);padding-bottom:10px}
.sub{color:var(--muted);font-size:13px;margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--rule);border-radius:10px;
padding:18px;margin-bottom:16px;box-shadow:0 1px 2px rgba(31,35,40,.04)}
.summary{display:flex;gap:10px;flex-wrap:wrap}
.pill{border-radius:999px;padding:6px 14px;font-weight:600;font-size:13px;
color:var(--pill-ink)}
.p-PASS{background:var(--pass)}.p-FAIL{background:var(--fail)}
.p-WARNING{background:var(--warn)}.p-NT{background:var(--nt)}
.badge{display:inline-block;min-width:86px;text-align:center;border-radius:6px;
padding:3px 8px;font-size:11.5px;font-weight:700;
color:var(--pill-ink);letter-spacing:.02em}
.b-PASS{background:var(--pass)}.b-FAIL{background:var(--fail)}
.b-WARNING{background:var(--warn)}.b-NT{background:var(--nt)}
.scopes td,.scopes th{border-bottom:1px dashed var(--rule);padding:8px 10px;
font-size:13px;text-align:left;vertical-align:top}
.scopes tr:last-child td{border-bottom:none}
table{border-collapse:collapse;width:100%}
ul{margin:6px 0 6px 18px;padding:0}li{margin:3px 0;font-size:13.5px}
.cause{border-left:4px solid var(--fail);padding:8px 14px;margin:12px 0;
background:#fff8f6;border-radius:0 8px 8px 0}
.cause.warn{border-color:var(--warn);background:#fffbf0}
.meta{font-size:12.5px;color:var(--muted)}
code,code.check{background:#f3ece5;border-radius:4px;padding:1px 5px;
font-size:12.5px}
code.check{background:none;padding:0;color:var(--tool);font-weight:600}
h2{font-size:16px;margin:0 0 12px;font-weight:700}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
font-size:12.5px;white-space:pre-wrap;word-break:break-word}
"""


def _diagnosis_from(d: Optional[Dict[str, Any]]) -> Optional[Diagnosis]:
    if not d:
        return None
    from .analyze import Cause, Unresolved
    known = {f.name for f in dataclasses.fields(Cause)}
    known_u = {f.name for f in dataclasses.fields(Unresolved)}
    return Diagnosis(causes=[Cause(**{k: v for k, v in c.items() if k in known})
                             for c in d["causes"]], notes=list(d["notes"]),
                     unresolved=[Unresolved(**{k: v for k, v in u.items() if k in known_u})
                                 for u in d.get("unresolved", [])])


def _badge(status: str) -> str:
    cls = "b-NT" if status == F.NOT_TESTED else "b-" + status.split()[0]
    return f'<span class="badge {cls}">{html.escape(status)}</span>'


def write_html(path: str, findings: List[F.Finding],
               diagnosis: Optional[Diagnosis], meta: Dict[str, Any],
               secrets: Iterable[str] = (),
               facts: Optional[Dict[str, Any]] = None) -> None:
    payload = build_payload(findings, diagnosis, meta, secrets, facts)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html_from_payload(payload))


def html_from_payload(payload: Dict[str, Any]) -> str:
    """Render a (redacted) findings-contract document as self-contained HTML."""
    meta = payload.get("meta") or {}
    counts = payload["summary"]
    esc = html.escape
    # render from the redacted document, never from the raw objects
    # contract minor versions may add fields: keep only the ones we know
    known = {f.name for f in dataclasses.fields(F.Finding)}
    findings = [F.Finding(**{k: v for k, v in d.items() if k in known})
                for d in payload["findings"]]
    diagnosis = _diagnosis_from(payload["diagnosis"])

    scope_names = {F.SCOPE_LOCAL: "Local machine checks",
                   F.SCOPE_REMOTE_NET: "Remote network checks",
                   F.SCOPE_SERVER: "Server-side checks (via SSH)"}

    parts: List[str] = []
    parts.append(f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>{esc(APP_NAME)} report</title><style>{_CSS}</style></head><body><div class="wrap">
<h1>{esc(APP_NAME)} — diagnostic report</h1>
<div class="sub">generated {esc(payload['generated_utc'])} ·
{esc(str(meta.get('target') or 'no target'))} · tool version {esc(__version__)}</div>""")

    parts.append('<div class="card"><div class="summary">'
                 f'<span class="pill p-PASS">PASS {counts.get(F.PASS, 0)}</span>'
                 f'<span class="pill p-FAIL">FAIL {counts.get(F.FAIL, 0)}</span>'
                 f'<span class="pill p-WARNING">WARNING {counts.get(F.WARNING, 0)}</span>'
                 f'<span class="pill p-NT">NOT TESTED {counts.get(F.NOT_TESTED, 0)}</span>'
                 "</div></div>")

    if diagnosis:
        parts.append('<div class="card"><h2>Diagnosis</h2>')
        if not diagnosis.causes:
            parts.append('<p>No confirmed or probable root causes identified.</p>')
        for c in diagnosis.causes:
            cls = "cause warn" if c.certainty == "possible" else "cause"
            parts.append(f'<div class="{cls}"><b>#{c.rank} [{esc(c.certainty.upper())} · '
                         f'{esc(c.origin)}]</b> {esc(c.summary)}'
                         + (f'<ul>{"".join(f"<li class=mono>{esc(e[:400])}</li>" for e in c.evidence)}</ul>' if c.evidence else "")
                         + (f'<ul>{"".join(f"<li><i>limitation: {esc(l)}</i></li>" for l in c.limitations)}</ul>' if c.limitations else "")
                         + (f'<div><b>Remediation:</b> {esc(c.recommendation)}</div>' if c.recommendation else "")
                         + "</div>")
        for u in diagnosis.unresolved:
            parts.append(f'<div class="cause warn"><b>[UNRESOLVED · {esc(u.check)}]</b> '
                         f'{esc(u.observed)}<div><b>Conclusion:</b> {esc(u.conclusion)}</div>'
                         + (f'<ul>{"".join(f"<li><i>uncertainty: {esc(x)}</i></li>" for x in u.uncertainty)}</ul>' if u.uncertainty else "")
                         + (f'<div><b>Next step:</b> {esc(u.recommendation)}</div>' if u.recommendation else "")
                         + "</div>")
        if diagnosis.notes:
            parts.append("<ul>" + "".join(f"<li>{esc(n)}</li>" for n in diagnosis.notes) + "</ul>")
        parts.append("</div>")

    for scope, heading in scope_names.items():
        items = [f for f in findings if f.scope == scope]
        if not items:
            continue
        parts.append(f'<div class="card"><h2>{esc(heading)}</h2><table class="scopes">')
        for f in items:
            ev = "".join(f"<li class=mono>{esc(e[:400])}</li>" for e in f.evidence)
            kind = (f" · failure: {esc(f.failure_kind)}" if f.failure_kind else "")
            kind += (f" · observation: {esc(f.observation)}" if f.observation else "")
            parts.append(
                f"<tr><td>{_badge(f.status)}</td>"
                f"<td><b>{esc(f.title)}</b>"
                + (f'<div class=meta>target: {esc(f.target)} · check: <code class="check">{esc(f.check)}</code>{kind}</div>' if f.target else f'<div class=meta>check: <code class="check">{esc(f.check)}</code>{kind}</div>')
                + (f"<ul>{ev}</ul>" if ev else "")
                + (f"<div><i>{esc(f.detail)}</i></div>" if f.detail else "")
                + (f"<div><b>Recommendation:</b> {esc(f.recommendation)}</div>" if f.recommendation else "")
                + "</td></tr>")
        parts.append("</table></div>")

    parts.append(f'<div class="meta">Generated by {esc(APP_NAME)} v{esc(__version__)}. '
                 "All diagnostics were read-only; reports never contain credentials.</div>"
                 "</div></body></html>")
    return "\n".join(parts)
