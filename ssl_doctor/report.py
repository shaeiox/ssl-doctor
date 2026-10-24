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


def write_json(path: str, findings: List[F.Finding],
               diagnosis: Optional[Diagnosis], meta: Dict[str, Any],
               secrets: Iterable[str] = (),
               facts: Optional[Dict[str, Any]] = None) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build_payload(findings, diagnosis, meta, secrets, facts), fh, indent=2,
                  default=str)


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
    from .analyze import Cause
    known = {f.name for f in dataclasses.fields(Cause)}
    return Diagnosis(causes=[Cause(**{k: v for k, v in c.items() if k in known})
                             for c in d["causes"]], notes=list(d["notes"]))


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
                         + (f'<div><b>Remediation:</b> {esc(c.recommendation)}</div>' if c.recommendation else "")
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
            parts.append(
                f"<tr><td>{_badge(f.status)}</td>"
                f"<td><b>{esc(f.title)}</b>"
                + (f'<div class=meta>target: {esc(f.target)} · check: <code class="check">{esc(f.check)}</code></div>' if f.target else f'<div class=meta>check: <code class="check">{esc(f.check)}</code></div>')
                + (f"<ul>{ev}</ul>" if ev else "")
                + (f"<div><i>{esc(f.detail)}</i></div>" if f.detail else "")
                + (f"<div><b>Recommendation:</b> {esc(f.recommendation)}</div>" if f.recommendation else "")
                + "</td></tr>")
        parts.append("</table></div>")

    parts.append(f'<div class="meta">Generated by {esc(APP_NAME)} v{esc(__version__)}. '
                 "All diagnostics were read-only; reports never contain credentials.</div>"
                 "</div></body></html>")
    return "\n".join(parts)
