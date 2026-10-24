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
:root{--pass:#1a7f37;--fail:#cf222e;--warn:#9a6700;--nt:#57606a;--bg:#f6f8fa}
*{box-sizing:border-box}
body{font-family:-apple-system,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;
margin:0;color:#1f2328;background:var(--bg)}
.wrap{max-width:1000px;margin:0 auto;padding:24px}
h1{font-size:22px;margin:0 0 4px}.sub{color:#57606a;font-size:13px;margin-bottom:16px}
.card{background:#fff;border:1px solid #d0d7de;border-radius:8px;padding:16px;
margin-bottom:16px}
.summary{display:flex;gap:12px;flex-wrap:wrap}
.pill{border-radius:999px;padding:6px 14px;font-weight:600;font-size:13px;color:#fff}
.p-PASS{background:var(--pass)}.p-FAIL{background:var(--fail)}
.p-WARNING{background:var(--warn)}.p-NT{background:var(--nt)}
.badge{display:inline-block;min-width:86px;text-align:center;border-radius:6px;
padding:2px 8px;font-size:11.5px;font-weight:700;color:#fff}
.b-PASS{background:var(--pass)}.b-FAIL{background:var(--fail)}
.b-WARNING{background:var(--warn)}.b-NT{background:var(--nt)}
.scopes td,.scopes th{border-bottom:1px solid #eaecef;padding:6px 10px;font-size:13px;
text-align:left;vertical-align:top}
table{border-collapse:collapse;width:100%}
ul{margin:6px 0 6px 18px;padding:0}li{margin:3px 0;font-size:13.5px}
.cause{border-left:4px solid var(--fail);padding:6px 12px;margin:10px 0;background:#fbfbfc}
.cause.warn{border-color:var(--warn)}
.meta{font-size:12.5px;color:#57606a}
code{background:#eaeef2;border-radius:4px;padding:1px 5px;font-size:12.5px}
h2{font-size:16px;margin:0 0 10px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;
white-space:pre-wrap;word-break:break-word}
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
            kind = (f" · failure: {esc(f.failure_kind)}" if f.failure_kind else "")
            parts.append(
                f"<tr><td>{_badge(f.status)}</td>"
                f"<td><b>{esc(f.title)}</b>"
                + (f"<div class=meta>target: {esc(f.target)} · check: {esc(f.check)}{kind}</div>" if f.target else f"<div class=meta>check: {esc(f.check)}{kind}</div>")
                + (f"<ul>{ev}</ul>" if ev else "")
                + (f"<div><i>{esc(f.detail)}</i></div>" if f.detail else "")
                + (f"<div><b>Recommendation:</b> {esc(f.recommendation)}</div>" if f.recommendation else "")
                + "</td></tr>")
        parts.append("</table></div>")

    parts.append(f'<div class="meta">Generated by {esc(APP_NAME)} v{esc(__version__)}. '
                 "All diagnostics were read-only; reports never contain credentials.</div>"
                 "</div></body></html>")
    return "\n".join(parts)
