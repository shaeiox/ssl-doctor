"""Server-rendered dashboard: targets, scan history, diagnosis, report export.

No JavaScript framework or CDN: works air-gapped, and every value is
HTML-escaped. Sign-in exchanges an API token for an HttpOnly, SameSite=Strict
cookie (replaced by SSO sign-in in identity-access). Queries carry explicit
org predicates and run under RLS, like the API.
"""

from __future__ import annotations

import html
from typing import Callable, Optional
from uuid import UUID

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .db import Database
from .render import document_html

COOKIE = "ssldoctor_session"
esc = html.escape

_CSS = """
:root{--pass:#1a7f37;--fail:#cf222e;--warn:#9a6700;--nt:#57606a;--bg:#f6f8fa;--line:#d0d7de}
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,'Segoe UI',Roboto,Arial,
sans-serif;color:#1f2328;background:var(--bg)}header{background:#fff;border-bottom:1px solid
var(--line);padding:12px 24px;display:flex;justify-content:space-between;align-items:center}
main{max-width:1000px;margin:0 auto;padding:24px}h1{font-size:20px;margin:0 0 16px}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line);
border-radius:8px}td,th{padding:8px 12px;border-bottom:1px solid #eaecef;text-align:left;
font-size:14px}a{color:#0969da}.b{display:inline-block;min-width:72px;text-align:center;
border-radius:6px;padding:2px 8px;font-size:12px;font-weight:700;color:#fff;background:var(--nt)}
.b-PASS{background:var(--pass)}.b-FAIL{background:var(--fail)}.b-WARNING{background:var(--warn)}
form.inline{display:inline}button{font:inherit;padding:4px 12px;border-radius:6px;border:1px
solid var(--line);background:#fff;cursor:pointer}.muted{color:#57606a;font-size:13px}
input{font:inherit;padding:6px 10px;border:1px solid var(--line);border-radius:6px;width:100%}
.card{background:#fff;border:1px solid var(--line);border-radius:8px;padding:16px;max-width:420px}
@media (max-width:640px){main{padding:16px}td,th{padding:6px}}
"""


def _page(title: str, body: str, signed_in: bool = True) -> HTMLResponse:
    nav = ('<nav><a href="/ui">Targets</a> · <a href="/ui/logout">Sign out</a></nav>'
           if signed_in else "")
    return HTMLResponse(
        f"<!doctype html><html><head><meta charset=utf-8>"
        f"<meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>{esc(title)} · SSL Doctor</title><style>{_CSS}</style></head><body>"
        f"<header><b>SSL Doctor</b>{nav}</header><main>{body}</main></body></html>")


def _badge(overall: Optional[str]) -> str:
    return f'<span class="b b-{esc(overall or "")}">{esc(overall or "pending")}</span>'


def mount_ui(app: FastAPI, db: Database, resolve_member: Callable,
             permissions: dict) -> None:

    def current(request: Request):
        token = request.cookies.get(COOKIE)
        m = resolve_member(token) if token else None
        if not m:
            raise HTTPException(303, headers={"Location": "/ui/login"})
        return m

    def can(m, perm: str) -> bool:
        return perm in permissions.get(m.role, set())

    @app.get("/ui/login", response_class=HTMLResponse)
    def login_form(error: str = ""):
        msg = f'<p style="color:var(--fail)">{esc(error)}</p>' if error else ""
        return _page("Sign in", f"""<div class=card><h1>Sign in</h1>{msg}
            <form method=post action=/ui/login><label>API token<br>
            <input type=password name=token autocomplete=off required></label>
            <p><button type=submit>Sign in</button></p></form></div>""", signed_in=False)

    @app.post("/ui/login")
    def login(request: Request, token: str = Form(...)):
        if not resolve_member(token):
            return RedirectResponse("/ui/login?error=Invalid+or+revoked+token", 303)
        resp = RedirectResponse("/ui", 303)
        resp.set_cookie(COOKIE, token, httponly=True, samesite="strict",
                        secure=request.url.scheme == "https", max_age=8 * 3600)
        return resp

    @app.get("/ui/logout")
    def logout():
        resp = RedirectResponse("/ui/login", 303)
        resp.delete_cookie(COOKIE)
        return resp

    @app.get("/ui", response_class=HTMLResponse)
    def targets_page(request: Request):
        m = current(request)
        with db.org(m.org_id) as conn:
            rows = conn.execute(
                "SELECT t.id, t.host, t.port, t.sni, r.overall, r.created_at "
                "FROM app.targets t LEFT JOIN LATERAL (SELECT overall, created_at "
                "FROM app.scan_results WHERE target_id = t.id AND org_id = t.org_id "
                "ORDER BY created_at DESC LIMIT 1) r ON true "
                "WHERE t.org_id = %s ORDER BY t.host", (m.org_id,)).fetchall()
        body = "".join(
            f"<tr><td><a href='/ui/targets/{r['id']}'>{esc(r['host'])}:{r['port']}</a>"
            f"{' <span class=muted>SNI ' + esc(r['sni']) + '</span>' if r['sni'] else ''}"
            f"</td><td>{_badge(r['overall'])}</td>"
            f"<td class=muted>{esc(str(r['created_at'] or '—'))[:19]}</td><td>"
            + (f"<form class=inline method=post action='/ui/targets/{r['id']}/scan'>"
               "<button>Scan now</button></form>" if can(m, "scan") else "")
            + "</td></tr>" for r in rows) or "<tr><td colspan=4>No targets yet.</td></tr>"
        return _page("Targets", "<h1>Targets</h1><table><tr><th>Target</th><th>Last "
                                f"result</th><th>When</th><th></th></tr>{body}</table>")

    @app.get("/ui/targets/{target_id}", response_class=HTMLResponse)
    def target_page(request: Request, target_id: UUID):
        m = current(request)
        with db.org(m.org_id) as conn:
            t = conn.execute("SELECT * FROM app.targets WHERE id = %s AND org_id = %s",
                             (target_id, m.org_id)).fetchone()
            if not t:
                raise HTTPException(404, "target not found")
            results = conn.execute(
                "SELECT id, overall, created_at FROM app.scan_results WHERE target_id = %s "
                "AND org_id = %s ORDER BY created_at DESC", (target_id, m.org_id)).fetchall()
            jobs = conn.execute(
                "SELECT j.status, j.kind, j.error, j.created_at, a.name FROM app.scan_jobs j "
                "JOIN app.agents a ON a.id = j.agent_id WHERE j.target_id = %s AND "
                "j.org_id = %s AND j.status IN ('queued','running','not_runnable','failed') "
                "ORDER BY j.created_at DESC LIMIT 10", (target_id, m.org_id)).fetchall()
        hist = "".join(
            f"<tr><td><a href='/ui/results/{r['id']}'>{esc(str(r['created_at']))[:19]}</a>"
            f"</td><td>{_badge(r['overall'])}</td><td>"
            + (f"<a href='/ui/compare?a={results[i + 1]['id']}&b={r['id']}'>compare with "
               "previous</a>" if i + 1 < len(results) else "")
            + "</td></tr>" for i, r in enumerate(results)) \
            or "<tr><td colspan=3>No results yet.</td></tr>"
        pending = "".join(f"<li>{esc(j['kind'])} job on {esc(j['name'])}: "
                          f"<b>{esc(j['status'])}</b>"
                          f"{' — ' + esc(j['error']) if j['error'] else ''}</li>" for j in jobs)
        scan = (f"<form class=inline method=post action='/ui/targets/{target_id}/scan'>"
                "<button>Scan now</button></form>" if can(m, "scan") else "")
        return _page(t["host"], f"<h1>{esc(t['host'])}:{t['port']} {scan}</h1>"
                     + (f"<ul>{pending}</ul>" if pending else "")
                     + "<table><tr><th>Scan</th><th>Overall</th><th></th></tr>"
                     f"{hist}</table>")

    @app.post("/ui/targets/{target_id}/scan")
    def ui_scan(request: Request, target_id: UUID):
        m = current(request)
        if not can(m, "scan"):
            raise HTTPException(403, f"role '{m.role}' may not scan")
        with db.org(m.org_id) as conn:
            if not conn.execute("SELECT 1 FROM app.targets WHERE id = %s AND org_id = %s",
                                (target_id, m.org_id)).fetchone():
                raise HTTPException(404, "target not found")
            from .monitor import enqueue_scan
            enqueue_scan(conn, m.org_id, target_id)
        return RedirectResponse(f"/ui/targets/{target_id}", 303)

    @app.get("/ui/results/{result_id}", response_class=HTMLResponse)
    def result_page(request: Request, result_id: UUID):
        m = current(request)
        with db.org(m.org_id) as conn:
            r = conn.execute("SELECT document FROM app.scan_results WHERE id = %s AND "
                             "org_id = %s", (result_id, m.org_id)).fetchone()
        if not r:
            raise HTTPException(404, "result not found")
        links = (f"<p class=muted>Export: <a href='/ui/results/{result_id}/export.json'>JSON"
                 f"</a> · <a href='/ui/results/{result_id}/export.html'>HTML</a></p>")
        report = document_html(r["document"])
        inner = report[report.find("<div class=\"wrap\">"):report.rfind("</body>")]
        return _page("Result", links + inner)

    @app.get("/ui/compare", response_class=HTMLResponse)
    def compare_page(request: Request, a: UUID, b: UUID):
        m = current(request)
        with db.org(m.org_id) as conn:
            docs = {}
            for key, rid in (("a", a), ("b", b)):
                r = conn.execute("SELECT overall, created_at, document FROM app.scan_results "
                                 "WHERE id = %s AND org_id = %s", (rid, m.org_id)).fetchone()
                if not r:
                    raise HTTPException(404, "result not found")
                docs[key] = r
        sa = {f["check"]: f["status"] for f in docs["a"]["document"]["findings"]}
        sb = {f["check"]: f["status"] for f in docs["b"]["document"]["findings"]}
        rows = "".join(
            f"<tr{' style=font-weight:600' if sa.get(c) != sb.get(c) else ''}>"
            f"<td><code>{esc(c)}</code></td><td>{_badge(sa.get(c))}</td>"
            f"<td>{_badge(sb.get(c))}</td></tr>" for c in sorted(set(sa) | set(sb)))
        head = (f"<tr><th>Check</th><th>{esc(str(docs['a']['created_at']))[:19]} "
                f"{_badge(docs['a']['overall'])}</th><th>"
                f"{esc(str(docs['b']['created_at']))[:19]} {_badge(docs['b']['overall'])}"
                "</th></tr>")
        return _page("Compare", f"<h1>Compare scans</h1><table>{head}{rows}</table>")

    @app.get("/ui/results/{result_id}/export.{fmt}")
    def ui_export(request: Request, result_id: UUID, fmt: str):
        import json
        from fastapi import Response
        m = current(request)
        if fmt not in ("json", "html"):
            raise HTTPException(404, "unknown format")
        with db.org(m.org_id) as conn:
            r = conn.execute("SELECT document FROM app.scan_results WHERE id = %s AND "
                             "org_id = %s", (result_id, m.org_id)).fetchone()
        if not r:
            raise HTTPException(404, "result not found")
        if fmt == "html":
            return HTMLResponse(document_html(r["document"]))
        return Response(json.dumps(r["document"], indent=2), media_type="application/json",
                        headers={"Content-Disposition":
                                 f'attachment; filename="ssl-doctor-{result_id}.json"'})
