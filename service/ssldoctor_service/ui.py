"""Server-rendered dashboard: targets, scan history, diagnosis, report export.

No JavaScript framework or CDN: works air-gapped, and every value is
HTML-escaped. Sign-in (OIDC, SAML, or an API token unless the org enforces
SSO) creates a server-side session; the HttpOnly, SameSite=Strict cookie
holds only a random session token. Queries carry explicit org predicates and
run under RLS, like the API.
"""

from __future__ import annotations

import html
from typing import Callable, Optional
from uuid import UUID

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from . import audit
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


def _ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


def _badge(overall: Optional[str]) -> str:
    return f'<span class="b b-{esc(overall or "")}">{esc(overall or "pending")}</span>'


def mount_ui(app: FastAPI, db: Database, resolve_member: Callable,
             permissions: dict) -> None:
    from types import SimpleNamespace
    from urllib.parse import urlsplit
    from . import identity
    from .db import sha256_hex

    def session_member(request: Request):
        token = request.cookies.get(COOKIE)
        if not token:
            return None
        with db.system() as conn:
            r = conn.execute("SELECT * FROM app.auth_session(%s)",
                             (sha256_hex(token),)).fetchone()
        return SimpleNamespace(org_id=r["org_id"], role=r["role"], user_id=r["user_id"],
                               actor=f"user:{r['user_id']}", session_id=r["session_id"]) \
            if r else None

    def current(request: Request):
        m = session_member(request)
        if not m:
            raise HTTPException(303, headers={"Location": "/ui/login"})
        return m

    def can(m, perm: str) -> bool:
        return perm in permissions.get(m.role, set())

    def signed_in(request: Request, org_id, user_id, method: str, actor: str):
        """Create a session and answer with a same-site bounce to /ui.

        The bounce page (instead of a 303) matters after cross-site IdP
        redirects/POSTs: SameSite=Strict cookies set there are only sent on a
        navigation that starts on this site.
        """
        with db.org(org_id) as conn:
            token = identity.create_session(conn, org_id, user_id, method)
            audit.record(conn, org_id, actor, "member.signin", None, _ip(request),
                         {"method": method})
        resp = HTMLResponse("<!doctype html><meta http-equiv=refresh content='0;url=/ui'>"
                            "<a href='/ui'>Continue</a>")
        resp.set_cookie(COOKIE, token, httponly=True, samesite="strict",
                        secure=request.url.scheme == "https",
                        max_age=int(identity.SESSION_TTL.total_seconds()))
        return resp

    def refused(reason: str):
        from urllib.parse import quote
        return RedirectResponse(f"/ui/login?error={quote(reason)}", 303)

    def login_info(slug: str):
        with db.system() as conn:
            r = conn.execute("SELECT * FROM app.org_login_info(%s)", (slug,)).fetchone()
        if not r:
            raise HTTPException(404, "unknown organization")
        return r

    def sso_config(conn, org_id):
        cfg = conn.execute("SELECT * FROM app.sso_configs WHERE org_id = %s", (org_id,)).fetchone()
        if not cfg:
            raise HTTPException(404, "single sign-on is not configured")
        return cfg

    @app.get("/ui/login", response_class=HTMLResponse)
    def login_form(error: str = ""):
        msg = f'<p style="color:var(--fail)">{esc(error)}</p>' if error else ""
        return _page("Sign in", f"""<div class=card><h1>Sign in</h1>{msg}
            <form method=get action=/ui/sso/start><label>Organization (single sign-on)<br>
            <input name=org autocomplete=organization required></label>
            <p><button type=submit>Continue with SSO</button></p></form>
            <hr><form method=post action=/ui/login><label>or an API token<br>
            <input type=password name=token autocomplete=off required></label>
            <p><button type=submit>Sign in</button></p></form></div>""", signed_in=False)

    @app.post("/ui/login")
    def login(request: Request, token: str = Form(...)):
        m = resolve_member(token)
        if not m:
            return refused("Invalid or revoked token")
        with db.system() as conn:
            enforced = conn.execute("SELECT app.sso_enforced(%s) AS e",
                                    (m.org_id,)).fetchone()["e"]
        if enforced:
            with db.org(m.org_id) as conn:
                slug = conn.execute("SELECT slug FROM app.organizations WHERE id = %s",
                                    (m.org_id,)).fetchone()["slug"]
            return RedirectResponse(f"/ui/sso/{slug}/start", 303)
        resp = signed_in(request, m.org_id, m.user_id, "api-token", m.actor)
        return resp

    @app.get("/ui/logout")
    def logout(request: Request):
        m = session_member(request)
        if m:
            with db.org(m.org_id) as conn:
                conn.execute("UPDATE app.sessions SET revoked_at = now() WHERE id = %s",
                             (m.session_id,))
        resp = RedirectResponse("/ui/login", 303)
        resp.delete_cookie(COOKIE)
        return resp

    # ---------------- single sign-on
    @app.get("/ui/sso/start")
    def sso_pick(org: str):
        return RedirectResponse(f"/ui/sso/{org.strip().lower()}/start", 303)

    @app.get("/ui/sso/{slug}/start")
    def sso_start(request: Request, slug: str):
        info = login_info(slug)
        base = str(request.base_url).rstrip("/")
        with db.org(info["org_id"]) as conn:
            cfg = sso_config(conn, info["org_id"])
            if cfg["protocol"] == "oidc":
                url = identity.oidc_start(conn, cfg, info["org_id"],
                                          f"{base}/ui/sso/{slug}/oidc/callback")
            else:
                url = identity.saml_start(conn, cfg, info["org_id"], base, slug,
                                          identity.saml_request_data(urlsplit(str(request.url))))
        return RedirectResponse(url, 303)

    @app.get("/ui/sso/{slug}/oidc/callback")
    def oidc_callback(request: Request, slug: str, state: str = "", code: str = "",
                      error: str = ""):
        if error:
            return refused(f"Identity provider refused sign-in: {error}")
        info = login_info(slug)
        base = str(request.base_url).rstrip("/")
        try:
            with db.org(info["org_id"]) as conn:
                cfg = sso_config(conn, info["org_id"])
                claims = identity.oidc_finish(conn, cfg, info["org_id"], state, code,
                                              f"{base}/ui/sso/{slug}/oidc/callback")
                u = identity.sso_user(conn, info["org_id"], cfg, claims.get("email"),
                                      claims["sub"], claims.get("name"))
        except identity.SignInRefused as exc:
            return refused(str(exc))
        return signed_in(request, info["org_id"], u["id"], "oidc", f"user:{u['id']}")

    @app.post("/ui/sso/{slug}/saml/acs")
    async def saml_acs(request: Request, slug: str):
        form = dict(await request.form())
        info = login_info(slug)
        base = str(request.base_url).rstrip("/")
        try:
            with db.org(info["org_id"]) as conn:
                cfg = sso_config(conn, info["org_id"])
                a = identity.saml_finish(conn, cfg, info["org_id"], base, slug,
                                         identity.saml_request_data(urlsplit(str(request.url)),
                                                                    form))
                u = identity.sso_user(conn, info["org_id"], cfg, a["email"], a["sub"],
                                      a.get("name"))
        except identity.SignInRefused as exc:
            return refused(str(exc))
        return signed_in(request, info["org_id"], u["id"], "saml", f"user:{u['id']}")

    @app.get("/ui/sso/{slug}/saml/metadata")
    def saml_metadata(request: Request, slug: str):
        from fastapi import Response
        from onelogin.saml2.settings import OneLogin_Saml2_Settings
        info = login_info(slug)
        with db.org(info["org_id"]) as conn:
            cfg = sso_config(conn, info["org_id"])
        settings = OneLogin_Saml2_Settings(identity.saml_settings(
            cfg, str(request.base_url).rstrip("/"), slug), sp_validation_only=True)
        return Response(settings.get_sp_metadata(), media_type="application/xml")

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
            jobs = enqueue_scan(conn, m.org_id, target_id)
            audit.record(conn, m.org_id, m.actor, "scan.start", f"target:{target_id}",
                         _ip(request), {"jobs": len(jobs), "via": "dashboard"})
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
            audit.record(conn, m.org_id, m.actor, "report.export", f"result:{result_id}",
                         _ip(request), {"format": fmt, "via": "dashboard"})
        if fmt == "html":
            return HTMLResponse(document_html(r["document"]))
        return Response(json.dumps(r["document"], indent=2), media_type="application/json",
                        headers={"Content-Disposition":
                                 f'attachment; filename="ssl-doctor-{result_id}.json"'})
