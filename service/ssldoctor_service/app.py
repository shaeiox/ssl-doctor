"""Control-plane HTTP API (FastAPI).

Two audiences:
* members, with ``Authorization: Bearer <api token>``, under /v1/...
* agents, with ``Authorization: Bearer <agent credential>``, under /v1/agent/...

Tenant isolation: every handler runs its queries in ``db.org(org_id)``, so
RLS filters all rows. Objects of another organization are indistinguishable
from objects that don't exist (404).
"""

from __future__ import annotations

import json
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from ssl_doctor import contract

from . import audit
from .db import Database, sha256_hex
from .monitor import (IntervalTooShort, dispatch, enqueue_scan, evaluate,
                      set_monitoring)

ENROLLMENT_TTL = timedelta(hours=24)
MAX_POLL_SECONDS = 30.0

# role -> permissions (enforced centrally in `require`)
PERMISSIONS = {
    "owner": {"view", "scan", "targets", "agents", "members", "settings", "audit"},
    "admin": {"view", "scan", "targets", "agents", "members", "settings", "audit"},
    "engineer": {"view", "scan", "targets"},
    "viewer": {"view"},
}


@dataclass
class Member:
    token_id: UUID
    org_id: UUID
    role: str
    user_id: Optional[UUID] = None
    actor: str = ""                 # audit identity: user:<id>
    ip: Optional[str] = None        # request source address (audit)


@dataclass
class AgentIdentity:
    agent_id: UUID
    org_id: UUID
    role: str


# ------------------------------------------------------------------ models

class EnrollmentTokenIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    role: str = Field(pattern="^(client|server)$")


class TargetIn(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(443, ge=1, le=65535)
    sni: Optional[str] = Field(None, max_length=253)
    agent_ids: List[UUID] = []


class Assignment(BaseModel):
    agent_id: UUID
    kind: str = Field(pattern="^(client|server)$")


class ScanIn(BaseModel):
    # default: one job per assigned agent, of that agent's role
    assignments: Optional[List[Assignment]] = None


class MonitoringIn(BaseModel):
    interval_seconds: Optional[int] = Field(None, ge=60)   # None = stop monitoring
    expiry_threshold_days: int = Field(30, ge=1, le=365)


class ChannelIn(BaseModel):
    kind: str = Field(pattern="^(email|webhook)$")
    address: str = Field(min_length=3, max_length=500)
    secret: Optional[str] = Field(None, min_length=16, max_length=200)


class MemberIn(BaseModel):
    email: str = Field(min_length=3, max_length=320, pattern=r"^[^@\s]+@[^@\s]+$")
    role: str = Field(pattern="^(owner|admin|engineer|viewer)$")
    display_name: Optional[str] = Field(None, max_length=200)


class RoleIn(BaseModel):
    role: str = Field(pattern="^(owner|admin|engineer|viewer)$")


class TokenIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class SSOConfigIn(BaseModel):
    protocol: str = Field(pattern="^(oidc|saml)$")
    enforced: bool = False
    default_role: str = Field("viewer", pattern="^(admin|engineer|viewer)$")
    jit_provisioning: bool = False
    oidc_issuer: Optional[str] = None
    oidc_client_id: Optional[str] = None
    oidc_client_secret: Optional[str] = None
    oidc_authorize_url: Optional[str] = None
    oidc_token_url: Optional[str] = None
    oidc_jwks_url: Optional[str] = None
    saml_idp_entity_id: Optional[str] = None
    saml_idp_sso_url: Optional[str] = None
    saml_idp_cert: Optional[str] = None


class EnrollIn(BaseModel):
    token: str = Field(min_length=16, max_length=200)


class DeclineIn(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


# ------------------------------------------------------------------ app

def _bearer(authorization: Optional[str]) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token")
    return authorization[7:].strip()


def _row(r):
    return {k: (str(v) if isinstance(v, (UUID, datetime)) else v) for k, v in r.items()}


def create_app(db: Database) -> FastAPI:
    app = FastAPI(title="SSL Doctor control plane", version="0.1.0")

    # ---------------- authentication / authorization
    def resolve_member(token: str) -> Optional[Member]:
        with db.system() as conn:
            r = conn.execute("SELECT * FROM app.auth_api_token(%s)",
                             (sha256_hex(token),)).fetchone()
        return Member(r["token_id"], r["org_id"], r["role"], r["user_id"],
                      actor=f"user:{r['user_id']}") if r else None

    def member(request: Request, authorization: Optional[str] = Header(None)) -> Member:
        m = resolve_member(_bearer(authorization))
        if not m:
            raise HTTPException(401, "invalid or revoked token")
        m.ip = request.client.host if request.client else None
        return m

    def log(conn, m: Member, action: str, obj: Optional[str] = None, **details):
        audit.record(conn, m.org_id, m.actor, action, obj, m.ip, details)

    def require(permission: str):
        def dep(m: Member = Depends(member)) -> Member:
            if permission not in PERMISSIONS.get(m.role, set()):
                raise HTTPException(403, f"role '{m.role}' may not {permission}")
            return m
        return dep

    def agent(authorization: Optional[str] = Header(None)) -> AgentIdentity:
        cred = _bearer(authorization)
        with db.system() as conn:
            r = conn.execute("SELECT * FROM app.auth_agent(%s)",
                             (sha256_hex(cred),)).fetchone()
        if not r:
            raise HTTPException(401, "unknown agent credential")
        if r["revoked"]:
            raise HTTPException(401, "agent revoked")
        return AgentIdentity(r["agent_id"], r["org_id"], r["role"])

    @app.get("/healthz")
    def healthz():
        with db.system() as conn:
            conn.execute("SELECT 1")
        return {"status": "ok"}

    # ---------------- agents & enrollment (owners/admins)
    @app.post("/v1/enrollment-tokens", status_code=201)
    def create_enrollment_token(body: EnrollmentTokenIn, m: Member = Depends(require("agents"))):
        token = secrets.token_urlsafe(32)
        expires = datetime.now(timezone.utc) + ENROLLMENT_TTL
        with db.org(m.org_id) as conn:
            conn.execute("INSERT INTO app.enrollment_tokens (org_id, token_hash, agent_role, "
                         "agent_name, expires_at) VALUES (%s, %s, %s, %s, %s)",
                         (m.org_id, sha256_hex(token), body.role, body.name, expires))
            log(conn, m, "agent.enrollment_token", f"enrollment:{body.name}", role=body.role)
        return {"token": token, "expires_at": expires.isoformat(), "role": body.role}

    @app.get("/v1/agents")
    def list_agents(m: Member = Depends(require("view"))):
        with db.org(m.org_id) as conn:
            rows = conn.execute("SELECT id, name, role, created_at, last_seen_at, revoked_at "
                                "FROM app.agents WHERE org_id = %s ORDER BY created_at",
                                (m.org_id,)).fetchall()
        return [_row(r) for r in rows]

    @app.post("/v1/agents/{agent_id}/revoke")
    def revoke_agent(agent_id: UUID, m: Member = Depends(require("agents"))):
        with db.org(m.org_id) as conn:
            r = conn.execute("UPDATE app.agents SET revoked_at = coalesce(revoked_at, now()) "
                             "WHERE id = %s AND org_id = %s RETURNING id, revoked_at",
                             (agent_id, m.org_id)).fetchone()
            if not r:
                raise HTTPException(404, "agent not found")
            log(conn, m, "agent.revoke", f"agent:{agent_id}")
        return _row(r)

    # ---------------- targets
    @app.post("/v1/targets", status_code=201)
    def create_target(body: TargetIn, m: Member = Depends(require("targets"))):
        with db.org(m.org_id) as conn:
            for aid in body.agent_ids:
                if not conn.execute("SELECT 1 FROM app.agents WHERE id = %s AND org_id = %s "
                                    "AND revoked_at IS NULL", (aid, m.org_id)).fetchone():
                    raise HTTPException(404, f"agent {aid} not found")
            t = conn.execute("INSERT INTO app.targets (org_id, host, port, sni) VALUES "
                             "(%s, %s, %s, %s) RETURNING *",
                             (m.org_id, body.host, body.port, body.sni)).fetchone()
            for aid in body.agent_ids:
                conn.execute("INSERT INTO app.target_agents (org_id, target_id, agent_id) "
                             "VALUES (%s, %s, %s)", (m.org_id, t["id"], aid))
            log(conn, m, "target.create", f"target:{t['id']}", host=body.host, port=body.port)
        return {**_row(t), "agent_ids": [str(a) for a in body.agent_ids]}

    def _target(conn, target_id: UUID, org_id: UUID):
        t = conn.execute("SELECT * FROM app.targets WHERE id = %s AND org_id = %s",
                         (target_id, org_id)).fetchone()
        if not t:
            raise HTTPException(404, "target not found")
        agents = conn.execute("SELECT agent_id FROM app.target_agents WHERE target_id = %s "
                              "AND org_id = %s", (target_id, org_id)).fetchall()
        return {**_row(t), "agent_ids": [str(a["agent_id"]) for a in agents]}

    @app.get("/v1/targets")
    def list_targets(m: Member = Depends(require("view"))):
        with db.org(m.org_id) as conn:
            ids = [r["id"] for r in conn.execute(
                "SELECT id FROM app.targets WHERE org_id = %s ORDER BY created_at",
                (m.org_id,)).fetchall()]
            return [_target(conn, i, m.org_id) for i in ids]

    @app.get("/v1/targets/{target_id}")
    def get_target(target_id: UUID, m: Member = Depends(require("view"))):
        with db.org(m.org_id) as conn:
            return _target(conn, target_id, m.org_id)

    # ---------------- scans
    @app.post("/v1/targets/{target_id}/scans", status_code=201)
    def start_scan(target_id: UUID, body: ScanIn = ScanIn(),
                   m: Member = Depends(require("scan"))):
        with db.org(m.org_id) as conn:
            t = _target(conn, target_id, m.org_id)
            if body.assignments is None:
                jobs = enqueue_scan(conn, m.org_id, target_id)
                if not jobs:
                    raise HTTPException(409, "target has no active agents assigned")
                log(conn, m, "scan.start", f"target:{target_id}", jobs=len(jobs))
                return [_row(j) for j in jobs]
            else:
                assignments = [(a.agent_id, a.kind) for a in body.assignments]
                for aid, _kind in assignments:
                    if str(aid) not in t["agent_ids"]:
                        raise HTTPException(404, f"agent {aid} is not assigned to target")
            if not assignments:
                raise HTTPException(409, "target has no active agents assigned")
            jobs = [conn.execute("INSERT INTO app.scan_jobs (org_id, target_id, agent_id, kind) "
                                 "VALUES (%s, %s, %s, %s) RETURNING *",
                                 (m.org_id, target_id, aid, kind)).fetchone()
                    for aid, kind in assignments]
            log(conn, m, "scan.start", f"target:{target_id}", jobs=len(jobs))
        return [_row(j) for j in jobs]

    @app.get("/v1/jobs/{job_id}")
    def get_job(job_id: UUID, m: Member = Depends(require("view"))):
        with db.org(m.org_id) as conn:
            j = conn.execute("SELECT * FROM app.scan_jobs WHERE id = %s AND org_id = %s",
                             (job_id, m.org_id)).fetchone()
        if not j:
            raise HTTPException(404, "job not found")
        return _row(j)

    # ---------------- results history
    @app.get("/v1/targets/{target_id}/results")
    def list_results(target_id: UUID, m: Member = Depends(require("view"))):
        with db.org(m.org_id) as conn:
            _target(conn, target_id, m.org_id)
            rows = conn.execute("SELECT id, job_id, overall, created_at FROM app.scan_results "
                                "WHERE target_id = %s AND org_id = %s ORDER BY created_at",
                                (target_id, m.org_id)).fetchall()
        return [_row(r) for r in rows]

    def _result(conn, result_id: UUID, org_id: UUID):
        r = conn.execute("SELECT * FROM app.scan_results WHERE id = %s AND org_id = %s",
                         (result_id, org_id)).fetchone()
        if not r:
            raise HTTPException(404, "result not found")
        return r

    @app.get("/v1/results/{result_id}")
    def get_result(result_id: UUID, m: Member = Depends(require("view"))):
        with db.org(m.org_id) as conn:
            r = _result(conn, result_id, m.org_id)
        return {**_row({k: v for k, v in r.items() if k != "document"}),
                "document": r["document"]}

    @app.get("/v1/compare")
    def compare(a: UUID = Query(...), b: UUID = Query(...),
                m: Member = Depends(require("view"))):
        """Side-by-side status of every check in two results."""
        with db.org(m.org_id) as conn:
            ra, rb = _result(conn, a, m.org_id), _result(conn, b, m.org_id)
        sa = {f["check"]: f["status"] for f in ra["document"]["findings"]}
        sb = {f["check"]: f["status"] for f in rb["document"]["findings"]}
        rows = [{"check": c, "a": sa.get(c), "b": sb.get(c), "changed": sa.get(c) != sb.get(c)}
                for c in sorted(set(sa) | set(sb))]
        return {"a": {"id": str(a), "overall": ra["overall"], "created_at": str(ra["created_at"])},
                "b": {"id": str(b), "overall": rb["overall"], "created_at": str(rb["created_at"])},
                "checks": rows}

    @app.get("/v1/results/{result_id}/export")
    def export(result_id: UUID, format: str = Query("json", pattern="^(json|html)$"),
               m: Member = Depends(require("view"))):
        with db.org(m.org_id) as conn:
            doc = _result(conn, result_id, m.org_id)["document"]
            log(conn, m, "report.export", f"result:{result_id}", format=format)
        if format == "json":
            return Response(json.dumps(doc, indent=2), media_type="application/json",
                            headers={"Content-Disposition":
                                     f'attachment; filename="ssl-doctor-{result_id}.json"'})
        from .render import document_html
        return HTMLResponse(document_html(doc))

    from .ui import mount_ui
    mount_ui(app, db, resolve_member, PERMISSIONS)

    # ---------------- monitoring & alerting
    @app.put("/v1/targets/{target_id}/monitoring")
    def put_monitoring(target_id: UUID, body: MonitoringIn,
                       m: Member = Depends(require("targets"))):
        with db.org(m.org_id) as conn:
            _target(conn, target_id, m.org_id)
            try:
                r = set_monitoring(conn, m.org_id, target_id, body.interval_seconds,
                                   body.expiry_threshold_days, datetime.now(timezone.utc))
            except IntervalTooShort as exc:
                raise HTTPException(422, str(exc))
            log(conn, m, "target.monitoring", f"target:{target_id}",
                interval_seconds=body.interval_seconds,
                expiry_threshold_days=body.expiry_threshold_days)
        return _row(r)

    @app.get("/v1/targets/{target_id}/alerts")
    def list_alerts(target_id: UUID, m: Member = Depends(require("view"))):
        with db.org(m.org_id) as conn:
            _target(conn, target_id, m.org_id)
            state = conn.execute("SELECT condition, is_open, opened_at, closed_at FROM "
                                 "app.alert_state WHERE target_id = %s AND org_id = %s "
                                 "ORDER BY condition", (target_id, m.org_id)).fetchall()
            sent = conn.execute("SELECT id, condition, status, attempts, created_at, sent_at "
                                "FROM app.alerts WHERE target_id = %s AND org_id = %s "
                                "ORDER BY created_at", (target_id, m.org_id)).fetchall()
        return {"conditions": [_row(r) for r in state], "deliveries": [_row(r) for r in sent]}

    @app.post("/v1/channels", status_code=201)
    def create_channel(body: ChannelIn, m: Member = Depends(require("settings"))):
        if body.kind == "webhook" and not body.address.startswith(("https://", "http://")):
            raise HTTPException(422, "webhook address must be an http(s) URL")
        with db.org(m.org_id) as conn:
            r = conn.execute("INSERT INTO app.notification_channels (org_id, kind, address, "
                             "secret) VALUES (%s, %s, %s, %s) RETURNING id, kind, address, "
                             "created_at", (m.org_id, body.kind, body.address,
                                            body.secret)).fetchone()
            log(conn, m, "channel.create", f"channel:{r['id']}", kind=body.kind)
        return _row(r)

    @app.get("/v1/channels")
    def list_channels(m: Member = Depends(require("view"))):
        with db.org(m.org_id) as conn:
            rows = conn.execute("SELECT id, kind, address, created_at FROM "
                                "app.notification_channels WHERE org_id = %s ORDER BY "
                                "created_at", (m.org_id,)).fetchall()
        return [_row(r) for r in rows]

    @app.delete("/v1/channels/{channel_id}", status_code=204)
    def delete_channel(channel_id: UUID, m: Member = Depends(require("settings"))):
        with db.org(m.org_id) as conn:
            if conn.execute("SELECT 1 FROM app.alerts WHERE channel_id = %s AND org_id = %s "
                            "LIMIT 1", (channel_id, m.org_id)).fetchone():
                raise HTTPException(409, "channel has delivery history; it cannot be deleted")
            r = conn.execute("DELETE FROM app.notification_channels WHERE id = %s AND "
                             "org_id = %s RETURNING id", (channel_id, m.org_id)).fetchone()
            if not r:
                raise HTTPException(404, "channel not found")
            log(conn, m, "channel.delete", f"channel:{channel_id}")
        return Response(status_code=204)

    # ---------------- members & API tokens
    def _member_row(u):
        return _row({k: u[k] for k in ("id", "email", "display_name", "role", "active",
                                       "external_id", "created_at", "removed_at")})

    def _owners(conn, org_id):
        return conn.execute("SELECT count(*) AS n FROM app.users WHERE org_id = %s AND "
                            "role = 'owner' AND active", (org_id,)).fetchone()["n"]

    @app.get("/v1/members")
    def list_members(m: Member = Depends(require("view"))):
        with db.org(m.org_id) as conn:
            rows = conn.execute("SELECT * FROM app.users WHERE org_id = %s ORDER BY "
                                "created_at", (m.org_id,)).fetchall()
        return [_member_row(u) for u in rows]

    @app.post("/v1/members", status_code=201)
    def add_member(body: MemberIn, m: Member = Depends(require("members"))):
        if body.role == "owner" and m.role != "owner":
            raise HTTPException(403, "only owners may grant the owner role")
        import psycopg
        with db.org(m.org_id) as conn:
            try:
                u = conn.execute("INSERT INTO app.users (org_id, email, display_name, role) "
                                 "VALUES (%s, %s, %s, %s) RETURNING *",
                                 (m.org_id, body.email, body.display_name, body.role)).fetchone()
            except psycopg.errors.UniqueViolation:
                raise HTTPException(409, "a member with this email already exists")
            log(conn, m, "member.create", f"user:{u['id']}", email=body.email, role=body.role)
        return _member_row(u)

    @app.patch("/v1/members/{user_id}")
    def change_role(user_id: UUID, body: RoleIn, m: Member = Depends(require("members"))):
        with db.org(m.org_id) as conn:
            u = conn.execute("SELECT * FROM app.users WHERE id = %s AND org_id = %s AND "
                             "active FOR UPDATE", (user_id, m.org_id)).fetchone()
            if not u:
                raise HTTPException(404, "member not found")
            if "owner" in (body.role, u["role"]) and m.role != "owner":
                raise HTTPException(403, "only owners may grant or remove the owner role")
            if u["role"] == "owner" and body.role != "owner" and _owners(conn, m.org_id) <= 1:
                raise HTTPException(409, "an organization must keep at least one owner")
            u = conn.execute("UPDATE app.users SET role = %s WHERE id = %s RETURNING *",
                             (body.role, user_id)).fetchone()
            log(conn, m, "member.role_change", f"user:{user_id}", role=body.role)
        return _member_row(u)

    @app.delete("/v1/members/{user_id}", status_code=204)
    def remove_member(user_id: UUID, m: Member = Depends(require("members"))):
        from .identity import deactivate_user
        with db.org(m.org_id) as conn:
            u = conn.execute("SELECT role FROM app.users WHERE id = %s AND org_id = %s AND "
                             "active", (user_id, m.org_id)).fetchone()
            if not u:
                raise HTTPException(404, "member not found")
            if u["role"] == "owner" and (m.role != "owner" or _owners(conn, m.org_id) <= 1):
                raise HTTPException(409 if m.role == "owner" else 403,
                                    "cannot remove the last owner" if m.role == "owner"
                                    else "only owners may remove an owner")
            deactivate_user(conn, m.org_id, user_id)
            log(conn, m, "member.remove", f"user:{user_id}")
        return Response(status_code=204)

    @app.post("/v1/tokens", status_code=201)
    def create_token(body: TokenIn, m: Member = Depends(require("view"))):
        """A personal API token for the caller (inherits the caller's role)."""
        token = secrets.token_urlsafe(32)
        with db.org(m.org_id) as conn:
            r = conn.execute("INSERT INTO app.api_tokens (org_id, name, token_hash, role, "
                             "user_id) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                             (m.org_id, body.name, sha256_hex(token), m.role,
                              m.user_id)).fetchone()
        return {"id": str(r["id"]), "token": token}

    # ---------------- single sign-on configuration (owners/admins)
    @app.put("/v1/sso")
    def put_sso(body: SSOConfigIn, m: Member = Depends(require("settings"))):
        need = (["oidc_issuer", "oidc_client_id", "oidc_client_secret", "oidc_authorize_url",
                 "oidc_token_url", "oidc_jwks_url"] if body.protocol == "oidc" else
                ["saml_idp_entity_id", "saml_idp_sso_url", "saml_idp_cert"])
        missing = [f for f in need if not getattr(body, f)]
        if missing:
            raise HTTPException(422, f"missing for {body.protocol}: {', '.join(missing)}")
        cols = list(SSOConfigIn.model_fields)
        with db.org(m.org_id) as conn:
            before = conn.execute("SELECT enforced FROM app.sso_configs WHERE org_id = %s",
                                  (m.org_id,)).fetchone()
            conn.execute(
                f"INSERT INTO app.sso_configs (org_id, {', '.join(cols)}) VALUES "
                f"(%s, {', '.join(['%s'] * len(cols))}) ON CONFLICT (org_id) DO UPDATE SET "
                + ", ".join(f"{c} = EXCLUDED.{c}" for c in cols) + ", updated_at = now()",
                [m.org_id] + [getattr(body, c) for c in cols])
            log(conn, m, "sso.configure", "sso", protocol=body.protocol)
            if (before["enforced"] if before else False) != body.enforced:
                log(conn, m, "sso.enforce", "sso", enforced=body.enforced)
        return {"protocol": body.protocol, "enforced": body.enforced}

    @app.post("/v1/sso/scim-token", status_code=201)
    def scim_token(m: Member = Depends(require("settings"))):
        token = secrets.token_urlsafe(32)
        with db.org(m.org_id) as conn:
            r = conn.execute("UPDATE app.sso_configs SET scim_token_hash = %s WHERE org_id = %s "
                             "RETURNING org_id", (sha256_hex(token), m.org_id)).fetchone()
            if not r:
                raise HTTPException(409, "configure single sign-on first")
            log(conn, m, "sso.configure", "scim", change="scim-token-rotated")
        return {"token": token}

    from .scim import mount_scim
    mount_scim(app, db)

    # ---------------- audit log (owners/admins)
    @app.get("/v1/audit")
    def export_audit(since: datetime = Query(...), until: datetime = Query(...),
                     m: Member = Depends(require("audit"))):
        """JSON Lines export of the org's audit entries in [since, until)."""
        with db.org(m.org_id) as conn:
            rows = conn.execute("SELECT seq, entry, prev_hash, hash FROM app.audit_log "
                                "WHERE org_id = %s AND created_at >= %s AND created_at < %s "
                                "ORDER BY seq", (m.org_id, since, until)).fetchall()
            log(conn, m, "audit.export", None, since=since.isoformat(),
                until=until.isoformat(), entries=len(rows))
        body = "".join(json.dumps({"seq": r["seq"], "entry": r["entry"],
                                   "prev_hash": r["prev_hash"], "hash": r["hash"]}) + "\n"
                       for r in rows)
        return Response(body, media_type="application/x-ndjson", headers={
            "Content-Disposition": 'attachment; filename="ssl-doctor-audit.jsonl"'})

    @app.get("/v1/audit/verify")
    def verify_audit(m: Member = Depends(require("audit"))):
        with db.org(m.org_id) as conn:
            ok, bad, reason = audit.verify_org(conn, m.org_id)
        return {"ok": ok, "first_bad_entry": bad, "detail": reason}

    # ---------------- agent protocol
    @app.post("/v1/agent/enroll", status_code=201)
    def enroll(body: EnrollIn, request: Request):
        credential = secrets.token_urlsafe(32)
        with db.system() as conn:
            r = conn.execute("SELECT * FROM app.enroll_agent(%s, %s)",
                             (sha256_hex(body.token), sha256_hex(credential))).fetchone()
            if not r:
                raise HTTPException(403, "enrollment token invalid, expired or already used")
            # same transaction: scope to the agent's org and record the enrollment
            conn.execute("SELECT set_config('app.org_id', %s, true)", (str(r["org_id"]),))
            audit.record(conn, r["org_id"], f"agent:{r['agent_id']}", "agent.enroll",
                         f"agent:{r['agent_id']}",
                         request.client.host if request.client else None,
                         {"role": r["role"], "name": r["name"]})
        return {"agent_id": str(r["agent_id"]), "org_id": str(r["org_id"]),
                "role": r["role"], "name": r["name"], "credential": credential}

    @app.post("/v1/agent/jobs/next")
    def next_job(wait: float = Query(20.0, ge=0, le=MAX_POLL_SECONDS),
                 a: AgentIdentity = Depends(agent)):
        """Long-poll: claim the agent's oldest queued job (SKIP LOCKED queue)."""
        deadline = time.monotonic() + wait
        while True:
            with db.org(a.org_id) as conn:
                conn.execute("UPDATE app.agents SET last_seen_at = now() WHERE id = %s",
                             (a.agent_id,))
                j = conn.execute(
                    "UPDATE app.scan_jobs SET status = 'running', started_at = now() "
                    "WHERE id = (SELECT id FROM app.scan_jobs WHERE agent_id = %s AND "
                    "org_id = %s AND status = 'queued' ORDER BY created_at "
                    "FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING *",
                    (a.agent_id, a.org_id)).fetchone()
                if j:
                    t = conn.execute("SELECT host, port, sni FROM app.targets WHERE id = %s",
                                     (j["target_id"],)).fetchone()
                    return {"job_id": str(j["id"]), "kind": j["kind"], "target": t}
            if time.monotonic() >= deadline:
                return Response(status_code=204)
            time.sleep(0.25)

    def _running_job(conn, job_id: UUID, a: AgentIdentity):
        j = conn.execute("SELECT * FROM app.scan_jobs WHERE id = %s AND agent_id = %s "
                         "AND org_id = %s FOR UPDATE", (job_id, a.agent_id, a.org_id)).fetchone()
        if not j:
            raise HTTPException(404, "job not found")
        if j["status"] != "running":
            raise HTTPException(409, f"job is {j['status']}")
        return j

    @app.post("/v1/agent/jobs/{job_id}/result", status_code=201)
    def upload_result(job_id: UUID, document: dict, a: AgentIdentity = Depends(agent)):
        try:
            doc = contract.load_document(document)
        except contract.ContractError as exc:
            raise HTTPException(422, str(exc))
        overall = (doc.get("diagnosis") or {}).get("overall")
        with db.org(a.org_id) as conn:
            j = _running_job(conn, job_id, a)
            r = conn.execute("INSERT INTO app.scan_results (org_id, job_id, target_id, "
                             "overall, document) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                             (a.org_id, job_id, j["target_id"], overall,
                              json.dumps(doc))).fetchone()
            conn.execute("UPDATE app.scan_jobs SET status = 'done', finished_at = now() "
                         "WHERE id = %s", (job_id,))
            opened = evaluate(conn, a.org_id, j["target_id"], r["id"], doc,
                              datetime.now(timezone.utc))
        if opened:
            threading.Thread(target=_dispatch_quietly, daemon=True).start()
        return {"result_id": str(r["id"]), "alerts_opened": opened}

    def _dispatch_quietly():
        try:
            dispatch(db)
        except Exception:  # noqa: BLE001 - the scheduler retries pending alerts
            pass

    @app.post("/v1/agent/jobs/{job_id}/decline")
    def decline_job(job_id: UUID, body: DeclineIn, a: AgentIdentity = Depends(agent)):
        with db.org(a.org_id) as conn:
            _running_job(conn, job_id, a)
            conn.execute("UPDATE app.scan_jobs SET status = 'not_runnable', error = %s, "
                         "finished_at = now() WHERE id = %s", (body.reason, job_id))
        return {"status": "not_runnable"}

    return app
