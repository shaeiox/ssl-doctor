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

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from ssl_doctor import contract

from .db import Database, sha256_hex
from .monitor import (IntervalTooShort, dispatch, enqueue_scan, evaluate,
                      set_monitoring)

ENROLLMENT_TTL = timedelta(hours=24)
MAX_POLL_SECONDS = 30.0

# role -> permissions (enforced centrally in `require`)
PERMISSIONS = {
    "owner": {"view", "scan", "targets", "agents", "members", "settings"},
    "admin": {"view", "scan", "targets", "agents", "members", "settings"},
    "engineer": {"view", "scan", "targets"},
    "viewer": {"view"},
}


@dataclass
class Member:
    token_id: UUID
    org_id: UUID
    role: str


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
        return Member(r["token_id"], r["org_id"], r["role"]) if r else None

    def member(authorization: Optional[str] = Header(None)) -> Member:
        m = resolve_member(_bearer(authorization))
        if not m:
            raise HTTPException(401, "invalid or revoked token")
        return m

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
        return Response(status_code=204)

    # ---------------- agent protocol
    @app.post("/v1/agent/enroll", status_code=201)
    def enroll(body: EnrollIn):
        credential = secrets.token_urlsafe(32)
        with db.system() as conn:
            r = conn.execute("SELECT * FROM app.enroll_agent(%s, %s)",
                             (sha256_hex(body.token), sha256_hex(credential))).fetchone()
        if not r:
            raise HTTPException(403, "enrollment token invalid, expired or already used")
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
