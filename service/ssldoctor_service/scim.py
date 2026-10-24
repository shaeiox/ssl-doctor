"""SCIM 2.0 user provisioning (RFC 7643/7644 subset used by common IdPs).

``/scim/v2/Users`` is authenticated by the organization's SCIM bearer token
(rotated through /v1/sso/scim-token). Deprovisioning — ``active: false`` via
PATCH/PUT, or DELETE — deactivates the member and revokes every session and
API token in the same transaction.
"""

from __future__ import annotations

import re
from typing import Optional
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from . import audit
from .db import Database, sha256_hex
from .identity import deactivate_user

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


def _scim_error(status: int, detail: str) -> JSONResponse:
    return JSONResponse({"schemas": [ERROR_SCHEMA], "status": str(status), "detail": detail},
                        status_code=status, media_type="application/scim+json")


def _resource(u: dict) -> dict:
    return {"schemas": [USER_SCHEMA], "id": str(u["id"]), "externalId": u["external_id"],
            "userName": u["email"], "displayName": u["display_name"],
            "emails": [{"value": u["email"], "primary": True}], "active": u["active"],
            "meta": {"resourceType": "User", "created": u["created_at"].isoformat()}}


def mount_scim(app: FastAPI, db: Database) -> None:

    def org_for(authorization: Optional[str]) -> UUID:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "missing bearer token")
        with db.system() as conn:
            r = conn.execute("SELECT app.auth_scim(%s) AS org",
                             (sha256_hex(authorization[7:].strip()),)).fetchone()
        if not r or not r["org"]:
            raise HTTPException(401, "invalid SCIM token")
        return r["org"]

    def ip(request: Request) -> Optional[str]:
        return request.client.host if request.client else None

    def get_user(conn, org: UUID, user_id: str) -> dict:
        try:
            uid = UUID(user_id)
        except ValueError:
            raise HTTPException(404, "user not found")
        u = conn.execute("SELECT * FROM app.users WHERE id = %s AND org_id = %s",
                         (uid, org)).fetchone()
        if not u:
            raise HTTPException(404, "user not found")
        return u

    def set_active(conn, org: UUID, u: dict, active: bool, request: Request) -> dict:
        if u["active"] and not active:
            deactivate_user(conn, org, u["id"])
            audit.record(conn, org, "scim", "member.remove", f"user:{u['id']}", ip(request),
                         {"via": "scim"})
        elif active and not u["active"]:
            conn.execute("UPDATE app.users SET active = true, removed_at = NULL WHERE id = %s",
                         (u["id"],))
            audit.record(conn, org, "scim", "member.create", f"user:{u['id']}", ip(request),
                         {"via": "scim", "reactivated": True})
        return conn.execute("SELECT * FROM app.users WHERE id = %s", (u["id"],)).fetchone()

    @app.exception_handler(HTTPException)
    async def _errors(request: Request, exc: HTTPException):
        if request.url.path.startswith("/scim/"):
            return _scim_error(exc.status_code, str(exc.detail))
        from fastapi.exception_handlers import http_exception_handler
        return await http_exception_handler(request, exc)

    @app.post("/scim/v2/Users", status_code=201)
    async def create_user(request: Request, authorization: Optional[str] = Header(None)):
        org = org_for(authorization)
        body = await request.json()
        email = body.get("userName") or next((e["value"] for e in body.get("emails", [])
                                              if e.get("value")), None)
        if not email:
            raise HTTPException(400, "userName is required")
        with db.org(org) as conn:
            role = conn.execute("SELECT default_role FROM app.sso_configs WHERE org_id = %s",
                                (org,)).fetchone()["default_role"]
            if conn.execute("SELECT 1 FROM app.users WHERE org_id = %s AND lower(email) = "
                            "lower(%s)", (org, email)).fetchone():
                raise HTTPException(409, "user already exists")
            u = conn.execute("INSERT INTO app.users (org_id, email, display_name, role, "
                             "external_id, active) VALUES (%s, %s, %s, %s, %s, %s) RETURNING *",
                             (org, email, body.get("displayName"), role,
                              body.get("externalId"), body.get("active", True))).fetchone()
            audit.record(conn, org, "scim", "member.create", f"user:{u['id']}", ip(request),
                         {"via": "scim", "email": email, "role": role})
        return JSONResponse(_resource(u), status_code=201, media_type="application/scim+json")

    @app.get("/scim/v2/Users")
    def list_users(filter: Optional[str] = None, authorization: Optional[str] = Header(None)):
        org = org_for(authorization)
        sql, args = "SELECT * FROM app.users WHERE org_id = %s", [org]
        if filter:
            m = re.fullmatch(r'\s*(userName|externalId)\s+eq\s+"([^"]*)"\s*', filter)
            if not m:
                raise HTTPException(400, 'only `userName eq "..."` / `externalId eq "..."` '
                                         "filters are supported")
            col = "lower(email)" if m.group(1) == "userName" else "external_id"
            sql += f" AND {col} = " + ("lower(%s)" if m.group(1) == "userName" else "%s")
            args.append(m.group(2))
        with db.org(org) as conn:
            rows = conn.execute(sql + " ORDER BY created_at", args).fetchall()
        return JSONResponse({"schemas": [LIST_SCHEMA], "totalResults": len(rows),
                             "startIndex": 1, "itemsPerPage": len(rows),
                             "Resources": [_resource(u) for u in rows]},
                            media_type="application/scim+json")

    @app.get("/scim/v2/Users/{user_id}")
    def read_user(user_id: str, authorization: Optional[str] = Header(None)):
        org = org_for(authorization)
        with db.org(org) as conn:
            return JSONResponse(_resource(get_user(conn, org, user_id)),
                                media_type="application/scim+json")

    @app.patch("/scim/v2/Users/{user_id}")
    async def patch_user(user_id: str, request: Request,
                         authorization: Optional[str] = Header(None)):
        org = org_for(authorization)
        body = await request.json()
        with db.org(org) as conn:
            u = get_user(conn, org, user_id)
            for op in body.get("Operations", []):
                if op.get("op", "").lower() not in ("replace", "add"):
                    continue
                value = op.get("value")
                path = (op.get("path") or "").lower()
                if path == "active":
                    u = set_active(conn, org, u, bool(value), request)
                elif not path and isinstance(value, dict):
                    if "active" in value:
                        u = set_active(conn, org, u, bool(value["active"]), request)
                    if value.get("displayName"):
                        u = conn.execute("UPDATE app.users SET display_name = %s WHERE id = %s "
                                         "RETURNING *", (value["displayName"], u["id"])).fetchone()
        return JSONResponse(_resource(u), media_type="application/scim+json")

    @app.put("/scim/v2/Users/{user_id}")
    async def replace_user(user_id: str, request: Request,
                           authorization: Optional[str] = Header(None)):
        org = org_for(authorization)
        body = await request.json()
        with db.org(org) as conn:
            u = get_user(conn, org, user_id)
            u = set_active(conn, org, u, bool(body.get("active", True)), request)
            if body.get("displayName"):
                u = conn.execute("UPDATE app.users SET display_name = %s WHERE id = %s "
                                 "RETURNING *", (body["displayName"], u["id"])).fetchone()
        return JSONResponse(_resource(u), media_type="application/scim+json")

    @app.delete("/scim/v2/Users/{user_id}", status_code=204)
    def delete_user(user_id: str, request: Request,
                    authorization: Optional[str] = Header(None)):
        org = org_for(authorization)
        with db.org(org) as conn:
            set_active(conn, org, get_user(conn, org, user_id), False, request)
        return Response(status_code=204)
