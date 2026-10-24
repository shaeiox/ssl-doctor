"""Identity: sessions, OIDC / SAML sign-in, member lifecycle, SCIM provisioning.

* Browser sessions are server-side rows: the cookie holds a random token,
  stored only as a hash.
* OIDC: authorization code + PKCE (S256) + nonce. The ID token is verified
  against the IdP's JWKS (signature, issuer, audience, expiry, nonce).
  Endpoints are configured explicitly, so no discovery or outbound access is
  needed beyond the customer's own IdP.
* SAML 2.0: SP-initiated; python3-saml in strict mode, with signed
  assertions required (xmlsec) and InResponseTo bound to the stored request.
* Removing or deprovisioning a member revokes all of their sessions and API
  tokens in the same transaction.

The protocol libraries (authlib, python3-saml) are imported lazily.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from .db import sha256_hex

SESSION_TTL = timedelta(hours=8)
STATE_TTL = timedelta(minutes=10)


class SignInRefused(Exception):
    """Sign-in must not proceed (unknown/deprovisioned user, bad assertion...)."""


# ------------------------------------------------------------------ sessions

def create_session(conn, org_id: UUID, user_id: UUID, method: str) -> str:
    token = secrets.token_urlsafe(32)
    conn.execute("INSERT INTO app.sessions (org_id, user_id, token_hash, method, expires_at) "
                 "VALUES (%s, %s, %s, %s, %s)",
                 (org_id, user_id, sha256_hex(token), method,
                  datetime.now(timezone.utc) + SESSION_TTL))
    return token


def revoke_user_credentials(conn, org_id: UUID, user_id: UUID) -> None:
    conn.execute("UPDATE app.sessions SET revoked_at = now() WHERE user_id = %s AND "
                 "org_id = %s AND revoked_at IS NULL", (user_id, org_id))
    conn.execute("UPDATE app.api_tokens SET revoked_at = now() WHERE user_id = %s AND "
                 "org_id = %s AND revoked_at IS NULL", (user_id, org_id))


def deactivate_user(conn, org_id: UUID, user_id: UUID) -> Optional[dict]:
    u = conn.execute("UPDATE app.users SET active = false, removed_at = coalesce(removed_at, "
                     "now()) WHERE id = %s AND org_id = %s RETURNING *",
                     (user_id, org_id)).fetchone()
    if u:
        revoke_user_credentials(conn, org_id, user_id)
    return u


def sso_user(conn, org_id: UUID, cfg: dict, email: str, external_id: Optional[str],
             display_name: Optional[str] = None) -> dict:
    """The active member an SSO assertion identifies (JIT-provisioned if enabled)."""
    if not email:
        raise SignInRefused("the identity provider did not supply an email address")
    u = None
    if external_id:
        u = conn.execute("SELECT * FROM app.users WHERE org_id = %s AND external_id = %s",
                         (org_id, external_id)).fetchone()
    if not u:
        u = conn.execute("SELECT * FROM app.users WHERE org_id = %s AND lower(email) = "
                         "lower(%s)", (org_id, email)).fetchone()
    if u and not u["active"]:
        raise SignInRefused("this account has been deprovisioned")
    if u:
        if external_id and not u["external_id"]:
            conn.execute("UPDATE app.users SET external_id = %s WHERE id = %s",
                         (external_id, u["id"]))
        return u
    if not cfg.get("jit_provisioning"):
        raise SignInRefused("no member with this identity; ask an administrator to add you")
    return conn.execute("INSERT INTO app.users (org_id, email, display_name, role, external_id) "
                        "VALUES (%s, %s, %s, %s, %s) RETURNING *",
                        (org_id, email, display_name, cfg["default_role"],
                         external_id)).fetchone()


def _store_state(conn, org_id: UUID, state: str, nonce: str,
                 verifier: Optional[str] = None) -> None:
    conn.execute("DELETE FROM app.sso_states WHERE org_id = %s AND expires_at < now()",
                 (org_id,))
    conn.execute("INSERT INTO app.sso_states (state_hash, org_id, nonce, code_verifier, "
                 "expires_at) VALUES (%s, %s, %s, %s, %s)",
                 (sha256_hex(state), org_id, nonce, verifier,
                  datetime.now(timezone.utc) + STATE_TTL))


def _consume_state(conn, org_id: UUID, state: str) -> dict:
    r = conn.execute("DELETE FROM app.sso_states WHERE state_hash = %s AND org_id = %s AND "
                     "expires_at > now() RETURNING nonce, code_verifier",
                     (sha256_hex(state or ""), org_id)).fetchone()
    if not r:
        raise SignInRefused("sign-in request expired or was already used; start again")
    return r


# ------------------------------------------------------------------ OIDC

def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def oidc_start(conn, cfg: dict, org_id: UUID, redirect_uri: str) -> str:
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(48)
    _store_state(conn, org_id, state, nonce, verifier)
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    q = urllib.parse.urlencode({
        "response_type": "code", "client_id": cfg["oidc_client_id"],
        "redirect_uri": redirect_uri, "scope": "openid email profile",
        "state": state, "nonce": nonce,
        "code_challenge": challenge, "code_challenge_method": "S256"})
    sep = "&" if "?" in cfg["oidc_authorize_url"] else "?"
    return f"{cfg['oidc_authorize_url']}{sep}{q}"


def _http_json(url: str, data: Optional[dict] = None, timeout: float = 10) -> dict:
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method="POST" if body else "GET")
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def oidc_finish(conn, cfg: dict, org_id: UUID, state: str, code: str,
                redirect_uri: str) -> dict:
    """Exchange the code and return verified ID-token claims."""
    from authlib.jose import JsonWebKey, jwt
    from authlib.jose.errors import JoseError

    st = _consume_state(conn, org_id, state)
    try:
        tokens = _http_json(cfg["oidc_token_url"], {
            "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
            "client_id": cfg["oidc_client_id"], "client_secret": cfg["oidc_client_secret"],
            "code_verifier": st["code_verifier"]})
        keys = JsonWebKey.import_key_set(_http_json(cfg["oidc_jwks_url"]))
    except Exception as exc:  # noqa: BLE001
        raise SignInRefused(f"identity provider exchange failed: {exc}")
    if "id_token" not in tokens:
        raise SignInRefused("identity provider returned no id_token")
    try:
        claims = jwt.decode(tokens["id_token"], keys, claims_options={
            "iss": {"essential": True, "value": cfg["oidc_issuer"]},
            "aud": {"essential": True, "value": cfg["oidc_client_id"]},
            "nonce": {"essential": True, "value": st["nonce"]},
            "exp": {"essential": True}, "sub": {"essential": True}})
        claims.validate(leeway=60)
    except JoseError as exc:
        raise SignInRefused(f"ID token rejected: {exc}")
    return dict(claims)


# ------------------------------------------------------------------ SAML

def saml_settings(cfg: dict, base_url: str, slug: str) -> dict:
    sp = f"{base_url}/ui/sso/{slug}/saml"
    return {
        "strict": True, "debug": False,
        "sp": {"entityId": f"{sp}/metadata",
               "assertionConsumerService": {
                   "url": f"{sp}/acs",
                   "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"},
               "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"},
        "idp": {"entityId": cfg["saml_idp_entity_id"],
                "singleSignOnService": {
                    "url": cfg["saml_idp_sso_url"],
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"},
                "x509cert": cfg["saml_idp_cert"]},
        "security": {"wantAssertionsSigned": True, "wantMessagesSigned": False,
                     "requestedAuthnContext": False, "rejectDeprecatedAlgorithm": True,
                     # NameID-only assertions are valid SAML; identity comes from NameID
                     "wantAttributeStatement": False},
    }


def saml_request_data(url: urllib.parse.SplitResult, post: Optional[dict] = None) -> dict:
    return {"https": "on" if url.scheme == "https" else "off",
            "http_host": url.hostname, "server_port": str(url.port or
                                                          (443 if url.scheme == "https" else 80)),
            "script_name": url.path, "get_data": dict(urllib.parse.parse_qsl(url.query)),
            "post_data": post or {}}


def saml_start(conn, cfg: dict, org_id: UUID, base_url: str, slug: str,
               request_data: dict) -> str:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    auth = OneLogin_Saml2_Auth(request_data, saml_settings(cfg, base_url, slug))
    url = auth.login()
    _store_state(conn, org_id, auth.get_last_request_id(), "saml")
    return url


def saml_finish(conn, cfg: dict, org_id: UUID, base_url: str, slug: str,
                request_data: dict) -> dict:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.response import OneLogin_Saml2_Response
    settings = saml_settings(cfg, base_url, slug)
    raw = request_data["post_data"].get("SAMLResponse", "")
    try:
        from onelogin.saml2.settings import OneLogin_Saml2_Settings
        in_response_to = OneLogin_Saml2_Response(
            OneLogin_Saml2_Settings(settings), raw).document.get("InResponseTo")
    except Exception:  # noqa: BLE001
        raise SignInRefused("malformed SAML response")
    _consume_state(conn, org_id, in_response_to or "")
    auth = OneLogin_Saml2_Auth(request_data, settings)
    auth.process_response(request_id=in_response_to)
    if auth.get_errors() or not auth.is_authenticated():
        raise SignInRefused("SAML response rejected: " + (auth.get_last_error_reason()
                                                          or ", ".join(auth.get_errors())))
    attrs = auth.get_attributes()
    return {"email": auth.get_nameid(), "sub": auth.get_nameid(),
            "name": (attrs.get("displayName") or [None])[0]}
