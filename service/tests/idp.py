"""Fake identity providers for tests: OIDC (RS256 + JWKS + PKCE) and SAML 2.0."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import http.server
import json
import threading
import time
import urllib.parse
import uuid

from authlib.jose import JsonWebKey, jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _pem_private(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


class OIDCProvider:
    """Authorize -> immediate redirect with a code; token endpoint checks PKCE."""

    def __init__(self, client_id="ssl-doctor", client_secret="s3cret-client"):
        self.client_id, self.client_secret = client_id, client_secret
        self.key, self.other_key = _rsa(), _rsa()
        self.codes = {}
        self.email, self.sub = "", ""
        self.tamper = None          # None | 'aud' | 'nonce' | 'expired' | 'key'
        idp = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, code, obj):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):  # noqa: N802
                u = urllib.parse.urlsplit(self.path)
                q = dict(urllib.parse.parse_qsl(u.query))
                if u.path == "/authorize":
                    code = uuid.uuid4().hex
                    idp.codes[code] = q
                    loc = q["redirect_uri"] + "?" + urllib.parse.urlencode(
                        {"code": code, "state": q["state"]})
                    self.send_response(302)
                    self.send_header("Location", loc)
                    self.end_headers()
                elif u.path == "/jwks":
                    pub = JsonWebKey.import_key(idp.key.public_key().public_bytes(
                        serialization.Encoding.PEM,
                        serialization.PublicFormat.SubjectPublicKeyInfo),
                        {"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256"})
                    self._json(200, {"keys": [pub.as_dict()]})
                else:
                    self._json(404, {})

            def do_POST(self):  # noqa: N802
                form = dict(urllib.parse.parse_qsl(
                    self.rfile.read(int(self.headers["Content-Length"])).decode()))
                req = idp.codes.pop(form.get("code"), None)
                if not req or form.get("client_secret") != idp.client_secret:
                    return self._json(400, {"error": "invalid_grant"})
                challenge = base64.urlsafe_b64encode(hashlib.sha256(
                    form.get("code_verifier", "").encode()).digest()).rstrip(b"=").decode()
                if challenge != req.get("code_challenge"):
                    return self._json(400, {"error": "invalid_grant", "detail": "PKCE"})
                now = int(time.time())
                claims = {"iss": idp.issuer, "sub": idp.sub, "email": idp.email,
                          "aud": idp.client_id, "nonce": req["nonce"],
                          "iat": now, "exp": now + 300}
                if idp.tamper == "aud":
                    claims["aud"] = "someone-else"
                elif idp.tamper == "nonce":
                    claims["nonce"] = "replayed"
                elif idp.tamper == "expired":
                    claims.update(iat=now - 3600, exp=now - 1200)
                key = idp.other_key if idp.tamper == "key" else idp.key
                token = jwt.encode({"alg": "RS256", "kid": "k1"}, claims, _pem_private(key))
                self._json(200, {"access_token": "at", "token_type": "Bearer",
                                 "id_token": token.decode()})

        self._srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.issuer = f"http://127.0.0.1:{self._srv.server_address[1]}"
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()

    def config(self) -> dict:
        return {"protocol": "oidc", "oidc_issuer": self.issuer,
                "oidc_client_id": self.client_id, "oidc_client_secret": self.client_secret,
                "oidc_authorize_url": f"{self.issuer}/authorize",
                "oidc_token_url": f"{self.issuer}/token", "oidc_jwks_url": f"{self.issuer}/jwks"}

    def stop(self):
        self._srv.shutdown()


class SAMLProvider:
    """Builds signed SAML Responses for an SP's AuthnRequest."""

    entity_id = "https://idp.example.test/saml"
    sso_url = "https://idp.example.test/sso"

    def __init__(self):
        self.key = _rsa()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test SAML IdP")])
        now = dt.datetime.now(dt.timezone.utc)
        self.cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                     .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
                     .not_valid_before(now - dt.timedelta(days=1))
                     .not_valid_after(now + dt.timedelta(days=30))
                     .sign(self.key, hashes.SHA256()))
        self.cert_pem = self.cert.public_bytes(serialization.Encoding.PEM).decode()

    def config(self) -> dict:
        return {"protocol": "saml", "saml_idp_entity_id": self.entity_id,
                "saml_idp_sso_url": self.sso_url, "saml_idp_cert": self.cert_pem}

    @staticmethod
    def request_id(redirect_url: str) -> str:
        from onelogin.saml2.utils import OneLogin_Saml2_Utils
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(redirect_url).query))
        xml = OneLogin_Saml2_Utils.decode_base64_and_inflate(q["SAMLRequest"])
        import re
        return re.search(r'ID="([^"]+)"', xml.decode() if isinstance(xml, bytes) else xml).group(1)

    def response(self, request_id: str, acs: str, sp_entity: str, email: str,
                 sign: bool = True, tamper_email: str = "") -> str:
        from onelogin.saml2.constants import OneLogin_Saml2_Constants as C
        from onelogin.saml2.utils import OneLogin_Saml2_Utils
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        now = dt.datetime.now(dt.timezone.utc)
        t, before, later = (now.strftime(fmt), (now - dt.timedelta(minutes=5)).strftime(fmt),
                            (now + dt.timedelta(minutes=5)).strftime(fmt))
        assertion = f"""<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a{uuid.uuid4().hex}" Version="2.0" IssueInstant="{t}"><saml:Issuer>{self.entity_id}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{email}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{later}" Recipient="{acs}" InResponseTo="{request_id}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{before}" NotOnOrAfter="{later}"><saml:AudienceRestriction><saml:Audience>{sp_entity}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="{t}" SessionIndex="_s1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>"""
        if sign:
            assertion = OneLogin_Saml2_Utils.add_sign(
                assertion, _pem_private(self.key).decode(), self.cert_pem,
                sign_algorithm=C.RSA_SHA256, digest_algorithm=C.SHA256)
            assertion = assertion.decode() if isinstance(assertion, bytes) else assertion
            assertion = assertion.split("?>", 1)[-1] if assertion.startswith("<?xml") else assertion
        if tamper_email:
            assertion = assertion.replace(f">{email}<", f">{tamper_email}<")
        resp = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r{uuid.uuid4().hex}" Version="2.0" IssueInstant="{t}" Destination="{acs}" InResponseTo="{request_id}"><saml:Issuer>{self.entity_id}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>{assertion}</samlp:Response>"""
        return base64.b64encode(resp.encode()).decode()
