"""identity-access (group 10): SSO (OIDC + SAML), enforcement, RBAC, SCIM."""

import os
import unittest
import urllib.parse

import pgfixture

if pgfixture.available():
    import httpx
    import psycopg
    from harness import Service
    from idp import OIDCProvider, SAMLProvider
    from ssldoctor_service import db as dbmod


def setUpModule():
    global SVC, OIDC
    SVC, OIDC = Service(), OIDCProvider()


def tearDownModule():
    SVC.stop(), OIDC.stop()


def new_org(name):
    """A fresh org (own SSO config), its owner token and slug."""
    tok = "own-" + os.urandom(12).hex()
    org = dbmod.bootstrap_org(SVC.admin_dsn, name, tok)
    with psycopg.connect(SVC.admin_dsn) as conn:
        slug = conn.execute("SELECT slug FROM app.organizations WHERE id = %s",
                            (org,)).fetchone()[0]
    api = httpx.Client(base_url=SVC.url, timeout=30, headers={"Authorization": f"Bearer {tok}"})
    return org, tok, slug, api


def browser():
    return httpx.Client(base_url=SVC.url, timeout=30, follow_redirects=False)


def oidc_signin(slug):
    """Drive the browser hops by hand: SP -> IdP -> SP callback."""
    with browser() as b:
        r = b.get(f"/ui/sso/{slug}/start")
        assert r.status_code == 303, r.text
        idp = httpx.get(r.headers["location"], follow_redirects=False)
        assert idp.status_code == 302, idp.text
        cb = urllib.parse.urlsplit(idp.headers["location"])
        r = b.get(f"{cb.path}?{cb.query}")
        page = b.get("/ui") if b.cookies.get("ssldoctor_session") else None
        return r, page


def actions(org):
    with SVC.db.org(org) as conn:
        return [r["action"] for r in conn.execute(
            "SELECT action FROM app.audit_log WHERE org_id = %s ORDER BY seq", (org,))]


@unittest.skipUnless(pgfixture.available(), "PostgreSQL binaries not available")
class OIDCTests(unittest.TestCase):

    def setUp(self):
        self.org, self.tok, self.slug, self.api = new_org("oidc corp")
        r = self.api.put("/v1/sso", json=OIDC.config())
        self.assertEqual(r.status_code, 200, r.text)
        self.api.post("/v1/members", json={"email": "alice@oidc.example", "role": "engineer"})
        OIDC.email, OIDC.sub, OIDC.tamper = "alice@oidc.example", "idp|alice", None

    def tearDown(self):
        self.api.close()

    def test_signin_creates_session(self):
        r, page = oidc_signin(self.slug)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(page.status_code, 200)
        self.assertIn("Targets", page.text)
        self.assertIn("member.signin", actions(self.org))

    def test_rejected_id_tokens(self):
        for tamper in ("aud", "nonce", "expired", "key"):
            with self.subTest(tamper=tamper):
                OIDC.tamper = tamper
                r, page = oidc_signin(self.slug)
                self.assertEqual(r.status_code, 303)
                self.assertIn("error=", r.headers["location"])
                self.assertIsNone(page)

    def test_unknown_user_refused_without_jit(self):
        OIDC.email, OIDC.sub = "mallory@oidc.example", "idp|mallory"
        r, page = oidc_signin(self.slug)
        self.assertIsNone(page)
        self.assertIn("no+member", r.headers["location"].replace("%20", "+"))

    def test_jit_provisions_default_role(self):
        self.api.put("/v1/sso", json={**OIDC.config(), "jit_provisioning": True,
                                      "default_role": "viewer"})
        OIDC.email, OIDC.sub = "bob@oidc.example", "idp|bob"
        _r, page = oidc_signin(self.slug)
        self.assertEqual(page.status_code, 200)
        bob = [m for m in self.api.get("/v1/members").json() if m["email"] == "bob@oidc.example"]
        self.assertEqual(bob[0]["role"], "viewer")

    def test_state_is_single_use(self):
        with browser() as b:
            r = b.get(f"/ui/sso/{self.slug}/start")
            idp = httpx.get(r.headers["location"], follow_redirects=False)
            cb = urllib.parse.urlsplit(idp.headers["location"])
            b.get(f"{cb.path}?{cb.query}")
            replay = b.get(f"{cb.path}?{cb.query}")
        self.assertEqual(replay.status_code, 303)
        self.assertIn("error=", replay.headers["location"])


@unittest.skipUnless(pgfixture.available(), "PostgreSQL binaries not available")
class SAMLTests(unittest.TestCase):

    def setUp(self):
        self.idp = SAMLProvider()
        self.org, self.tok, self.slug, self.api = new_org("saml corp")
        self.assertEqual(self.api.put("/v1/sso", json=self.idp.config()).status_code, 200)
        self.api.post("/v1/members", json={"email": "carol@saml.example", "role": "admin"})
        self.acs = f"{SVC.url}/ui/sso/{self.slug}/saml/acs"
        self.sp = f"{SVC.url}/ui/sso/{self.slug}/saml/metadata"

    def tearDown(self):
        self.api.close()

    def post_response(self, **kw):
        with browser() as b:
            r = b.get(f"/ui/sso/{self.slug}/start")
            self.assertTrue(r.headers["location"].startswith(self.idp.sso_url))
            req_id = self.idp.request_id(r.headers["location"])
            resp = self.idp.response(req_id, self.acs, self.sp, "carol@saml.example", **kw)
            r = b.post(f"/ui/sso/{self.slug}/saml/acs", data={"SAMLResponse": resp})
            page = b.get("/ui") if b.cookies.get("ssldoctor_session") else None
        return r, page

    def test_signed_assertion_signs_in(self):
        r, page = self.post_response()
        self.assertEqual(r.status_code, 200, r.headers.get("location"))
        self.assertEqual(page.status_code, 200)

    def test_unsigned_assertion_rejected(self):
        r, page = self.post_response(sign=False)
        self.assertEqual(r.status_code, 303)
        self.assertIsNone(page)

    def test_tampered_assertion_rejected(self):
        r, page = self.post_response(tamper_email="mallory@saml.example")
        self.assertEqual(r.status_code, 303)
        self.assertIsNone(page)

    def test_sp_metadata_published(self):
        r = httpx.get(self.sp)
        self.assertEqual(r.status_code, 200)
        self.assertIn(self.acs, r.text)


@unittest.skipUnless(pgfixture.available(), "PostgreSQL binaries not available")
class EnforcementTests(unittest.TestCase):

    def test_enforced_sso_refuses_token_signin(self):
        org, tok, slug, api = new_org("enforced corp")
        with api:
            api.put("/v1/sso", json={**OIDC.config(), "enforced": True})
            with browser() as b:
                r = b.post("/ui/login", data={"token": tok})
                self.assertEqual(r.status_code, 303)
                self.assertEqual(r.headers["location"], f"/ui/sso/{slug}/start")
                self.assertIsNone(b.cookies.get("ssldoctor_session"))
        self.assertIn("sso.enforce", actions(org))
        self.assertIn("sso.configure", actions(org))


@unittest.skipUnless(pgfixture.available(), "PostgreSQL binaries not available")
class RBACTests(unittest.TestCase):

    def test_viewer_cannot_start_scan_or_manage(self):
        with SVC.client("A", "viewer") as v:
            self.assertEqual(v.post("/v1/members", json={"email": "x@a.example",
                                                         "role": "viewer"}).status_code, 403)

    def test_engineer_cannot_revoke_agent_or_manage_members(self):
        with SVC.client("A") as owner:
            tok = owner.post("/v1/enrollment-tokens", json={"name": "e", "role": "client"}).json()
        from ssl_doctor import agent
        st = agent.AgentClient(SVC.url).enroll(tok["token"])
        with SVC.client("A", "engineer") as e:
            self.assertEqual(e.post(f"/v1/agents/{st['agent_id']}/revoke").status_code, 403)
            self.assertEqual(e.post("/v1/members", json={"email": "y@a.example",
                                                         "role": "viewer"}).status_code, 403)
            self.assertEqual(e.put("/v1/sso", json=OIDC.config()).status_code, 403)

    def test_role_change_applies_to_existing_token_immediately(self):
        org, tok, slug, api = new_org("rbac corp")
        with api:
            u = api.post("/v1/members", json={"email": "dan@rbac.example",
                                              "role": "engineer"}).json()
            dtok = "dan-" + os.urandom(8).hex()
            with psycopg.connect(SVC.admin_dsn) as conn:
                conn.execute("INSERT INTO app.api_tokens (org_id, name, token_hash, role, "
                             "user_id) VALUES (%s, 'dan', %s, 'engineer', %s)",
                             (org, dbmod.sha256_hex(dtok), u["id"]))
            dan = httpx.Client(base_url=SVC.url, headers={"Authorization": f"Bearer {dtok}"})
            with dan:
                ch = {"kind": "email", "address": "d@rbac.example"}
                self.assertEqual(dan.post("/v1/channels", json=ch).status_code, 403)
                api.patch(f"/v1/members/{u['id']}", json={"role": "admin"})
                self.assertEqual(dan.post("/v1/channels", json=ch).status_code, 201)
        self.assertIn("member.role_change", actions(org))

    def test_admin_cannot_grant_owner_and_last_owner_is_protected(self):
        org, tok, slug, api = new_org("owners corp")
        with api:
            admin = api.post("/v1/members", json={"email": "ad@o.example", "role": "admin"}).json()
            atok = "adm-" + os.urandom(8).hex()
            with psycopg.connect(SVC.admin_dsn) as conn:
                conn.execute("INSERT INTO app.api_tokens (org_id, name, token_hash, role, "
                             "user_id) VALUES (%s, 'a', %s, 'admin', %s)",
                             (org, dbmod.sha256_hex(atok), admin["id"]))
            owner = [m for m in api.get("/v1/members").json() if m["role"] == "owner"][0]
            with httpx.Client(base_url=SVC.url, headers={"Authorization": f"Bearer {atok}"}) as a:
                self.assertEqual(a.patch(f"/v1/members/{admin['id']}",
                                         json={"role": "owner"}).status_code, 403)
            self.assertEqual(api.patch(f"/v1/members/{owner['id']}",
                                       json={"role": "admin"}).status_code, 409)


@unittest.skipUnless(pgfixture.available(), "PostgreSQL binaries not available")
class SCIMTests(unittest.TestCase):

    def setUp(self):
        self.org, self.tok, self.slug, self.api = new_org("scim corp")
        self.api.put("/v1/sso", json={**OIDC.config(), "default_role": "engineer"})
        scim_tok = self.api.post("/v1/sso/scim-token").json()["token"]
        self.scim = httpx.Client(base_url=f"{SVC.url}/scim/v2", timeout=30,
                                 headers={"Authorization": f"Bearer {scim_tok}"})

    def tearDown(self):
        self.api.close(), self.scim.close()

    def provision(self, email):
        r = self.scim.post("/Users", json={"schemas": ["urn:ietf:params:scim:schemas:core:2.0:"
                                                       "User"], "userName": email,
                                           "externalId": "ext-" + email, "active": True})
        self.assertEqual(r.status_code, 201, r.text)
        uid = r.json()["id"]
        tok = "u-" + os.urandom(8).hex()
        with psycopg.connect(SVC.admin_dsn) as conn:
            conn.execute("INSERT INTO app.api_tokens (org_id, name, token_hash, role, user_id) "
                         "VALUES (%s, 'u', %s, 'engineer', %s)",
                         (self.org, dbmod.sha256_hex(tok), uid))
        return uid, tok

    def test_deprovisioned_members_token_is_refused(self):
        uid, tok = self.provision("erin@scim.example")
        with httpx.Client(base_url=SVC.url, headers={"Authorization": f"Bearer {tok}"}) as erin:
            self.assertEqual(erin.get("/v1/targets").status_code, 200)
            r = self.scim.patch(f"/Users/{uid}", json={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{"op": "replace", "path": "active", "value": False}]})
            self.assertEqual(r.json()["active"], False)
            self.assertEqual(erin.get("/v1/targets").status_code, 401)
        self.assertIn("member.remove", actions(self.org))

    def test_delete_and_filter(self):
        uid, tok = self.provision("frank@scim.example")
        found = self.scim.get("/Users", params={"filter": 'userName eq "frank@scim.example"'})
        self.assertEqual(found.json()["totalResults"], 1)
        self.assertEqual(self.scim.delete(f"/Users/{uid}").status_code, 204)
        with httpx.Client(base_url=SVC.url, headers={"Authorization": f"Bearer {tok}"}) as f:
            self.assertEqual(f.get("/v1/targets").status_code, 401)

    def test_deprovisioned_user_cannot_sso_back_in(self):
        uid, _tok = self.provision("gina@scim.example")
        self.scim.delete(f"/Users/{uid}")
        OIDC.email, OIDC.sub, OIDC.tamper = "gina@scim.example", "ext-gina@scim.example", None
        r, page = oidc_signin(self.slug)
        self.assertIsNone(page)
        self.assertIn("deprovisioned", urllib.parse.unquote(r.headers["location"]))

    def test_scim_token_cannot_reach_other_org(self):
        uid, _tok = self.provision("hank@scim.example")
        _org, _t, _s, other = new_org("other scim corp")
        with other:
            other.put("/v1/sso", json=OIDC.config())
            otok = other.post("/v1/sso/scim-token").json()["token"]
        with httpx.Client(base_url=f"{SVC.url}/scim/v2",
                          headers={"Authorization": f"Bearer {otok}"}) as o:
            self.assertEqual(o.get(f"/Users/{uid}").status_code, 404)
            self.assertEqual(o.delete(f"/Users/{uid}").status_code, 404)
            listed = [u["id"] for u in o.get("/Users").json()["Resources"]]
            self.assertNotIn(uid, listed)                 # only that org's own users
        self.assertTrue(self.scim.get(f"/Users/{uid}").json()["active"])

    def test_bad_scim_token_gets_scim_error(self):
        with httpx.Client(base_url=f"{SVC.url}/scim/v2",
                          headers={"Authorization": "Bearer nope"}) as c:
            r = c.get("/Users")
        self.assertEqual(r.status_code, 401)
        self.assertIn("urn:ietf:params:scim:api:messages:2.0:Error", r.text)


if __name__ == "__main__":
    unittest.main()
