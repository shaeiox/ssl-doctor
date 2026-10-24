"""tenant-workspaces 8.4: dashboard views, scan from UI, export, isolation."""

import contextlib
import json
import re
import unittest

import pgfixture

if pgfixture.available():
    import httpx
    from harness import Service
    from test_tenancy import doc, org_world
    from ssl_doctor import agent, contract


def setUpModule():
    global SVC
    import test_tenancy
    SVC = test_tenancy.SVC = Service()


def tearDownModule():
    SVC.stop()


@contextlib.contextmanager
def browser(org="A", role="owner"):
    """A signed-in browser session (cookie jar)."""
    with httpx.Client(base_url=SVC.url, timeout=60, follow_redirects=False) as c:
        r = c.post("/ui/login", data={"token": SVC.tokens[(org, role)]})
        assert r.status_code == 200 and "url=/ui" in r.text, (r.status_code, r.text)
        assert c.cookies.get("ssldoctor_session"), "no session cookie"
        yield c


@unittest.skipUnless(pgfixture.available(), "PostgreSQL binaries not available")
class DashboardTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.w = org_world("A")
        cls.b = org_world("B")

    def test_requires_sign_in(self):
        with httpx.Client(base_url=SVC.url) as c:
            r = c.get("/ui")
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/login")

    def test_bad_token_rejected(self):
        with httpx.Client(base_url=SVC.url) as c:
            r = c.post("/ui/login", data={"token": "nope-not-a-token"})
        self.assertIn("error=", r.headers["location"])

    def test_session_cookie_flags(self):
        with httpx.Client(base_url=SVC.url) as c:
            r = c.post("/ui/login", data={"token": SVC.tokens[("A", "owner")]})
        cookie = r.headers["set-cookie"].lower()
        self.assertIn("httponly", cookie)
        self.assertIn("samesite=strict", cookie)

    def test_targets_history_result_and_export(self):
        with browser() as c:
            targets = c.get("/ui").text
            self.assertIn("shop.example:443", targets)
            self.assertIn(f"/ui/targets/{self.w['target']}", targets)
            hist = c.get(f"/ui/targets/{self.w['target']}").text
            self.assertIn(f"/ui/results/{self.w['result']}", hist)
            page = c.get(f"/ui/results/{self.w['result']}").text
            self.assertIn("Diagnosis", page)
            exported = c.get(f"/ui/results/{self.w['result']}/export.json")
        self.assertEqual(exported.status_code, 200)
        self.assertEqual(contract.validate(json.loads(exported.text)), [])

    def test_scan_from_ui_and_compare(self):
        cl = agent.AgentClient(SVC.url, self.w["agent"]["credential"])
        with browser() as c:
            r = c.post(f"/ui/targets/{self.w['target']}/scan")
            self.assertEqual(r.status_code, 303)
            second = cl.upload(cl.next_job(wait=5)["job_id"], doc("WARNING", "FAIL"))
            hist = c.get(f"/ui/targets/{self.w['target']}").text
            link = re.search(r"/ui/compare\?a=[0-9a-f-]+&b=[0-9a-f-]+", hist).group(0)
            self.assertIn(second["result_id"], link)
            cmp = c.get(link)
        self.assertEqual(cmp.status_code, 200)
        self.assertIn("tls.chain", cmp.text)

    def test_viewer_has_no_scan_button_and_cannot_post(self):
        with browser("A", "viewer") as c:
            self.assertNotIn("Scan now", c.get("/ui").text)
            self.assertEqual(c.post(f"/ui/targets/{self.w['target']}/scan").status_code, 403)

    def test_other_tenant_pages_are_404(self):
        with browser("B") as c:
            self.assertNotIn(self.w["target"], c.get("/ui").text)
            for path in (f"/ui/targets/{self.w['target']}", f"/ui/results/{self.w['result']}",
                         f"/ui/results/{self.w['result']}/export.json",
                         f"/ui/compare?a={self.w['result']}&b={self.b['result']}"):
                self.assertEqual(c.get(path).status_code, 404, path)
            self.assertEqual(c.post(f"/ui/targets/{self.w['target']}/scan").status_code, 404)

    def test_values_are_html_escaped(self):
        with SVC.client("A") as api:
            api.post("/v1/targets", json={"host": "<script>x</script>", "port": 443})
        with browser() as c:
            page = c.get("/ui").text
        self.assertNotIn("<script>x</script>", page)
        self.assertIn("&lt;script&gt;", page)


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(pgfixture.available(), "PostgreSQL binaries not available")
class SessionTests(unittest.TestCase):

    def test_cookie_holds_session_not_api_token(self):
        with browser() as c:
            self.assertNotEqual(c.cookies.get("ssldoctor_session"), SVC.tokens[("A", "owner")])

    def test_logout_revokes_session(self):
        with browser() as c:
            cookie = c.cookies.get("ssldoctor_session")
            c.get("/ui/logout")
        with httpx.Client(base_url=SVC.url, cookies={"ssldoctor_session": cookie}) as c:
            self.assertEqual(c.get("/ui").status_code, 303)
