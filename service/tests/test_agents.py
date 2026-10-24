"""scan-agents (group 7): enrollment, outbound job loop, roles, read-only, revocation."""

import contextlib
import io
import unittest

import pgfixture

if pgfixture.available():
    from harness import Service
    from fixtures.pki import HOSTNAME, get_pki, openssl_available
    from fixtures.scan import trust_env
    from fixtures.tls_server import TLSServer
    from ssl_doctor import agent, contract
    from ssl_doctor import findings as F


def setUpModule():
    global SVC
    SVC = Service()


def tearDownModule():
    SVC.stop()


def enroll(role="client", org="A"):
    with SVC.client(org) as c:
        tok = c.post("/v1/enrollment-tokens", json={"name": f"{role}-agent", "role": role})
        assert tok.status_code == 201, tok.text
    data = agent.AgentClient(SVC.url).enroll(tok.json()["token"])
    return {"url": SVC.url, **data}, tok.json()["token"]


def target_for(state, port, org="A"):
    with SVC.client(org) as c:
        t = c.post("/v1/targets", json={"host": "127.0.0.1", "port": port, "sni": HOSTNAME,
                                        "agent_ids": [state["agent_id"]]})
        assert t.status_code == 201, t.text
        return t.json()["id"]


@unittest.skipUnless(pgfixture.available(), "PostgreSQL binaries not available")
class EnrollmentTests(unittest.TestCase):

    def test_successful_enrollment_registers_to_org(self):
        state, _ = enroll()
        self.assertEqual(state["org_id"], str(SVC.orgs["A"]))
        with SVC.client("A") as a, SVC.client("B") as b:
            self.assertIn(state["agent_id"], [x["id"] for x in a.get("/v1/agents").json()])
            self.assertNotIn(state["agent_id"], [x["id"] for x in b.get("/v1/agents").json()])

    def test_token_reuse_refused(self):
        _state, token = enroll()
        with self.assertRaises(agent.AgentError) as cm:
            agent.AgentClient(SVC.url).enroll(token)
        self.assertIn("403", str(cm.exception))

    def test_cli_enroll_stores_credential_0600(self):
        import os
        import stat
        import tempfile
        with SVC.client() as c:
            tok = c.post("/v1/enrollment-tokens", json={"name": "cli", "role": "client"}).json()
        path = os.path.join(tempfile.mkdtemp(), "agent.json")
        with contextlib.redirect_stdout(io.StringIO()):
            rc = agent.main(["enroll", SVC.url, tok["token"], "--state", path])
        self.assertEqual(rc, 0)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(agent.load_state(path)["role"], "client")


@unittest.skipUnless(pgfixture.available() and openssl_available(),
                     "PostgreSQL or openssl not available")
class JobLoopTests(unittest.TestCase):

    def test_client_agent_completes_client_job(self):
        state, _ = enroll("client")
        with TLSServer(get_pki(), "leaf-only") as srv, trust_env(("root", "intermediate")):
            tid = target_for(state, srv.port)
            with SVC.client() as c:
                job = c.post(f"/v1/targets/{tid}/scans").json()[0]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(agent.serve(state, once=True, wait=5), 0)
        with SVC.client() as c:
            self.assertEqual(c.get(f"/v1/jobs/{job['id']}").json()["status"], "done")
            results = c.get(f"/v1/targets/{tid}/results").json()
            self.assertEqual(len(results), 1)
            doc = c.get(f"/v1/results/{results[0]['id']}").json()["document"]
        self.assertEqual(contract.validate(doc), [])
        # the customer scenario, diagnosed remotely: server cause, not PASS
        self.assertEqual(doc["diagnosis"]["overall"], "FAIL")
        self.assertEqual(doc["diagnosis"]["causes"][0]["origin"], "server")

    def test_server_job_sent_to_client_agent_is_declined(self):
        state, _ = enroll("client")
        tid = target_for(state, 443)
        with SVC.client() as c:
            job = c.post(f"/v1/targets/{tid}/scans", json={"assignments": [
                {"agent_id": state["agent_id"], "kind": "server"}]}).json()[0]
        with contextlib.redirect_stdout(io.StringIO()):
            agent.serve(state, once=True, wait=5)
        with SVC.client() as c:
            j = c.get(f"/v1/jobs/{job['id']}").json()
        self.assertEqual(j["status"], "not_runnable")
        self.assertIn("cannot run 'server' jobs", j["error"])


@unittest.skipUnless(pgfixture.available() and openssl_available(),
                     "PostgreSQL or openssl not available")
class ReadOnlyServerAgentTests(unittest.TestCase):

    def test_unreadable_nginx_config_is_not_tested_with_reason(self):
        with TLSServer(get_pki(), "full-chain") as srv:
            doc = agent.run_server_checks("127.0.0.1", srv.port, HOSTNAME)
        conf = [f for f in doc["findings"] if f["check"] == "nginx.conf"][0]
        self.assertEqual(conf["status"], F.NOT_TESTED)
        self.assertIn("no readable nginx configuration for account", conf["evidence"][0])
        self.assertEqual(contract.validate(doc), [])


@unittest.skipUnless(pgfixture.available(), "PostgreSQL binaries not available")
class RevocationTests(unittest.TestCase):

    def test_revoked_agent_upload_refused_and_nothing_stored(self):
        state, _ = enroll("client")
        tid = target_for(state, 443)
        cl = agent.AgentClient(SVC.url, state["credential"])
        with SVC.client() as c:
            c.post(f"/v1/targets/{tid}/scans")
            job = cl.next_job(wait=5)
            self.assertIsNotNone(job)
            self.assertEqual(c.post(f"/v1/agents/{state['agent_id']}/revoke").status_code, 200)
        doc = {"schema_version": "1.0", "tool": "t", "generated_utc": "t", "findings": [],
               "summary": {s: 0 for s in ("PASS", "FAIL", "WARNING", "NOT TESTED")}}
        with self.assertRaises(agent.AgentError) as cm:
            cl.upload(job["job_id"], doc)
        self.assertIn("401", str(cm.exception))
        with SVC.client() as c:
            self.assertEqual(c.get(f"/v1/targets/{tid}/results").json(), [])


if __name__ == "__main__":
    unittest.main()
