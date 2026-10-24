"""tenant-workspaces (group 8): targets, jobs, immutable history, isolation."""

import os
import unittest

import pgfixture

if pgfixture.available():
    from harness import Service
    from ssl_doctor import agent


def setUpModule():
    global SVC
    SVC = Service()


def tearDownModule():
    SVC.stop()


def doc(status_tls_chain, overall):
    return {"schema_version": "1.0", "tool": "t", "generated_utc": "t",
            "summary": {s: 0 for s in ("PASS", "FAIL", "WARNING", "NOT TESTED")},
            "diagnosis": {"overall": overall, "causes": [], "notes": []},
            "findings": [{"check": "tls.chain", "title": "c", "status": status_tls_chain,
                          "scope": "remote-net", "evidence": []},
                         {"check": "tls.verify", "title": "v", "status": "PASS",
                          "scope": "remote-net", "evidence": []}]}


def org_world(org):
    """Agent + target + one finished job/result in `org`; returns ids."""
    with SVC.client(org) as c:
        tok = c.post("/v1/enrollment-tokens", json={"name": "a", "role": "client"}).json()
        st = agent.AgentClient(SVC.url).enroll(tok["token"])
        t = c.post("/v1/targets", json={"host": "shop.example", "port": 443,
                                        "agent_ids": [st["agent_id"]]}).json()
        job = c.post(f"/v1/targets/{t['id']}/scans").json()[0]
        cl = agent.AgentClient(SVC.url, st["credential"])
        claimed = cl.next_job(wait=5)
        res = cl.upload(claimed["job_id"], doc("PASS", "PASS"))
        ch = c.post("/v1/channels", json={"kind": "email", "address": f"ops@{org}.example"})
        user = c.post("/v1/members", json={"email": f"m-{os.urandom(4).hex()}@{org}.example",
                                           "role": "viewer"}).json()
    return {"agent": st, "target": t["id"], "job": job["id"], "result": res["result_id"],
            "channel": ch.json()["id"], "user": user["id"]}


@unittest.skipUnless(pgfixture.available(), "PostgreSQL binaries not available")
class HistoryTests(unittest.TestCase):

    def test_repeat_scans_both_kept_and_comparable(self):
        w = org_world("A")
        cl = agent.AgentClient(SVC.url, w["agent"]["credential"])
        with SVC.client("A") as c:
            c.post(f"/v1/targets/{w['target']}/scans")
            second = cl.upload(cl.next_job(wait=5)["job_id"], doc("WARNING", "FAIL"))
            hist = c.get(f"/v1/targets/{w['target']}/results").json()
            self.assertEqual([h["id"] for h in hist], [w["result"], second["result_id"]])
            cmp = c.get("/v1/compare", params={"a": w["result"],
                                               "b": second["result_id"]}).json()
        changed = {r["check"]: (r["a"], r["b"]) for r in cmp["checks"] if r["changed"]}
        self.assertEqual(changed, {"tls.chain": ("PASS", "WARNING")})
        self.assertEqual((cmp["a"]["overall"], cmp["b"]["overall"]), ("PASS", "FAIL"))

    def test_results_are_immutable_for_the_app_role(self):
        import psycopg
        w = org_world("A")
        with self.assertRaises(psycopg.Error):
            with SVC.db.org(SVC.orgs["A"]) as conn:
                conn.execute("UPDATE app.scan_results SET overall = 'PASS' WHERE id = %s",
                             (w["result"],))
        with self.assertRaises(psycopg.Error):
            with SVC.db.org(SVC.orgs["A"]) as conn:
                conn.execute("DELETE FROM app.scan_results WHERE id = %s", (w["result"],))

    def test_job_completion_is_single_use(self):
        w = org_world("A")
        cl = agent.AgentClient(SVC.url, w["agent"]["credential"])
        with self.assertRaises(agent.AgentError) as cm:
            cl.upload(w["job"], doc("PASS", "PASS"))
        self.assertIn("409", str(cm.exception))

    def test_viewer_cannot_start_scan(self):
        w = org_world("A")
        with SVC.client("A", "viewer") as v:
            self.assertEqual(v.post(f"/v1/targets/{w['target']}/scans").status_code, 403)


@unittest.skipUnless(pgfixture.available(), "PostgreSQL binaries not available")
class CrossTenantTests(unittest.TestCase):
    """Org B, holding valid credentials, probes every org-A object it can name."""

    @classmethod
    def setUpClass(cls):
        cls.a = org_world("A")
        cls.b = org_world("B")

    def test_every_id_endpoint_hides_other_tenant(self):
        from ssldoctor_service.app import create_app
        ids = {"target_id": self.a["target"], "job_id": self.a["job"],
               "result_id": self.a["result"], "agent_id": self.a["agent"]["agent_id"],
               "channel_id": self.a["channel"], "user_id": self.a["user"]}
        bodies = {("PUT", "/v1/targets/{target_id}/monitoring"): {"interval_seconds": 3600},
                  ("PATCH", "/v1/members/{user_id}"): {"role": "viewer"}}
        exercised = set()
        routes = [r for r in create_app(SVC.db).routes
                  if "{" in getattr(r, "path", "") and r.path.startswith("/v1/")
                  and not r.path.startswith("/v1/agent/")]
        with SVC.client("B") as c:
            for r in routes:
                for method in r.methods:
                    path = r.path.format(**ids)
                    resp = c.request(method, path, json=bodies.get((method, r.path)))
                    self.assertEqual(resp.status_code, 404,
                                     f"{method} {r.path}: {resp.status_code} {resp.text}")
                    exercised.add((method, r.path))
            # query-parameter endpoint
            resp = c.get("/v1/compare", params={"a": self.a["result"], "b": self.b["result"]})
            self.assertEqual(resp.status_code, 404)
            exercised.add(("GET", "/v1/compare"))
        self.assertGreaterEqual(len(exercised), 13)

    def test_lists_show_only_own_objects(self):
        with SVC.client("B") as c:
            tids = [t["id"] for t in c.get("/v1/targets").json()]
            aids = [x["id"] for x in c.get("/v1/agents").json()]
        self.assertIn(self.b["target"], tids)
        self.assertNotIn(self.a["target"], tids)
        self.assertNotIn(self.a["agent"]["agent_id"], aids)

    def test_target_cannot_reference_other_tenants_agent(self):
        with SVC.client("B") as c:
            r = c.post("/v1/targets", json={"host": "x.example", "port": 443,
                                            "agent_ids": [self.a["agent"]["agent_id"]]})
        self.assertEqual(r.status_code, 404)

    def test_agent_cannot_touch_other_tenants_job(self):
        with SVC.client("A") as c:
            c.post(f"/v1/targets/{self.a['target']}/scans")
        b_agent = agent.AgentClient(SVC.url, self.b["agent"]["credential"])
        self.assertIsNone(b_agent.next_job(wait=0))          # A's queue is invisible
        with self.assertRaises(agent.AgentError) as cm:
            b_agent.upload(self.a["job"], doc("PASS", "PASS"))
        self.assertIn("404", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
