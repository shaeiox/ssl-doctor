"""certificate-monitoring (group 9): schedule, drift conditions, dedup, channels."""

import json
import os
import unittest
from datetime import datetime, timedelta, timezone

import pgfixture

if pgfixture.available():
    from harness import Service
    from receivers import SMTPSink, WebhookSink, wait_for
    from ssl_doctor import agent
    from ssldoctor_service import monitor

SHA_A, SHA_B = "a" * 64, "b" * 64
SECRET = "whsec-0123456789abcdef"


def setUpModule():
    global SVC, HOOK, SMTP, _env
    SVC, HOOK, SMTP = Service(), WebhookSink(), SMTPSink()
    _env = {k: os.environ.get(k) for k in ("SSLDOCTOR_SMTP_HOST", "SSLDOCTOR_SMTP_PORT")}
    os.environ.update({"SSLDOCTOR_SMTP_HOST": "127.0.0.1",
                       "SSLDOCTOR_SMTP_PORT": str(SMTP.port)})
    with SVC.client("A") as c:
        assert c.post("/v1/channels", json={"kind": "webhook", "address": HOOK.url,
                                            "secret": SECRET}).status_code == 201
        assert c.post("/v1/channels", json={"kind": "email",
                                            "address": "ops@a.example"}).status_code == 201


def tearDownModule():
    SVC.stop(), HOOK.stop(), SMTP.stop()
    for k, v in _env.items():
        os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


def mkdoc(sha=SHA_A, days_left=200, chain="complete", multiip="PASS"):
    not_after = (datetime.now(timezone.utc) + timedelta(days=days_left)).isoformat()
    return {"schema_version": "1.1", "tool": "t", "generated_utc": "t",
            "summary": {s: 0 for s in ("PASS", "FAIL", "WARNING", "NOT TESTED")},
            "diagnosis": {"overall": "PASS", "causes": [], "notes": []},
            "findings": [{"check": "tls.multiip", "title": "m", "status": multiip,
                          "scope": "remote-net", "evidence": []}],
            "facts": {"leaf": {"sha256": sha, "subject": "CN=shop.example",
                               "not_after": not_after}, "chain_status": chain}}


class World:
    """A monitored target in org A with a client agent that uploads given docs."""

    def __init__(self):
        with SVC.client("A") as c:
            tok = c.post("/v1/enrollment-tokens", json={"name": "a", "role": "client"}).json()
            self.state = agent.AgentClient(SVC.url).enroll(tok["token"])
            self.target = c.post("/v1/targets", json={
                "host": "shop.example", "port": 443,
                "agent_ids": [self.state["agent_id"]]}).json()["id"]
        self.agent = agent.AgentClient(SVC.url, self.state["credential"])

    def upload(self, doc):
        with SVC.client("A") as c:
            c.post(f"/v1/targets/{self.target}/scans")
        return self.agent.upload(self.agent.next_job(wait=5)["job_id"], doc)

    def alerts(self):
        with SVC.client("A") as c:
            return c.get(f"/v1/targets/{self.target}/alerts").json()

    def deliveries(self, condition):
        return [d for d in self.alerts()["deliveries"] if d["condition"] == condition]

    def hooks(self, condition):
        out = []
        for headers, body in HOOK.requests:
            p = json.loads(body)
            if p["target_id"] == self.target and p["condition"] == condition:
                out.append((headers, body, p))
        return out


@unittest.skipUnless(pgfixture.available(), "PostgreSQL binaries not available")
class SchedulerTests(unittest.TestCase):

    def test_daily_target_scanned_once_per_simulated_day(self):
        w = World()
        with SVC.client("A") as c:
            r = c.put(f"/v1/targets/{w.target}/monitoring", json={"interval_seconds": 86400})
            self.assertEqual(r.status_code, 200, r.text)
        t0 = datetime.now(timezone.utc) + timedelta(seconds=1)
        for hour in range(72):                                  # three simulated days
            monitor.schedule(SVC.db, t0 + timedelta(hours=hour))
        with SVC.db.org(SVC.orgs["A"]) as conn:
            jobs = conn.execute("SELECT count(*) AS n FROM app.scan_jobs WHERE target_id = %s",
                                (w.target,)).fetchone()["n"]
        self.assertEqual(jobs, 3)

    def test_interval_below_plan_minimum_rejected(self):
        w = World()
        with SVC.client("A") as c:
            r = c.put(f"/v1/targets/{w.target}/monitoring", json={"interval_seconds": 600})
        self.assertEqual(r.status_code, 422)
        self.assertIn("minimum of 3600s", r.text)

    def test_unmonitored_target_not_scheduled(self):
        w = World()
        monitor.schedule(SVC.db, datetime.now(timezone.utc) + timedelta(days=30))
        with SVC.db.org(SVC.orgs["A"]) as conn:
            n = conn.execute("SELECT count(*) AS n FROM app.scan_jobs WHERE target_id = %s",
                             (w.target,)).fetchone()["n"]
        self.assertEqual(n, 0)


@unittest.skipUnless(pgfixture.available(), "PostgreSQL binaries not available")
class ConditionTests(unittest.TestCase):

    def test_expiry_within_threshold_then_expired_alerts_twice(self):
        w = World()
        w.upload(mkdoc(days_left=20))                          # threshold default 30
        w.upload(mkdoc(days_left=-1))
        conds = {c["condition"]: c["is_open"] for c in w.alerts()["conditions"]}
        self.assertEqual(conds, {"expiry_soon": False, "expired": True})
        self.assertEqual(len(w.deliveries("expiry_soon")), 2)  # one per channel
        self.assertEqual(len(w.deliveries("expired")), 2)

    def test_chain_regression_cites_both_scans(self):
        w = World()
        first = w.upload(mkdoc(chain="complete"))
        second = w.upload(mkdoc(chain="incomplete"))
        self.assertEqual(second["alerts_opened"], ["chain_incomplete"])
        self.assertTrue(wait_for(lambda: w.hooks("chain_incomplete")))
        p = w.hooks("chain_incomplete")[0][2]
        self.assertEqual(p["previous_result_id"], first["result_id"])
        self.assertEqual(p["result_id"], second["result_id"])

    def test_leaf_change_alerts(self):
        w = World()
        w.upload(mkdoc(sha=SHA_A))
        r = w.upload(mkdoc(sha=SHA_B))
        self.assertEqual(r["alerts_opened"], ["leaf_changed:" + SHA_B])

    def test_configured_chain_facts_neither_alert_nor_hide_a_leaf_change(self):
        """1.7 server-agent documents carry facts.certificates but no leaf."""
        w = World()
        w.upload(mkdoc(sha=SHA_A))
        server_doc = mkdoc()
        server_doc["schema_version"] = "1.7"
        server_doc["facts"] = {"certificates": {"configured:/etc/ssl/a.pem": {
            "source": "configured", "status": "broken", "certificates": []}}}
        self.assertEqual(w.upload(server_doc)["alerts_opened"], [])
        r = w.upload(mkdoc(sha=SHA_B))
        self.assertEqual(r["alerts_opened"], ["leaf_changed:" + SHA_B])

    def test_expired_intermediate_alerts(self):
        w = World()
        doc = mkdoc()
        doc["findings"].append({"check": "chain.validity", "title": "v", "status": "FAIL",
                                "scope": "remote-net",
                                "evidence": ["position 2 ('Int'): expired 3 days ago"]})
        r = w.upload(doc)
        self.assertEqual(r["alerts_opened"], ["chain_certificate_invalid"])

    def test_endpoint_inconsistency_alerts(self):
        w = World()
        r = w.upload(mkdoc(multiip="WARNING"))
        self.assertEqual(r["alerts_opened"], ["endpoint_inconsistent"])


@unittest.skipUnless(pgfixture.available(), "PostgreSQL binaries not available")
class DedupAndChannelTests(unittest.TestCase):

    def test_three_identical_regressions_send_exactly_one_alert(self):
        w = World()
        w.upload(mkdoc(chain="complete"))
        for _ in range(3):
            w.upload(mkdoc(chain="incomplete"))
        monitor.dispatch(SVC.db)
        self.assertTrue(wait_for(lambda: all(d["status"] == "sent"
                                             for d in w.deliveries("chain_incomplete"))))
        self.assertEqual(len(w.deliveries("chain_incomplete")), 2)   # webhook + email
        self.assertEqual(len(w.hooks("chain_incomplete")), 1)
        mails = [m for m in SMTP.messages if w.target in m["data"]
                 and "chain_incomplete" in m["data"]]
        self.assertEqual(len(mails), 1)
        self.assertEqual(mails[0]["to"], ["ops@a.example"])

    def test_condition_rearms_after_clearing(self):
        w = World()
        w.upload(mkdoc(chain="incomplete"))
        w.upload(mkdoc(chain="complete"))
        r = w.upload(mkdoc(chain="incomplete"))
        self.assertEqual(r["alerts_opened"], ["chain_incomplete"])
        self.assertEqual(len(w.deliveries("chain_incomplete")), 4)   # 2 openings x 2 channels

    def test_webhook_is_hmac_signed(self):
        w = World()
        w.upload(mkdoc(multiip="WARNING"))
        self.assertTrue(wait_for(lambda: w.hooks("endpoint_inconsistent")))
        headers, body, _p = w.hooks("endpoint_inconsistent")[0]
        headers = {k.lower(): v for k, v in headers.items()}
        expected = monitor.sign_webhook(SECRET, headers["x-ssldoctor-timestamp"], body)
        self.assertEqual(headers["x-ssldoctor-signature"], expected)

    def test_failed_delivery_is_retried_then_marked_failed(self):
        with SVC.client("B") as c:
            c.post("/v1/channels", json={"kind": "webhook",
                                         "address": "http://127.0.0.1:9/unreachable"})
            tok = c.post("/v1/enrollment-tokens", json={"name": "b", "role": "client"}).json()
            st = agent.AgentClient(SVC.url).enroll(tok["token"])
            tid = c.post("/v1/targets", json={"host": "b.example", "port": 443,
                                              "agent_ids": [st["agent_id"]]}).json()["id"]
            c.post(f"/v1/targets/{tid}/scans")
            cl = agent.AgentClient(SVC.url, st["credential"])
            cl.upload(cl.next_job(wait=5)["job_id"], mkdoc(multiip="WARNING"))
            for _ in range(6):
                monitor.dispatch(SVC.db, max_attempts=3)
            d = c.get(f"/v1/targets/{tid}/alerts").json()["deliveries"]
        self.assertEqual([(x["status"], x["attempts"]) for x in d], [("failed", 3)])


if __name__ == "__main__":
    unittest.main()
