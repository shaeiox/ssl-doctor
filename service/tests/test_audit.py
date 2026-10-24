"""audit-logging (group 11): recorded actions, tamper evidence, export."""

import json
import unittest
from datetime import datetime, timedelta, timezone

import pgfixture

if pgfixture.available():
    import psycopg
    from harness import Service
    from ssl_doctor import agent
    from ssldoctor_service import audit, monitor


def setUpModule():
    global SVC
    SVC = Service()


def tearDownModule():
    SVC.stop()


def entries(org="A"):
    with SVC.db.org(SVC.orgs[org]) as conn:
        rows = conn.execute("SELECT seq, actor, action, object, source_ip, entry FROM "
                            "app.audit_log WHERE org_id = %s ORDER BY seq",
                            (SVC.orgs[org],)).fetchall()
    return [{**r, "event": json.loads(r["entry"])} for r in rows]


def user_id(org, role):
    """The user behind one of the harness's API tokens."""
    with psycopg.connect(SVC.admin_dsn) as conn:
        return conn.execute("SELECT user_id FROM app.api_tokens WHERE token_hash = %s",
                            (audit.hashlib.sha256(SVC.tokens[(org, role)].encode())
                             .hexdigest(),)).fetchone()[0]


@unittest.skipUnless(pgfixture.available(), "PostgreSQL binaries not available")
class RecordedActionTests(unittest.TestCase):

    def test_agent_revocation_entry(self):
        with SVC.client("A") as c:
            tok = c.post("/v1/enrollment-tokens", json={"name": "r", "role": "client"}).json()
            st = agent.AgentClient(SVC.url).enroll(tok["token"])
            before = datetime.now(timezone.utc)
            c.post(f"/v1/agents/{st['agent_id']}/revoke")
        e = [x for x in entries() if x["action"] == "agent.revoke"][-1]
        self.assertEqual(e["actor"], f"user:{user_id('A', 'owner')}")
        self.assertEqual(e["object"], f"agent:{st['agent_id']}")
        self.assertEqual(e["source_ip"], "127.0.0.1")
        at = datetime.fromisoformat(e["event"]["at"])
        self.assertLessEqual(abs((at - before).total_seconds()), 5)

    def test_platform_actions_are_recorded(self):
        with SVC.client("A") as c:
            tok = c.post("/v1/enrollment-tokens", json={"name": "x", "role": "client"}).json()
            st = agent.AgentClient(SVC.url).enroll(tok["token"])
            t = c.post("/v1/targets", json={"host": "audit.example", "port": 443,
                                            "agent_ids": [st["agent_id"]]}).json()
            c.put(f"/v1/targets/{t['id']}/monitoring", json={"interval_seconds": 3600})
            c.post(f"/v1/targets/{t['id']}/scans")
            cl = agent.AgentClient(SVC.url, st["credential"])
            res = cl.upload(cl.next_job(wait=5)["job_id"], {
                "schema_version": "1.0", "tool": "t", "generated_utc": "t", "findings": [],
                "summary": {s: 0 for s in ("PASS", "FAIL", "WARNING", "NOT TESTED")}})
            c.get(f"/v1/results/{res['result_id']}/export")
            ch = c.post("/v1/channels", json={"kind": "email", "address": "a@a.example"}).json()
            c.delete(f"/v1/channels/{ch['id']}")
        monitor.schedule(SVC.db, datetime.now(timezone.utc) + timedelta(hours=2))
        seen = {(e["action"], e["actor"].split(":")[0]) for e in entries()}
        for expected in [("agent.enrollment_token", "user"), ("agent.enroll", "agent"),
                         ("target.create", "user"), ("target.monitoring", "user"),
                         ("scan.start", "user"), ("scan.start", "system"),
                         ("report.export", "user"), ("channel.create", "user"),
                         ("channel.delete", "user")]:
            self.assertIn(expected, seen)

    def test_dashboard_signin_recorded(self):
        import httpx
        with httpx.Client(base_url=SVC.url) as c:
            c.post("/ui/login", data={"token": SVC.tokens[("A", "viewer")]})
        e = [x for x in entries() if x["action"] == "member.signin"][-1]
        self.assertEqual(e["actor"], f"user:{user_id('A', 'viewer')}")

    def test_unknown_action_rejected(self):
        with self.assertRaises(ValueError):
            with SVC.db.org(SVC.orgs["A"]) as conn:
                audit.record(conn, SVC.orgs["A"], "system", "made.up")


@unittest.skipUnless(pgfixture.available(), "PostgreSQL binaries not available")
class TamperEvidenceTests(unittest.TestCase):

    def setUp(self):
        # fresh org per test: tampering is permanent by design
        import os
        from ssldoctor_service import db as dbmod
        self.org = dbmod.bootstrap_org(SVC.admin_dsn, "tamper", os.urandom(16).hex())
        with SVC.db.org(self.org) as conn:
            for i in range(5):
                audit.record(conn, self.org, "system", "scan.start", f"target:{i}")

    def verify(self):
        with SVC.db.org(self.org) as conn:
            return audit.verify_org(conn, self.org)

    def tamper(self, sql, *params):
        """Edit as a superuser, bypassing the append-only trigger (outside the app)."""
        with psycopg.connect(SVC.admin_dsn, autocommit=True) as conn:
            conn.execute("ALTER TABLE app.audit_log DISABLE TRIGGER audit_log_append_only")
            try:
                conn.execute(sql, params)
            finally:
                conn.execute("ALTER TABLE app.audit_log ENABLE TRIGGER audit_log_append_only")

    def test_intact_chain_verifies(self):
        ok, bad, _ = self.verify()
        self.assertTrue(ok)

    def test_altered_entry_detected_at_that_entry(self):
        with SVC.db.org(self.org) as conn:
            seq = conn.execute("SELECT max(seq) - 2 AS s FROM app.audit_log WHERE org_id = %s",
                               (self.org,)).fetchone()["s"]
        self.tamper("UPDATE app.audit_log SET entry = replace(entry, 'scan.start', "
                    "'scan.stop') WHERE org_id = %s AND seq = %s", self.org, seq)
        ok, bad, reason = self.verify()
        self.assertFalse(ok)
        self.assertEqual(bad, seq)
        self.assertIn("hash", reason)

    def test_altered_column_detected(self):
        self.tamper("UPDATE app.audit_log SET actor = 'token:someone-else' WHERE org_id = %s "
                    "AND seq = 1", self.org)
        ok, bad, reason = self.verify()
        self.assertEqual((ok, bad), (False, 1))
        self.assertIn("actor", reason)

    def test_deleted_entry_detected(self):
        self.tamper("DELETE FROM app.audit_log WHERE org_id = %s AND seq = 2", self.org)
        ok, bad, reason = self.verify()
        self.assertEqual((ok, bad), (False, 2))
        self.assertIn("missing", reason)

    def test_app_role_cannot_update_or_delete(self):
        for sql in ("UPDATE app.audit_log SET action = 'x' WHERE org_id = %s",
                    "DELETE FROM app.audit_log WHERE org_id = %s"):
            with self.assertRaises(psycopg.Error):
                with SVC.db.org(self.org) as conn:
                    conn.execute(sql, (self.org,))

    def test_verify_command_exit_status(self):
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = audit.main(["verify", "--dsn", SVC.app_dsn, "--org", str(self.org)])
        self.assertEqual(rc, 0 if self.verify()[0] else 1)
        self.assertTrue(out.getvalue().startswith(("OK", "BROKEN")))


@unittest.skipUnless(pgfixture.available(), "PostgreSQL binaries not available")
class ExportTests(unittest.TestCase):

    def test_export_range_contains_only_own_entries_and_verifies_offline(self):
        with SVC.client("A") as c:
            c.post("/v1/targets", json={"host": "export.example", "port": 443})
        since = datetime.now(timezone.utc) - timedelta(days=1)
        until = datetime.now(timezone.utc) + timedelta(seconds=5)
        with SVC.client("A", "owner") as c:
            r = c.get("/v1/audit", params={"since": since.isoformat(),
                                          "until": until.isoformat()})
        self.assertEqual(r.status_code, 200)
        lines = [json.loads(x) for x in r.text.splitlines()]
        events = [json.loads(x["entry"]) for x in lines]
        self.assertTrue(events)
        self.assertEqual({e["org_id"] for e in events}, {str(SVC.orgs["A"])})
        # a full-range export re-verifies with no database access
        ok, bad, reason = audit.verify_rows(lines)
        self.assertTrue(ok, reason)

    def test_range_excludes_entries_outside_it(self):
        future = datetime.now(timezone.utc) + timedelta(days=30)
        with SVC.client("A") as c:
            r = c.get("/v1/audit", params={"since": future.isoformat(),
                                          "until": (future + timedelta(days=1)).isoformat()})
        self.assertEqual(r.text, "")

    def test_engineer_cannot_export(self):
        now = datetime.now(timezone.utc)
        with SVC.client("A", "engineer") as c:
            r = c.get("/v1/audit", params={"since": now.isoformat(), "until": now.isoformat()})
        self.assertEqual(r.status_code, 403)


if __name__ == "__main__":
    unittest.main()
