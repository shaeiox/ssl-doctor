"""self-hosted-deployment 12.6: upgrading an older data dir preserves everything.

The previous schema state (migrations 0001-0003: tenancy, monitoring, audit;
API tokens not yet tied to users) is built exactly as that code wrote it. Then
``ssldoctor-server upgrade`` (the built executable when SSLDOCTOR_SERVER_EXE is
set) must keep every result readable, the audit chain intact, and the legacy
API token working.
"""

import json
import os
import secrets
import subprocess
import unittest
import uuid

import pgfixture
from test_server_main import Install, api, server_cmd


@unittest.skipUnless(pgfixture.available() and os.name != "nt", "PostgreSQL binaries needed")
class UpgradeTests(unittest.TestCase):

    def setUp(self):
        self.inst = Install()

    def tearDown(self):
        self.inst.cleanup()

    def build_previous_version(self):
        """A data dir at schema 0003, populated the way that version populated it."""
        import psycopg
        from ssldoctor_service import audit, db
        from ssldoctor_service.server_main import Postgres, _free_port, save_config
        data = self.inst.data
        os.makedirs(data, mode=0o700)
        run_as = self.inst.runas[1] if self.inst.runas else None
        cfg = {"version": "0.0.9", "listen_host": "127.0.0.1", "listen_port": self.inst.port,
               "pg_port": _free_port(), "pg_admin_password": secrets.token_urlsafe(16),
               "app_password": secrets.token_urlsafe(16), "run_as": run_as,
               "tls_cert": None, "tls_key": None}
        if run_as:
            import pwd
            pw = pwd.getpwnam(run_as)
            os.chown(data, pw.pw_uid, pw.pw_gid)
        pg = Postgres(data, cfg)
        pg.initdb()
        pg.start()
        token = "legacy-" + secrets.token_urlsafe(16)
        try:
            with psycopg.connect(pg.dsn(db="postgres"), autocommit=True) as c:
                c.execute("CREATE DATABASE ssldoctor")
            self.assertEqual(db.migrate(pg.dsn(), upto="0003_audit.sql")[-1], "0003_audit.sql")
            with psycopg.connect(pg.dsn(), autocommit=True) as c:
                c.execute(psycopg.sql.SQL("ALTER ROLE ssldoctor_app PASSWORD {}").format(
                    psycopg.sql.Literal(cfg["app_password"])))
            doc = {"schema_version": "1.0", "tool": "SSL Doctor 0.2.0", "generated_utc": "t",
                   "summary": {s: 0 for s in ("PASS", "FAIL", "WARNING", "NOT TESTED")},
                   "diagnosis": {"overall": "FAIL", "causes": [], "notes": []},
                   "findings": [{"check": "tls.chain", "title": "c", "status": "WARNING",
                                 "scope": "remote-net", "evidence": ["leaf only"]}]}
            with psycopg.connect(pg.dsn()) as c:
                org = c.execute("INSERT INTO app.organizations (name) VALUES ('Old Corp') "
                                "RETURNING id").fetchone()[0]
                c.execute("INSERT INTO app.api_tokens (org_id, name, token_hash, role) VALUES "
                          "(%s, 'bootstrap', %s, 'owner')", (org, db.sha256_hex(token)))
                agent = c.execute("INSERT INTO app.agents (org_id, name, role, credential_hash) "
                                  "VALUES (%s, 'old', 'client', %s) RETURNING id",
                                  (org, uuid.uuid4().hex)).fetchone()[0]
                target = c.execute("INSERT INTO app.targets (org_id, host, port) VALUES "
                                   "(%s, 'legacy.example', 443) RETURNING id",
                                   (org,)).fetchone()[0]
                job = c.execute("INSERT INTO app.scan_jobs (org_id, target_id, agent_id, kind, "
                                "status) VALUES (%s, %s, %s, 'client', 'done') RETURNING id",
                                (org, target, agent)).fetchone()[0]
                result = c.execute("INSERT INTO app.scan_results (org_id, job_id, target_id, "
                                   "overall, document) VALUES (%s, %s, %s, 'FAIL', %s) "
                                   "RETURNING id", (org, job, target, json.dumps(doc))).fetchone()[0]
            from psycopg.rows import dict_row
            with psycopg.connect(pg.dsn(), row_factory=dict_row) as c:
                for action in ("target.create", "scan.start", "report.export"):
                    audit.record(c, org, f"token:old", action, f"target:{target}")
        finally:
            pg.stop()
        save_config(data, cfg)
        if run_as:
            import pwd
            pw = pwd.getpwnam(run_as)
            os.chown(os.path.join(data, "config.json"), pw.pw_uid, pw.pw_gid)
        return token, str(target), str(result)

    def test_upgrade_preserves_results_audit_and_legacy_token(self):
        token, target, result = self.build_previous_version()
        up = self.inst.run("upgrade", "--data", self.inst.data)
        self.assertEqual(up.returncode, 0, up.stderr)
        self.assertIn("0004_identity.sql", up.stdout)
        self.assertTrue(os.listdir(os.path.join(self.inst.data, "backups")))
        va = self.inst.run("verify-audit", "--data", self.inst.data)
        self.assertEqual(va.returncode, 0, va.stdout + va.stderr)
        self.assertIn("3 entries verified", va.stdout)
        self.inst.serve()
        self.assertIn("legacy.example",
                      [t["host"] for t in api(self.inst.port, token, "GET", "/v1/targets")])
        doc = api(self.inst.port, token, "GET", f"/v1/results/{result}")["document"]
        self.assertEqual(doc["findings"][0]["evidence"], ["leaf only"])
        members = api(self.inst.port, token, "GET", "/v1/members")
        self.assertEqual([m["role"] for m in members], ["owner"])   # backfilled user
        self.assertEqual(json.load(open(os.path.join(self.inst.data, "config.json")))["version"],
                         subprocess.run(server_cmd() + ["version"], capture_output=True,
                                        text=True, env=self.inst.env).stdout.split()[-1])


if __name__ == "__main__":
    unittest.main()
