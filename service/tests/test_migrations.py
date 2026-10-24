"""8.1: migrations apply on an empty database, with RLS on every tenant table."""

import unittest

import pgfixture

# Hardcoded on purpose: a new table must be added here consciously, which
# forces the question "does it carry org_id and RLS?".
TENANT_TABLES = ["organizations", "api_tokens", "enrollment_tokens", "agents", "targets",
                 "target_agents", "scan_jobs", "scan_results",
                 "notification_channels", "alert_state", "alerts", "audit_log",
                 "users", "sessions", "sso_configs", "sso_states"]
MIGRATIONS = ["0001_init.sql", "0002_monitoring.sql", "0003_audit.sql", "0004_identity.sql"]


@unittest.skipUnless(pgfixture.available(), "PostgreSQL binaries not available")
class MigrationTests(unittest.TestCase):

    def setUp(self):
        import psycopg
        from ssldoctor_service import db
        self.psycopg, self.db = psycopg, db
        self.admin = pgfixture.fresh_database()

    def test_apply_on_empty_database(self):
        self.assertEqual(self.db.migrate(self.admin), MIGRATIONS)
        self.assertEqual(self.db.migrate(self.admin), [])      # idempotent

    def test_rls_enabled_on_every_tenant_table(self):
        self.db.migrate(self.admin)
        with self.psycopg.connect(self.admin) as conn:
            rows = dict(conn.execute(
                "SELECT c.relname, c.relrowsecurity FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'app' AND c.relkind = 'r'").fetchall())
            bypass = conn.execute("SELECT rolbypassrls, rolsuper FROM pg_roles "
                                  "WHERE rolname = 'ssldoctor_app'").fetchone()
        self.assertEqual(sorted(rows), sorted(TENANT_TABLES))
        self.assertTrue(all(rows.values()), rows)
        self.assertEqual(bypass, (False, False))

    def test_every_tenant_table_has_org_id(self):
        self.db.migrate(self.admin)
        with self.psycopg.connect(self.admin) as conn:
            cols = {r[0] for r in conn.execute(
                "SELECT table_name FROM information_schema.columns "
                "WHERE table_schema = 'app' AND column_name = 'org_id'")}
        self.assertEqual(cols, set(TENANT_TABLES) - {"organizations"})


if __name__ == "__main__":
    unittest.main()
