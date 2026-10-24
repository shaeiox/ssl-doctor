"""diagnosis-correlation: server chain causes, nginx correlation, client blame, certainty."""

import unittest

from fixtures.fake_server import FakeSession
from fixtures.pki import get_pki, openssl_available
from fixtures.scan import cli_session

from ssl_doctor import findings as F
from ssl_doctor.analyze import diagnose


def fnd(check, status, scope, *evidence, rec=""):
    return F.Finding(check, check, status, scope, list(evidence), recommendation=rec)


def top(diag):
    return diag.causes[0] if diag.causes else None


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class ServerChainCauseTests(unittest.TestCase):

    def test_customer_scenario_leaf_only_with_cached_intermediate(self):
        app = cli_session("leaf-only", trust=("root", "intermediate"))
        d = diagnose(app.store.all())
        self.assertNotEqual(d.overall, "PASS")
        self.assertEqual(top(d).origin, "server")
        self.assertIn("ssl_certificate", top(d).recommendation)

    def test_leaf_only_chain_file_on_server(self):
        p = get_pki()
        items = FakeSession(f"""http {{ server {{ listen 443 ssl; server_name shop.test;
            ssl_certificate {p.leaf}; ssl_certificate_key {p.leaf_key}; }} }}""").nginx_scan(
            "shop.test")
        d = diagnose(items)
        self.assertEqual(top(d).origin, "server")
        self.assertIn(p.leaf, " ".join(top(d).evidence))

    def test_fallback_vhost_is_server_cause(self):
        p = get_pki()
        items = FakeSession(f"""http {{ server {{ listen 443 ssl; server_name other.test;
            ssl_certificate {p.fullchain}; ssl_certificate_key {p.leaf_key}; }} }}""").nginx_scan(
            "shop.test")
        d = diagnose(items)
        self.assertTrue(any(c.origin == "server" and "no dedicated nginx server block"
                            in c.summary for c in d.causes))

    def test_wildcard_vhost_is_not_a_cause(self):
        p = get_pki()
        items = FakeSession(f"""http {{ server {{ listen 443 ssl; server_name *.test;
            ssl_certificate {p.fullchain}; ssl_certificate_key {p.leaf_key};
            ssl_protocols TLSv1.2 TLSv1.3; }} }}""").nginx_scan("shop.test")
        self.assertEqual(diagnose(items).causes, [])


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class ClientBlameTests(unittest.TestCase):

    def test_full_chain_root_present_no_client_cause(self):
        app = cli_session("full-chain", windows_roots=[get_pki().root])
        d = diagnose(app.store.all())
        self.assertFalse([c for c in d.causes if c.origin == "client"])

    def test_incomplete_chain_only_server_cause(self):
        app = cli_session("leaf-only", trust=("root", "intermediate"),
                          windows_roots=[get_pki().root])
        d = diagnose(app.store.all())
        self.assertFalse([c for c in d.causes if c.origin == "client"])
        self.assertEqual(top(d).origin, "server")

    def test_complete_chain_untrusted_root_is_not_missing_intermediate(self):
        # engineer's machine does not trust the private root at all
        app = cli_session("full-chain", trust=("other_intermediate",))
        d = diagnose(app.store.all())
        self.assertFalse([c for c in d.causes if "missing intermediates" in c.summary])


class CertaintyTests(unittest.TestCase):

    def test_local_validation_only_inference_is_probable(self):
        items = [fnd("tls.chain", F.NOT_TESTED, F.SCOPE_REMOTE_NET, "unread"),
                 fnd("tls.verify", F.FAIL, F.SCOPE_REMOTE_NET,
                     "validation failed: unable to get local issuer certificate")]
        causes = diagnose(items).causes
        self.assertTrue(causes)
        self.assertTrue(all(c.certainty == "probable" for c in causes))

    def test_root_store_miss_is_probable(self):
        items = [fnd("tls.chain", F.PASS, F.SCOPE_REMOTE_NET, "2 certificate(s), linked"),
                 fnd("local.rootca", F.FAIL, F.SCOPE_LOCAL, "not found in ROOT store: X")]
        c = [c for c in diagnose(items).causes if c.origin == "client"]
        self.assertEqual([x.certainty for x in c], ["probable"])


if __name__ == "__main__":
    unittest.main()
