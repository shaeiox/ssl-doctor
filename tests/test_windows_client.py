"""windows-client-checks: ROOT store read, path-built anchor, chain engine in /scan."""

import unittest

from fixtures.pki import get_pki, openssl_available
from fixtures.scan import cli_session, windows_client

from ssl_doctor import findings as F
from ssl_doctor import local


def finding(app, check):
    return [f for f in app.store.all() if f.check == check][-1]


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class RootStoreReadTests(unittest.TestCase):

    def test_three_tuple_store_present(self):
        with windows_client([get_pki().root]):
            f = local.check_issuer_in_windows_root(["CN=SSLDoctor Test Root"])
        self.assertEqual(f.status, F.PASS)

    def test_three_tuple_store_missing(self):
        with windows_client([get_pki().root]):
            f = local.check_issuer_in_windows_root(["CN=Some Other Root"])
        self.assertEqual(f.status, F.FAIL)


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class AnchorTests(unittest.TestCase):

    def test_full_chain_looks_up_root(self):
        app = cli_session("full-chain", windows_roots=[get_pki().root])
        rootca = finding(app, "local.rootca")
        self.assertEqual(rootca.status, F.PASS)
        self.assertIn("CN=SSLDoctor Test Root", rootca.evidence[0])

    def test_leaf_only_is_not_tested(self):
        app = cli_session("leaf-only", trust=("root", "intermediate"),
                          windows_roots=[get_pki().root])
        rootca = finding(app, "local.rootca")
        self.assertEqual(rootca.status, F.NOT_TESTED)
        self.assertIn("presented chain incomplete; anchor cannot be determined",
                      rootca.evidence[0])


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class ChainEngineTests(unittest.TestCase):

    def test_scan_runs_certutil_on_presented_leaf(self):
        app = cli_session("full-chain", windows_roots=[get_pki().root])
        self.assertEqual(len(app.certutil_calls), 1)
        self.assertEqual(app.certutil_calls[0], app.remote_facts["cert"].pem)
        self.assertEqual(finding(app, "local.certutil").status, F.PASS)


if __name__ == "__main__":
    unittest.main()
