"""tls-certificate-inspection: presented chain, linkage, root-only validation, SAN."""

import sys
import unittest

from fixtures.pki import HOSTNAME, openssl_available
from fixtures.scan import scan

from ssl_doctor import findings as F


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class PresentedChainTests(unittest.TestCase):

    def test_full_chain_is_two_certs(self):
        by, facts = scan("full-chain")
        self.assertEqual(len(facts["chain"]), 2)
        self.assertEqual(facts["chain"][0].common_name, HOSTNAME)
        self.assertEqual(by["tls.chain"].status, F.PASS)

    def test_leaf_only_is_one_cert(self):
        _by, facts = scan("leaf-only")
        self.assertEqual(len(facts["chain"]), 1)

    def test_reader_matches_runtime(self):
        _by, facts = scan("full-chain")
        expected = "public-api" if sys.version_info >= (3, 13) else "private-api"
        self.assertEqual(facts["chain_reader"], expected)

    def test_s_client_fallback_reads_same_chain(self):
        _by, facts = scan("full-chain", readers=("openssl-s_client",))
        self.assertEqual(facts["chain_reader"], "openssl-s_client")
        self.assertEqual(len(facts["chain"]), 2)

    def test_unreadable_chain_is_not_tested(self):
        by, facts = scan("full-chain", readers=())
        self.assertIsNone(facts["chain"])
        self.assertEqual(by["tls.chain"].status, F.NOT_TESTED)
        self.assertNotIn("only the leaf", " ".join(by["tls.chain"].evidence))


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class ChainVerdictTests(unittest.TestCase):

    def test_leaf_only_with_cached_intermediate_is_warning(self):
        by, facts = scan("leaf-only", trust=("root", "intermediate"))
        self.assertEqual(by["tls.chain"].status, F.WARNING)
        self.assertIn("intermediate certificate(s) not sent",
                      " ".join(by["tls.chain"].evidence))
        self.assertEqual(facts["chain_status"], "incomplete")

    def test_wrong_intermediate_names_position_1(self):
        by, facts = scan("wrong-chain")
        self.assertEqual(by["tls.chain"].status, F.WARNING)
        self.assertIn("position 1", by["tls.chain"].evidence[0])
        self.assertEqual(facts["chain_status"], "broken")

    def test_full_chain_anchor_is_root(self):
        _by, facts = scan("full-chain")
        self.assertEqual(facts["chain_status"], "complete")
        self.assertEqual(facts["anchor"], "CN=SSLDoctor Test Root")


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class RootOnlyValidationTests(unittest.TestCase):

    def test_cache_masks_missing_intermediate(self):
        by, _facts = scan("leaf-only", trust=("root", "intermediate"))
        self.assertEqual(by["tls.verify"].status, F.PASS)
        self.assertEqual(by["tls.verify.rootonly"].status, F.FAIL)

    def test_full_chain_passes_root_only(self):
        by, _facts = scan("full-chain")
        self.assertEqual(by["tls.verify.rootonly"].status, F.PASS)


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class HostnameTests(unittest.TestCase):

    def test_cn_only_fails(self):
        by, _facts = scan("cn-only")
        self.assertEqual(by["tls.hostname"].status, F.FAIL)
        self.assertIn("ignored by modern clients", " ".join(by["tls.hostname"].evidence))
        self.assertEqual(by["tls.verify"].status, F.FAIL)

    def test_san_passes(self):
        by, _facts = scan("full-chain")
        self.assertEqual(by["tls.hostname"].status, F.PASS)


if __name__ == "__main__":
    unittest.main()
