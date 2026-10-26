"""certificate-chain-validation: links and self-signatures are verified with
openssl, never inferred from names; without openssl the answer says so."""

import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from fixtures.pki import get_pki, openssl_available

from ssl_doctor import certs, chainval


def cert(path):
    return certs.parse_cert_file(path).certs[0]


def fresh_caches():
    chainval._LINK_CACHE.clear()
    chainval._SELF_CACHE.clear()


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class Links(unittest.TestCase):

    def setUp(self):
        fresh_caches()
        p = get_pki()
        self.leaf, self.inter = cert(p.leaf), cert(p.intermediate)

    def test_genuine_issuer_is_verified(self):
        self.assertEqual(chainval.verify_link(self.leaf, self.inter)[0], chainval.LINK_VERIFIED)
        self.assertEqual(chainval.verify_link(self.inter, cert(get_pki().root))[0],
                         chainval.LINK_VERIFIED)

    def test_forged_intermediate_with_same_name_and_ski_fails(self):
        forged = cert(get_pki().sample("forged-int.pem"))
        self.assertEqual((forged.subject, forged.ski), (self.inter.subject, self.inter.ski))
        self.assertEqual(chainval.verify_link(self.leaf, forged)[0],
                         chainval.LINK_SIGNATURE_FAILED)

    def test_wrong_name_is_a_name_mismatch(self):
        other = cert(get_pki().other_intermediate)
        self.assertEqual(chainval.verify_link(self.leaf, other)[0], chainval.LINK_NAME_MISMATCH)

    def test_non_ca_issuer(self):
        child = cert(get_pki().sample("leaf-issued.pem"))
        self.assertEqual(chainval.verify_link(child, self.leaf)[0], chainval.LINK_NOT_A_CA)

    def test_the_system_store_is_never_consulted(self):
        if not shutil.which("openssl"):
            self.skipTest("openssl binary not available")
        store = tempfile.mkdtemp(prefix="ssldoctor-store-")
        self.addCleanup(shutil.rmtree, store, True)
        shutil.copy(get_pki().intermediate, os.path.join(store, "int.pem"))
        if subprocess.run(["openssl", "rehash", store], capture_output=True).returncode:
            self.skipTest("openssl rehash not available")
        # same name, other key: openssl keeps searching for the issuer, and the
        # genuine intermediate in the store must not answer for this one.
        # openssl 3.x never adds the default directory once -CAfile is given;
        # 1.1.1 does unless -no-CApath is passed (test_isolation_flags_are_passed)
        other_key = cert(get_pki().sample("same-name-int.pem"))
        self.assertNotEqual(other_key.ski, self.inter.ski)
        with mock.patch.dict(os.environ, {"SSL_CERT_DIR": store,
                                          "SSL_CERT_FILE": get_pki().intermediate}):
            state, _ = chainval.verify_link(self.leaf, other_key)
        self.assertEqual(state, chainval.LINK_NAME_MISMATCH)

    def test_isolation_flags_are_passed(self):
        seen = []
        real = subprocess.run

        def spy(argv, *a, **kw):
            if argv[:2] == ["openssl", "verify"] and "-CAfile" in argv:
                seen.append(argv)
            return real(argv, *a, **kw)

        with mock.patch.object(chainval.subprocess, "run", side_effect=spy):
            chainval.verify_link(self.leaf, self.inter)
        self.assertTrue(seen)
        self.assertIn("-no-CApath", seen[0])
        self.assertIn("-partial_chain", seen[0])

    def test_without_openssl_a_name_match_is_name_only(self):
        with mock.patch.object(chainval.shutil, "which", return_value=None):
            state, detail = chainval.verify_link(self.leaf, self.inter)
        self.assertEqual(state, chainval.LINK_NAME_ONLY)
        self.assertIn("not verified", detail)

    def test_results_are_cached_per_pair(self):
        chainval.verify_link(self.leaf, self.inter)
        with mock.patch.object(chainval, "_verify", side_effect=AssertionError("re-run")):
            chainval.verify_link(self.leaf, self.inter)


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class SelfSigned(unittest.TestCase):

    def setUp(self):
        fresh_caches()

    def test_genuine_roots_and_self_signed_leaves(self):
        p = get_pki()
        for path in (p.root, p.sample("ed25519.pem"), p.sample("self-signed-leaf.pem")):
            with self.subTest(path=os.path.basename(path)):
                self.assertIs(chainval.self_signed(cert(path)), True)

    def test_name_only_self_signed_is_not_self_signed(self):
        c = cert(get_pki().sample("name-only-root.pem"))
        self.assertEqual(c.subject, c.issuer)
        self.assertIs(chainval.self_signed(c), False)

    def test_issued_certificate_is_not_self_signed(self):
        self.assertIs(chainval.self_signed(cert(get_pki().leaf)), False)

    def test_without_openssl_self_signature_is_unknown(self):
        with mock.patch.object(chainval.shutil, "which", return_value=None):
            self.assertIsNone(chainval.self_signed(cert(get_pki().root)))


if __name__ == "__main__":
    unittest.main()
