"""certificate-chain-validation: chains are verified, not matched by name.

R3: a forged intermediate (same subject and SKI, different key), a non-CA
"intermediate" and an expired intermediate all gave `complete` / PASS.
"""

import unittest
from unittest import mock

from fixtures.fake_server import FakeSession
from fixtures.pki import get_pki, openssl_available

from ssl_doctor import certs, chainval
from ssl_doctor import findings as F
from ssl_doctor.analyze import diagnose


def chain(sample):
    return certs.parse_cert_file(get_pki().sample(sample)).certs


def file_chain(path):
    return certs.parse_cert_file(path).certs


def roots(*paths):
    return [c for p in paths for c in certs.parse_cert_file(p).certs]


def fresh():
    chainval._LINK_CACHE.clear()
    chainval._SELF_CACHE.clear()


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class Signatures(unittest.TestCase):

    def setUp(self):
        fresh()

    def test_regression_r3_forged_intermediate(self):
        a = certs.assess_chain(chain("forged-chain.pem"))
        self.assertEqual((a.status, a.failure, a.broken_at), ("broken", "chain-signature", 1))
        self.assertIn("signature does not verify", " ".join(a.evidence))
        f = FakeSession("")._chainfile_finding(get_pki().sample("forged-chain.pem"))
        self.assertEqual((f.status, f.failure_kind), (F.FAIL, "chain-signature"))

    def test_forged_chain_raises_a_signature_cause(self):
        f = FakeSession("")._chainfile_finding(get_pki().sample("forged-chain.pem"))
        causes = [c.summary for c in diagnose([f]).causes]
        self.assertTrue(any("does not verify" in c for c in causes), causes)

    def test_wrong_intermediate_is_still_a_misordered_warning(self):
        a = certs.assess_chain(file_chain(get_pki().wrongchain))
        self.assertEqual((a.status, a.failure, a.broken_at), ("broken", "chain-misordered", 1))
        self.assertEqual(chainval.chain_verdict(a)[0], F.WARNING)

    def test_full_chain_says_signatures_verified(self):
        f = FakeSession("")._chainfile_finding(get_pki().fullchain)
        self.assertEqual(f.status, F.PASS)
        self.assertIn("signatures verified", " ".join(f.evidence))

    def test_equivalent_names_in_another_case_match(self):
        a = certs.assess_chain(chain("case-chain.pem"))
        self.assertEqual(a.status, "complete")
        self.assertIn("signatures verified", " ".join(a.evidence))

    def test_without_openssl_a_chain_is_never_pass(self):
        with mock.patch.object(chainval.shutil, "which", return_value=None):
            a = certs.assess_chain(file_chain(get_pki().fullchain))
        status, kind, uncertainty = chainval.chain_verdict(a)
        self.assertEqual((status, kind), (F.WARNING, "chain-unverified"))
        self.assertIn("links matched by name only; signatures not verified", uncertainty[0])


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class CaConstraints(unittest.TestCase):

    def setUp(self):
        fresh()

    def test_regression_r3_non_ca_issuer(self):
        a = certs.assess_chain(chain("nonca-chain.pem"))
        self.assertEqual((a.status, a.failure), ("broken", "chain-signature"))
        self.assertIn("is not a CA", " ".join(a.evidence))

    def test_path_length_exceeded(self):
        a = certs.assess_chain(chain("pathlen-chain.pem"))
        self.assertEqual((a.status, a.failure, a.broken_at), ("broken", "chain-signature", 3))
        self.assertIn("pathLenConstraint:0", " ".join(a.evidence))


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class Usage(unittest.TestCase):

    def setUp(self):
        fresh()

    def test_client_only_leaf_fails(self):
        f = chainval.usage_finding(chain("client-leaf.pem"), F.SCOPE_SERVER, "x")
        self.assertEqual(f.status, F.FAIL)
        self.assertIn("certificate is not valid for TLS server authentication",
                      " ".join(f.evidence))

    def test_ca_without_keycertsign_fails(self):
        f = chainval.usage_finding(chain("nosign-chain.pem"), F.SCOPE_SERVER, "x")
        self.assertEqual(f.status, F.FAIL)
        self.assertIn("'SSLDoctor NoSign CA'", " ".join(f.evidence))

    def test_good_chain_passes(self):
        f = chainval.usage_finding(file_chain(get_pki().fullchain), F.SCOPE_LOCAL, "x")
        self.assertEqual(f.status, F.PASS)

    def test_diagnosis_names_the_usage_cause_not_a_generic_failure(self):
        usage = chainval.usage_finding(chain("client-leaf.pem"), F.SCOPE_REMOTE_NET, "x")
        verify = F.Finding("tls.verify", "Certificate validation (system trust)", F.FAIL,
                           F.SCOPE_REMOTE_NET,
                           ["validation failed: unsuitable certificate purpose"])
        hs = F.Finding("tls.handshake", "TLS handshake", F.PASS, F.SCOPE_REMOTE_NET, ["ok"])
        d = diagnose([hs, usage, verify])
        summaries = [c.summary for c in d.causes]
        self.assertTrue(any("not valid for TLS server authentication" in s for s in summaries))
        self.assertFalse(any("failed against the system trust store" in s for s in summaries))
        self.assertEqual(d.unexplained, [])

    def test_usage_is_reported_for_a_configured_file(self):
        p = get_pki()
        by = {f.check: f for f in FakeSession(f"""http {{ server {{ listen 443 ssl;
            server_name shop.test; ssl_certificate {p.sample('client-leaf.pem')};
            ssl_certificate_key {p.path('client_leaf.key')}; }} }}""").nginx_scan("shop.test")}
        self.assertEqual(by["chain.usage"].status, F.FAIL)

    def test_usage_is_reported_for_a_supplied_file(self):
        by = {f.check: f for f in certs.inspect_cert_file(get_pki().sample("client-leaf.pem"))}
        self.assertEqual(by["chain.usage"].status, F.FAIL)


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class SelfSigned(unittest.TestCase):

    def setUp(self):
        fresh()

    def test_regression_r7_name_only_self_signed(self):
        c = chain("name-only-root.pem")
        a = certs.assess_chain(c)
        self.assertNotEqual(a.status, "complete")
        self.assertIn("not self-signed", " ".join(a.evidence))
        by = {f.check: f for f in certs.inspect_cert_file(get_pki().sample("name-only-root.pem"))}
        self.assertIn("self-issued name, not self-signed", " ".join(by["cert.selfsigned"].evidence))

    def test_genuine_self_signed_leaf_is_verified(self):
        a = certs.assess_chain(chain("self-signed-leaf.pem"))
        self.assertEqual(a.status, "complete")
        self.assertIn("self-signature verified", " ".join(a.evidence))


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class Anchors(unittest.TestCase):

    def setUp(self):
        fresh()
        p = get_pki()
        self.sent = file_chain(p.fullchain) + chain("cross-root.pem")
        self.sent[2].position = 3

    def test_two_same_name_roots_pick_the_key_identifier_match(self):
        p = get_pki()
        a = certs.assess_chain(file_chain(p.fullchain),
                               roots(p.sample("root2.pem"), p.root))
        self.assertEqual(a.status, "complete")
        self.assertTrue(a.anchored)
        text = " ".join(a.evidence)
        self.assertIn("2 trusted roots share the name", text)
        self.assertIn("matches 'SSLDoctor Test Intermediate'", text)

    def test_cross_signed_chain_lists_both_paths(self):
        p = get_pki()
        a = certs.assess_chain(self.sent, roots(p.root, p.sample("old-root.pem")))
        self.assertEqual(len(a.paths), 2)
        self.assertIn("the verdict uses path 1", a.evidence)
        self.assertEqual(chainval.chain_verdict(a)[0], F.PASS)

    def test_only_the_legacy_path_validates(self):
        a = certs.assess_chain(self.sent, roots(get_pki().sample("old-root.pem")))
        self.assertEqual(a.status, "complete")
        self.assertEqual(len(a.paths), 1)
        self.assertIn("[SSLDoctor Old Root]", a.paths[0])
        self.assertIn("no trusted root named 'CN=SSLDoctor Test Root' is present here",
                      " ".join(a.evidence))

    def test_path_enumeration_is_bounded(self):
        p = get_pki()
        with mock.patch.object(chainval, "MAX_PATHS", 1):
            a = certs.assess_chain(self.sent, roots(p.root, p.sample("old-root.pem")))
        self.assertEqual(len(a.paths), 1)


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class MissingIntermediate(unittest.TestCase):

    def setUp(self):
        fresh()

    def test_missing_issuer_is_named_with_its_aia_url(self):
        a = certs.assess_chain(chain("aia-leaf.pem"), roots(get_pki().root))
        self.assertEqual((a.status, a.failure), ("incomplete", "chain-incomplete"))
        text = " ".join(a.evidence)
        self.assertIn("missing issuer: 'CN=SSLDoctor Test Intermediate'", text)
        self.assertIn("http://ca.test/int.crt", text)

    def test_verified_chain_with_unknown_anchor_stays_complete(self):
        p = get_pki()
        a = certs.assess_chain(file_chain(p.fullchain), roots(p.sample("old-root.pem")))
        self.assertEqual((a.status, a.anchored), ("complete", False))
        self.assertIn("anchor unknown", " ".join(a.evidence))
        self.assertEqual(chainval.chain_verdict(a)[0], F.PASS)


if __name__ == "__main__":
    unittest.main()
