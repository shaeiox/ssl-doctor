"""certificate-trust-classification: an explicit, evidence-based trust class
(public / private / self-signed / unknown) per chain, its anchor's validity,
and no server blame for a client's missing root."""

import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from fixtures.fake_server import FakeSession
from fixtures.pki import get_pki, openssl_available
from fixtures.scan import trust_env

from ssl_doctor import certs, chainval, netchecks
from ssl_doctor import findings as F
from ssl_doctor.analyze import diagnose


def pem_chain(path):
    return certs.parse_cert_file(path).certs


def trust(chain, roots, **kw):
    chainval._LINK_CACHE.clear()
    chainval._SELF_CACHE.clear()
    return chainval.trust_finding(chain, F.SCOPE_LOCAL, "x", roots, **kw)


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class TrustClass(unittest.TestCase):

    def setUp(self):
        p = get_pki()
        self.full = pem_chain(p.fullchain)
        self.root = pem_chain(p.root)

    def test_public_names_store_and_anchor(self):
        f = trust(self.full, self.root)
        self.assertEqual(f.status, F.PASS)
        self.assertIn("trust class: public", f.evidence)
        text = " ".join(f.evidence)
        self.assertIn("system trust store of this machine", text)
        self.assertIn("1 root anchor(s)", text)
        self.assertIn("'SSLDoctor Test Root'", text)

    def test_private_ca_from_ssl_trusted_certificate(self):
        p = get_pki()
        with trust_env(("intermediate",)):          # no self-signed root in the store
            by = {f.check: f for f in FakeSession(f"""http {{ server {{ listen 443 ssl;
                server_name shop.test; ssl_certificate {p.fullchain};
                ssl_certificate_key {p.leaf_key};
                ssl_trusted_certificate {p.root}; }} }}""").nginx_scan("shop.test")}
        f = by["chain.trust"]
        self.assertEqual(f.status, F.WARNING)
        self.assertIn("trust class: private", f.evidence)
        self.assertIn(f"ssl_trusted_certificate {p.root}", " ".join(f.evidence))

    def test_public_looking_issuer_is_unknown(self):
        chain = certs.parse_cert_file(get_pki().sample("lookalike-chain.pem")).certs
        self.assertIn("DigiCert", chain[0].issuer)
        f = trust(chain, self.root)
        self.assertIn("trust class: unknown", f.evidence)
        self.assertNotIn("trust class: public", f.evidence)

    def test_self_signed(self):
        chain = certs.parse_cert_file(get_pki().sample("self-signed-leaf.pem")).certs
        self.assertIn("trust class: self-signed", trust(chain, self.root).evidence)

    def test_verifier_unavailable_is_not_tested(self):
        with mock.patch.object(chainval.shutil, "which", return_value=None):
            f = trust(self.full, self.root)
        self.assertEqual((f.status, f.failure_kind), (F.NOT_TESTED, "verifier-unavailable"))
        self.assertIn("trust class: unknown", f.evidence)

    def test_trust_is_evaluated_without_the_network(self):
        with mock.patch.object(netchecks, "_handshake", side_effect=AssertionError("network")):
            self.assertEqual(trust(self.full, self.root).status, F.PASS)


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class AnchorsAndStores(unittest.TestCase):

    def test_expired_anchor_warns_with_a_limitation(self):
        p = get_pki()
        later = datetime.now(timezone.utc) + timedelta(days=60)   # fixtures live 30 days
        f = trust(pem_chain(p.fullchain), pem_chain(p.root), now=later)
        self.assertEqual(f.status, F.WARNING)
        self.assertIn("anchor expired on", " ".join(f.evidence))
        self.assertIn("clients with other stores may build a different path",
                      " ".join(f.uncertainty))

    def test_empty_store_is_not_tested(self):
        f = trust(pem_chain(get_pki().fullchain), [])
        self.assertEqual(f.status, F.NOT_TESTED)
        self.assertIn("no trust anchors available", f.evidence[0])


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class ClientTrustGap(unittest.TestCase):

    def test_complete_chain_from_an_unknown_root_blames_no_server(self):
        p = get_pki()
        full = pem_chain(p.fullchain)
        old_root = certs.parse_cert_file(p.sample("old-root.pem")).certs
        a = certs.assess_chain(full, old_root)
        chain_f = F.Finding("tls.chain", "Chain sent by server",
                            chainval.chain_verdict(a)[0], F.SCOPE_REMOTE_NET, a.evidence)
        trust_f = trust(full, old_root)
        verify = F.Finding("tls.verify", "Certificate validation (system trust)", F.FAIL,
                           F.SCOPE_REMOTE_NET,
                           ["validation failed: unable to get local issuer certificate"])
        hs = F.Finding("tls.handshake", "TLS handshake", F.PASS, F.SCOPE_REMOTE_NET, ["ok"])
        d = diagnose([hs, chain_f, trust_f, verify])
        self.assertEqual(chain_f.status, F.PASS)
        self.assertIn("trust class: unknown", trust_f.evidence)
        self.assertEqual([c for c in d.causes if c.origin == "server"], [])
        self.assertTrue(any(c.origin == "client" for c in d.causes))


if __name__ == "__main__":
    unittest.main()
