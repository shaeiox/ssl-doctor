"""certificate-file-inspection: inventory, duplicates, roles and CA bundles.

R7: a duplicated leaf was reported as a broken chain, and a certificate whose
subject merely equals its issuer counted as self-signed.
"""

import unittest

from fixtures.fake_server import FakeSession
from fixtures.pki import get_pki, openssl_available

from ssl_doctor import certs, chainval
from ssl_doctor import findings as F


def local(sample):
    return {f.check: f for f in certs.inspect_cert_file(get_pki().sample(sample))}


def server(sample):
    return FakeSession("")._chainfile_finding(get_pki().sample(sample))


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class Inventory(unittest.TestCase):

    def test_inventory_three_certs(self):
        parse = local("full-root.pem")["cert.parse"]
        rows = [e for e in parse.evidence if e.startswith("#")]
        self.assertEqual([r.split(" · ")[0] for r in rows],
                         ["#1 leaf", "#2 intermediate", "#3 root"])
        self.assertTrue(all("sha256 " in r and "CA:" in r for r in rows))
        self.assertIn("certificates in file: 3", parse.evidence)

    def test_server_file_inventory(self):
        f = FakeSession("")._chainfile_finding(get_pki().fullchain)
        self.assertEqual(f.status, F.PASS)
        self.assertTrue([e for e in f.evidence if e.startswith("#1 leaf")])


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class Duplicates(unittest.TestCase):

    def test_regression_r7_duplicate_not_broken(self):
        a = certs.assess_chain(certs.parse_cert_file(get_pki().sample("duplicate.pem")).certs)
        self.assertEqual(a.status, "complete")
        self.assertEqual(a.duplicates, ["position 3 duplicates position 1"])
        f = server("duplicate.pem")
        self.assertEqual(f.status, F.WARNING)
        text = " ".join(f.evidence)
        self.assertIn("position 3 duplicates position 1", text)
        self.assertNotIn("is not issued by", text)
        chainfile = local("duplicate.pem")["cert.chainfile"]
        self.assertEqual(chainfile.status, F.WARNING)
        self.assertIn("position 3 duplicates position 1", chainfile.evidence)

    def test_duplicate_in_presented_chain_order_keeps_positions(self):
        p = get_pki()
        chain = certs.parse_cert_file(p.sample("duplicate.pem")).certs
        for c in chain:
            c.position = 0                     # a presented chain has no file positions
        unique, notes = certs.dedupe(chain)
        self.assertEqual([c.position for c in unique], [1, 2])
        self.assertEqual(notes, ["position 3 duplicates position 1"])


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class Roles(unittest.TestCase):

    def roles(self, sample):
        return chainval.classify_roles(certs.parse_cert_file(get_pki().sample(sample)).certs)

    def test_roles_come_from_constraints_and_signatures(self):
        self.assertEqual(self.roles("full-root.pem"), ["leaf", "intermediate", "root"])
        self.assertEqual(self.roles("ca-bundle.pem"), ["root", "intermediate"])

    def test_regression_r7_name_only_self_signed_is_not_a_root(self):
        self.assertEqual(self.roles("name-only-root.pem"), ["intermediate"])

    def test_intermediate_first_fails_on_the_server(self):
        f = server("reversed.pem")
        self.assertEqual(f.status, F.FAIL)
        text = " ".join(f.evidence)
        self.assertIn("the first certificate is a CA certificate, not the server certificate",
                      text)
        self.assertIn("the server certificate is at position 2", text)

    def test_intermediate_first_warns_for_a_local_file(self):
        chainfile = local("reversed.pem")["cert.chainfile"]
        self.assertEqual(chainfile.status, F.WARNING)
        self.assertIn("not the server certificate", " ".join(chainfile.evidence))

    def test_unrelated_certificate_is_named(self):
        self.assertEqual(self.roles("unrelated.pem"), ["leaf", "intermediate", "unrelated"])
        f = server("unrelated.pem")
        self.assertEqual(f.status, F.WARNING)
        self.assertIn("position 3 ('SSLDoctor Other Intermediate') is unrelated",
                      " ".join(f.evidence))


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class KeyBlocks(unittest.TestCase):

    def key_lines(self):
        with open(get_pki().leaf_key) as fh:
            return [ln for ln in fh.read().splitlines() if ln and "-----" not in ln]

    def test_mixed_file_is_parsed_for_certificates_only(self):
        items = certs.inspect_cert_file(get_pki().sample("mixed.pem"))
        parse = {f.check: f for f in items}["cert.parse"]
        self.assertEqual(parse.status, F.PASS)
        self.assertIn("certificates in file: 1", parse.evidence)
        self.assertIn("a private-key block is present and was not read", parse.evidence)
        text = "\n".join(e for f in items for e in f.evidence)
        for line in self.key_lines():
            self.assertNotIn(line, text)


if __name__ == "__main__":
    unittest.main()
