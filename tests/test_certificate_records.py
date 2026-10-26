"""certificate-file-inspection: every certificate record carries the facts
later checks judge (key, signature, Basic Constraints, KU/EKU, SKI/AKI, AIA,
CRL distribution points) - read from the certificate, never inferred."""

import subprocess
import unittest
from unittest import mock

from fixtures.pki import get_pki, openssl_available

from ssl_doctor import certs


def record(path):
    with open(path, "rb") as fh:
        return certs.parse_cert_bytes(fh.read()).certs[0]


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class RecordFields(unittest.TestCase):

    def test_root(self):
        c = record(get_pki().root)
        self.assertEqual((c.key_type, c.key_bits, c.is_ca, c.basic_constraints, c.path_len),
                         ("RSA", 2048, True, True, None))
        self.assertEqual(c.key_usage, ["keyCertSign", "cRLSign"])
        self.assertEqual(c.ski, c.aki)
        self.assertEqual(c.signature_algorithm, "sha256WithRSAEncryption")

    def test_intermediate_path_length_and_identifiers(self):
        root, inter = record(get_pki().root), record(get_pki().intermediate)
        self.assertEqual((inter.is_ca, inter.path_len), (True, 0))
        self.assertEqual(inter.aki, root.ski)
        self.assertRegex(inter.ski, r"^[0-9a-f]{40}$")

    def test_leaf(self):
        leaf, inter = record(get_pki().leaf), record(get_pki().intermediate)
        self.assertEqual((leaf.is_ca, leaf.basic_constraints), (False, True))
        self.assertEqual(leaf.ext_key_usage, ["serverAuth"])
        self.assertEqual(leaf.aki, inter.ski)
        self.assertEqual(leaf.position, 1)

    def test_ec_certificate_with_aia_and_crl(self):
        c = record(get_pki().sample("ec-aia.pem"))
        self.assertEqual((c.key_type, c.key_bits, c.curve), ("EC", 256, "P-256"))
        self.assertEqual(c.public_key, "ECDSA 256 bit")
        self.assertEqual(c.signature_algorithm, "ecdsa-with-SHA256")
        self.assertEqual(c.key_usage, ["digitalSignature"])
        self.assertEqual(c.ext_key_usage, ["serverAuth", "clientAuth"])
        self.assertEqual(c.aia_ca_issuers, ["http://ca.test/int.crt"])
        self.assertEqual(c.ocsp_urls, ["http://ocsp.test"])
        self.assertEqual(c.crl_urls, ["http://crl.test/ca.crl"])
        self.assertEqual((c.is_ca, c.basic_constraints), (False, True))

    def test_ed25519(self):
        c = record(get_pki().sample("ed25519.pem"))
        self.assertEqual((c.key_type, c.key_bits, c.curve), ("Ed25519", 256, ""))
        self.assertEqual(c.signature_algorithm, "ED25519")

    def test_no_basic_constraints_is_not_a_ca(self):
        p = get_pki()
        out = p.path("no-bc.pem")
        subprocess.run(["openssl", "x509", "-req", "-in", p.sample("csr.pem"),
                        "-CA", p.intermediate, "-CAkey", p.path("int.key"),
                        "-CAcreateserial", "-days", "1", "-out", out],
                       check=True, capture_output=True, cwd=p.dir)
        c = record(out)
        self.assertTrue(c.extensions_read)
        self.assertEqual((c.basic_constraints, c.is_ca), (False, False))

    def test_without_openssl_extension_facts_are_unknown_not_false(self):
        with open(get_pki().intermediate, "rb") as fh:
            data = fh.read()
        with mock.patch.object(certs.shutil, "which", return_value=None):
            c = certs.parse_cert_bytes(data).certs[0]
        self.assertFalse(c.extensions_read)
        self.assertIsNone(c.is_ca)
        self.assertEqual((c.key_usage, c.ski), ([], ""))
        self.assertTrue(c.subject and c.sha256, "stdlib facts still present")


if __name__ == "__main__":
    unittest.main()
