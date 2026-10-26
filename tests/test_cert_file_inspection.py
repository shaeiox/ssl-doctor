"""certificate-file-inspection: content-based formats and strict parsing.

R6: a truncated trailing PEM block was ignored (cert.parse PASS, count 1) and a
corrupt middle block still produced cert.parse PASS plus a WARNING.
"""

import unittest
from unittest import mock

from fixtures.fake_server import FakeSession
from fixtures.pki import get_pki, openssl_available

from ssl_doctor import certs
from ssl_doctor import findings as F


def by_check(items):
    out = {}
    for f in items:
        out.setdefault(f.check, []).append(f)
    return out


def key_lines():
    with open(get_pki().leaf_key) as fh:
        return [ln for ln in fh.read().splitlines() if ln and "-----" not in ln]


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class FormatDetection(unittest.TestCase):

    def parse(self, sample):
        return certs.parse_cert_file(get_pki().sample(sample))

    def test_format_detection(self):
        expected = {
            "der-as.pem": (certs.FMT_DER, 1),
            "pkcs7.crt": (certs.FMT_PKCS7, 0),
            "pkcs12.bin": (certs.FMT_PKCS12, 0),
            "key-only.crt": (certs.FMT_KEY, 0),
            "csr.pem": (certs.FMT_CSR, 0),
            "empty.pem": (certs.FMT_EMPTY, 0),
            "mixed.pem": (certs.FMT_PEM, 1),
        }
        for sample, (fmt, count) in expected.items():
            with self.subTest(sample=sample):
                parsed = self.parse(sample)
                self.assertEqual((parsed.format, len(parsed.certs)), (fmt, count))

    def test_der_certificate_named_pem_is_parsed_and_says_der(self):
        items = by_check(certs.inspect_cert_file(get_pki().sample("der-as.pem")))
        [parse] = items["cert.parse"]
        self.assertEqual(parse.status, F.PASS)
        self.assertIn("format: DER", parse.evidence)

    def test_pkcs7_names_the_conversion(self):
        [f] = certs.inspect_cert_file(get_pki().sample("pkcs7.crt"))
        self.assertEqual(f.status, F.FAIL)
        text = " ".join(f.evidence)
        self.assertIn("PKCS#7", text)
        self.assertIn("openssl pkcs7 -print_certs", text)

    def test_pkcs12_without_extension(self):
        [f] = certs.inspect_cert_file(get_pki().sample("pkcs12.bin"))
        self.assertEqual(f.status, F.FAIL)
        self.assertIn("PKCS#12", " ".join(f.evidence))

    def test_private_key_supplied_as_certificate(self):
        [f] = certs.inspect_cert_file(get_pki().sample("key-only.crt"))
        self.assertEqual(f.status, F.FAIL)
        self.assertIn("this is a private key, not a certificate", " ".join(f.evidence))

    def test_empty_file(self):
        [f] = certs.inspect_cert_file(get_pki().sample("empty.pem"))
        self.assertEqual((f.status, f.evidence), (F.FAIL, ["file is empty"]))

    def test_no_key_bytes_in_any_evidence(self):
        lines = key_lines()
        for sample in ("key-only.crt", "pkcs12.bin", "mixed.pem"):
            with self.subTest(sample=sample):
                items = certs.inspect_cert_file(get_pki().sample(sample))
                text = "\n".join(e for f in items for e in f.evidence + [f.detail])
                for line in lines:
                    self.assertNotIn(line, text)


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class StrictParsing(unittest.TestCase):

    def test_regression_r6_truncated_block(self):
        items = by_check(certs.inspect_cert_file(get_pki().sample("truncated.pem")))
        [parse] = items["cert.parse"]
        self.assertEqual(parse.status, F.FAIL)
        self.assertIn("block 2 is not terminated", " ".join(parse.evidence))
        self.assertEqual(list(items), ["cert.parse"], "no other verdict on a broken file")

    def test_regression_r6_corrupt_middle_block(self):
        items = certs.inspect_cert_file(get_pki().sample("corrupt.pem"))
        parse = [f for f in items if f.check == "cert.parse"]
        self.assertEqual([f.status for f in parse], [F.FAIL])
        self.assertIn("block 2: invalid Base64", " ".join(parse[0].evidence))

    def test_malformed_asn1_inside_valid_base64(self):
        import base64
        bogus = base64.encodebytes(b"\x30\x03\x02\x01\x00" * 20)
        data = b"-----BEGIN CERTIFICATE-----\n" + bogus + b"-----END CERTIFICATE-----\n"
        parsed = certs.parse_cert_bytes(data)
        self.assertEqual(parsed.problems,
                         ["block 1: not a valid X.509 certificate (malformed ASN.1)"])

    def test_stray_end_marker(self):
        with open(get_pki().leaf, "rb") as fh:
            data = fh.read() + b"-----END CERTIFICATE-----\n"
        self.assertIn("without a matching BEGIN", " ".join(certs.parse_cert_bytes(data).problems))

    def test_clean_chain_file_still_parses(self):
        parsed = certs.parse_cert_file(get_pki().fullchain)
        self.assertTrue(parsed.ok)
        self.assertEqual([c.position for c in parsed.certs], [1, 2])

    def test_load_cert_file_reports_the_problem(self):
        found, err = certs.load_cert_file(get_pki().sample("truncated.pem"))
        self.assertEqual(len(found), 1)
        self.assertIn("not terminated", err)


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class ConfiguredFileOnServer(unittest.TestCase):

    def chainfile(self, path):
        return FakeSession("")._chainfile_finding(path)

    def test_truncated_ssl_certificate_file_fails(self):
        f = self.chainfile(get_pki().sample("truncated.pem"))
        self.assertEqual(f.status, F.FAIL)
        text = " ".join(f.evidence)
        self.assertIn("block 2 is not terminated", text)
        self.assertNotIn("not sent", text)

    def test_der_ssl_certificate_file_fails_because_nginx_needs_pem(self):
        f = self.chainfile(get_pki().sample("der-as.pem"))
        self.assertEqual(f.status, F.FAIL)
        self.assertIn("nginx loads only PEM", " ".join(f.evidence))
        self.assertIn("-inform DER", f.recommendation)

    def test_key_in_the_certificate_file_is_noted_not_read(self):
        f = self.chainfile(get_pki().sample("mixed.pem"))
        self.assertIn("private-key block is present and was not read", " ".join(f.evidence))
        text = " ".join(f.evidence)
        for line in key_lines():
            self.assertNotIn(line, text)

    def test_cat_fallback_when_base64_is_missing(self):
        session = FakeSession("")
        real = session.run

        def no_base64(cmd):
            if "| base64" in cmd:
                return 127, "", "base64: not found", ""
            return real(cmd)

        with mock.patch.object(session, "run", side_effect=no_base64):
            f = session._chainfile_finding(get_pki().fullchain)
        self.assertEqual(f.status, F.PASS)

    def test_exact_bytes_are_read(self):
        data, why = FakeSession("").read_public_file(get_pki().sample("der-as.pem"))
        with open(get_pki().sample("der-as.pem"), "rb") as fh:
            self.assertEqual(data, fh.read())
        self.assertEqual(why, "")


if __name__ == "__main__":
    unittest.main()
