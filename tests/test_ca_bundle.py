"""certificate-file-inspection: root / CA bundle files are parsed and classified.

A root needs CA:TRUE and a verified self-signature; a file name or a subject
that equals the issuer proves nothing.
"""

import contextlib
import io
import unittest
from unittest import mock

from fixtures.fake_server import FakeSession
from fixtures.pki import get_pki, openssl_available

from ssl_doctor import certs, chainval, cli
from ssl_doctor import findings as F


def cafile(path, purpose=chainval.CA_ROOTS):
    chainval._LINK_CACHE.clear()
    chainval._SELF_CACHE.clear()
    return chainval.ca_file_finding(certs.parse_cert_file(path), path, F.SCOPE_LOCAL,
                                    purpose)


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class SuppliedRootFile(unittest.TestCase):

    def test_root_file_with_an_intermediate_warns(self):
        f = cafile(get_pki().sample("ca-bundle.pem"))
        self.assertEqual(f.status, F.WARNING)
        text = " ".join(f.evidence)
        self.assertIn("certificates in file: 2", f.evidence)
        self.assertIn("file contains non-root certificates", text)
        self.assertTrue([e for e in f.evidence if e.startswith("#1 root")])
        self.assertTrue([e for e in f.evidence if e.startswith("#2 intermediate")])

    def test_name_only_root_is_not_a_root(self):
        f = cafile(get_pki().sample("name-only-root.pem"))
        self.assertEqual(f.status, F.WARNING)
        text = " ".join(f.evidence)
        self.assertIn("subject equals issuer, but it is not self-signed", text)
        self.assertIn("the file holds no root certificate", text)

    def test_genuine_root_file_passes(self):
        f = cafile(get_pki().root)
        self.assertEqual(f.status, F.PASS)
        self.assertIn("1 verified root certificate(s)", f.evidence)

    def test_broken_bundle_fails(self):
        self.assertEqual(cafile(get_pki().sample("truncated.pem")).status, F.FAIL)

    def test_without_openssl_roots_are_not_claimed(self):
        with mock.patch.object(certs.shutil, "which", return_value=None), \
                mock.patch.object(chainval.shutil, "which", return_value=None):
            f = cafile(get_pki().root)
        self.assertEqual(f.status, F.WARNING)
        self.assertTrue(f.uncertainty)

    def test_cli_command(self):
        app = cli.SSLDoctorCLI()
        with contextlib.redirect_stdout(io.StringIO()):
            app.execute(f"/cert cafile {get_pki().sample('ca-bundle.pem')}")
        [f] = [i for i in app.store.all() if i.check == "cert.cafile"]
        self.assertEqual(f.status, F.WARNING)


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class ServiceCaFile(unittest.TestCase):

    def test_intermediates_in_a_service_ca_file_are_normal(self):
        f = cafile(get_pki().sample("ca-bundle.pem"), chainval.CA_SERVICE)
        self.assertEqual(f.status, F.PASS)

    def test_leaf_in_a_service_ca_file_warns(self):
        f = cafile(get_pki().fullchain, chainval.CA_SERVICE)
        self.assertEqual(f.status, F.WARNING)
        self.assertIn("a leaf (non-CA) certificate, not a CA", " ".join(f.evidence))

    def nginx(self, trusted):
        p = get_pki()
        return {f.check: f for f in FakeSession(f"""http {{ server {{ listen 443 ssl;
            server_name shop.test; ssl_certificate {p.fullchain};
            ssl_certificate_key {p.leaf_key};
            ssl_trusted_certificate {trusted}; }} }}""").nginx_scan("shop.test")}

    def test_nginx_ssl_trusted_certificate_is_checked(self):
        f = self.nginx(get_pki().sample("ca-bundle.pem"))["cert.cafile"]
        self.assertEqual((f.status, f.scope), (F.PASS, F.SCOPE_SERVER))
        self.assertIn("ssl_trusted_certificate", f.evidence[0])

    def test_missing_ca_file_is_not_tested(self):
        f = self.nginx("/nonexistent/ca.pem")["cert.cafile"]
        self.assertEqual(f.status, F.NOT_TESTED)
        self.assertIn("missing", " ".join(f.evidence))


if __name__ == "__main__":
    unittest.main()
