"""server-certificate-deployment (P5): per-scan comparison, multiple
certificate/key pairs, listen addresses, permissions, encrypted-key startup,
the certificate inventory, and path failures in the verdict."""

import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from fixtures.fake_server import FakeSession
from fixtures.pki import get_pki, openssl_available

from ssl_doctor import certs, server
from ssl_doctor import findings as F
from ssl_doctor.analyze import diagnose


def sha(path):
    return certs.parse_cert_file(path).certs[0].sha256


def scan(config, **kw):
    session = FakeSession(config)
    items = session.nginx_scan("shop.test", **kw)
    return session, items


def by(items):
    out = {}
    for f in items:
        out.setdefault(f.check, []).append(f)
    return out


def dual_config(keys=None):
    p = get_pki()
    p.sample("ecdsa-chain.pem")
    keys = keys if keys is not None else [p.leaf_key, p.path("ecdsa_leaf.key")]
    key_lines = "".join(f"ssl_certificate_key {k}; " for k in keys)
    return (f"http {{ server {{ listen 443 ssl; server_name shop.test; "
            f"ssl_certificate {p.fullchain}; "
            f"ssl_certificate {p.sample('ecdsa-chain.pem')}; {key_lines}}} }}")


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class PerScanContext(unittest.TestCase):

    def test_regression_o2_stale_compare(self):
        p = get_pki()
        session = FakeSession(f"""http {{ server {{ listen 443 ssl; server_name shop.test;
            ssl_certificate /nonexistent/gone.pem; ssl_certificate_key {p.leaf_key}; }} }}""")
        session.begin_scan()                                 # an earlier /server cert
        session.scan_cert(p.leaf, states={p.leaf: "readable"})
        session.nginx_scan("shop.test")                      # this scan reads nothing
        f = session.compare_configured_vs_presented(sha(p.leaf))
        self.assertEqual(f.status, F.NOT_TESTED)
        self.assertIn("not read in this scan", f.evidence[0])


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class MultiplePairs(unittest.TestCase):

    def test_rsa_and_ecdsa_pairs_are_both_validated(self):
        _s, items = scan(dual_config())
        b = by(items)
        [path] = b["nginx.path_resolution"]
        self.assertEqual(path.status, F.PASS)
        self.assertEqual([e for e in path.evidence if e.startswith("pair ")],
                         ["pair 1:", "pair 2:"])
        self.assertEqual([f.status for f in b["srv.keymatch"]], [F.PASS, F.PASS])
        self.assertTrue(all(f.evidence[0].startswith("certificate pair ")
                            for f in b["srv.keymatch"]))
        self.assertEqual(len(b["nginx.chainfile"]), 2)

    def test_more_certificates_than_keys_fails(self):
        _s, items = scan(dual_config(keys=[get_pki().leaf_key]))
        [path] = by(items)["nginx.path_resolution"]
        self.assertEqual(path.status, F.FAIL)
        self.assertIn("2 certificates but 1 key configured", path.evidence[0])

    def test_single_pair_wording_is_unchanged(self):
        p = get_pki()
        _s, items = scan(f"""http {{ server {{ listen 443 ssl; server_name shop.test;
            ssl_certificate {p.fullchain}; ssl_certificate_key {p.leaf_key}; }} }}""")
        [keymatch] = by(items)["srv.keymatch"]
        self.assertFalse(keymatch.evidence[0].startswith("certificate pair"))

    def test_listen_address_selects_the_block(self):
        p = get_pki()
        config = (f"http {{ server {{ listen 10.0.0.5:443 ssl; server_name shop.test; "
                  f"ssl_certificate {p.fullchain}; ssl_certificate_key {p.leaf_key}; }} "
                  f"server {{ listen 443 ssl; server_name shop.test; "
                  f"ssl_certificate {p.sample('ecdsa-chain.pem')}; "
                  f"ssl_certificate_key {p.path('ecdsa_leaf.key')}; }} }}")
        _s, items = scan(config, addresses=("10.0.0.5",))
        domain = by(items)["nginx.domain"][0]
        self.assertIn("listen: 10.0.0.5:443 ssl", domain.evidence)
        self.assertTrue(any("10.0.0.5:443 has its own socket" in e for e in domain.evidence))
        _s, items = scan(config, addresses=("192.0.2.1",))
        self.assertIn("listen: 443 ssl", by(items)["nginx.domain"][0].evidence)


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class Compare(unittest.TestCase):

    def test_ecdsa_certificate_served_from_a_dual_configuration(self):
        p = get_pki()
        session, _items = scan(dual_config())
        f = session.compare_configured_vs_presented(sha(p.path("ecdsa_leaf.pem")))
        self.assertEqual(f.status, F.PASS)
        self.assertIn("ecdsa-chain.pem", f.evidence[0])

    def test_no_configured_certificate_matches(self):
        session, _items = scan(dual_config())
        f = session.compare_configured_vs_presented("ab" * 32)
        self.assertEqual(f.status, F.FAIL)
        self.assertEqual(len([e for e in f.evidence if e.startswith("configured:")]), 2)

    def test_served_intermediate_differs_from_the_file(self):
        p = get_pki()
        session, _items = scan(f"""http {{ server {{ listen 443 ssl; server_name shop.test;
            ssl_certificate {p.fullchain}; ssl_certificate_key {p.leaf_key}; }} }}""")
        presented = [sha(p.leaf), sha(p.other_intermediate)]
        f = session.compare_configured_vs_presented(presented[0], presented_chain=presented,
                                                     presented_from="192.0.2.10")
        self.assertEqual(f.status, F.WARNING)
        text = " ".join(f.evidence)
        self.assertIn("position 2 differs", text)
        self.assertIn("(replaced)", text)
        self.assertIn("presented chain captured from 192.0.2.10", text)
        self.assertTrue(any("not reloaded" in c.summary for c in diagnose([f]).causes))


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class Permissions(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ssldoctor-perms-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def copy(self, src, name, mode):
        path = os.path.join(self.dir, name)
        shutil.copy(src, path)
        os.chmod(path, mode)
        return path

    def test_world_readable_key_named_pem_warns(self):
        key = self.copy(get_pki().leaf_key, "site.pem", 0o644)
        [f] = server.LocalSession().permissions([(key, "key")])
        self.assertEqual(f.status, F.WARNING)
        self.assertIn("private key readable by other users", f.evidence)

    def test_service_account_cannot_read_the_certificate(self):
        # owned by the test's account, mode 0600: "nobody" can read it neither
        # under root nor in the unprivileged CI job
        cert = self.copy(get_pki().leaf, "site.crt", 0o600)
        [f] = server.LocalSession().permissions([(cert, "certificate")], reader="nobody")
        self.assertEqual(f.status, F.FAIL)
        self.assertIn(f"service account nobody cannot read {cert}", f.evidence)
        self.assertTrue(any("cannot read its certificate or key" in c.summary
                            for c in diagnose([f]).causes))

    def test_permissions_run_in_the_nginx_scan(self):
        p = get_pki()
        _s, items = scan(f"""http {{ server {{ listen 443 ssl; server_name shop.test;
            ssl_certificate {p.fullchain}; ssl_certificate_key {p.leaf_key}; }} }}""")
        perms = by(items)["srv.perms"]
        self.assertEqual({f.target for f in perms}, {p.fullchain, p.leaf_key})

    def test_no_content_is_read(self):
        session = server.LocalSession()
        commands = []
        real = session.run
        with mock.patch.object(session, "run",
                               side_effect=lambda c: commands.append(c) or real(c)):
            session.permissions([(get_pki().leaf_key, "key")])
        self.assertTrue(commands)
        self.assertTrue(all(c.startswith(("stat ", "id ")) for c in commands), commands)


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class KeyStartup(unittest.TestCase):

    def encrypted_key(self):
        d = tempfile.mkdtemp(prefix="ssldoctor-enc-")
        self.addCleanup(shutil.rmtree, d, True)
        out = os.path.join(d, "enc.key")
        subprocess.run(["openssl", "pkcs8", "-topk8", "-v2", "aes256", "-in",
                        get_pki().leaf_key, "-passout", "pass:secret", "-out", out],
                       check=True, capture_output=True)
        pw = os.path.join(d, "pass.txt")
        with open(pw, "w") as fh:
            fh.write("secret-passphrase-line\n")
        return out, pw

    def run_scan(self, key, password_file=""):
        p = get_pki()
        extra = f"ssl_password_file {password_file};" if password_file else ""
        session = FakeSession(f"""http {{ server {{ listen 443 ssl; server_name shop.test;
            ssl_certificate {p.fullchain}; ssl_certificate_key {key}; {extra} }} }}""")
        commands = []
        real = session.run
        with mock.patch.object(session, "run",
                               side_effect=lambda c: commands.append(c) or real(c)):
            items = session.nginx_scan("shop.test")
        return {f.check: f for f in items}, items, commands

    def test_encrypted_key_without_ssl_password_file(self):
        key, _pw = self.encrypted_key()
        b, items, _c = self.run_scan(key)
        self.assertEqual(b["srv.keystartup"].status, F.FAIL)
        self.assertIn("without ssl_password_file", " ".join(b["srv.keystartup"].evidence))
        self.assertTrue(any("cannot start with the configured encrypted private key"
                            in c.summary for c in diagnose(items).causes))

    def test_encrypted_key_with_a_passphrase_file_never_reads_it(self):
        key, pw = self.encrypted_key()
        b, items, _commands = self.run_scan(key, pw)
        self.assertEqual(b["srv.keystartup"].status, F.PASS)
        self.assertIn("its content is not read", " ".join(b["srv.keystartup"].evidence))
        self.assertEqual(b["srv.keymatch"].status, F.NOT_TESTED)
        text = "\n".join(e for f in items for e in f.evidence)
        self.assertNotIn("secret-passphrase-line", text)
        # command audit against the real probe scripts (LocalSession runs /bin/sh)
        session = server.LocalSession()
        session._password_file = (pw, pw)
        commands = []
        real = session.run
        with mock.patch.object(session, "run",
                               side_effect=lambda c: commands.append(c) or real(c)):
            f = session._keystartup_finding(key)
        self.assertEqual(f.status, F.PASS)
        touching = [c for c in commands if pw in c]
        self.assertTrue(touching)
        self.assertTrue(all(c.startswith("for p in ") and "cat " not in c
                            and "base64" not in c and "head " not in c
                            for c in touching), touching)

    def test_unencrypted_key_raises_no_startup_finding(self):
        b, _items, _c = self.run_scan(get_pki().leaf_key)
        self.assertNotIn("srv.keystartup", b)


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class Inventory(unittest.TestCase):

    CONFIG = None

    def config(self):
        p = get_pki()
        return (f"http {{ server {{ listen 443 ssl; server_name shop.test; "
                f"ssl_certificate {p.fullchain}; ssl_certificate_key {p.leaf_key}; }} "
                f"server {{ listen 443 ssl default_server; server_name other.test; "
                f"ssl_certificate {p.sample('ecdsa-chain.pem')}; "
                f"ssl_certificate_key {p.path('ecdsa_leaf.key')}; }} }}")

    def test_another_block_covering_the_domain_warns(self):
        session, _items = scan(self.config())
        f = session.inventory_finding(sha(get_pki().leaf))
        self.assertEqual(f.status, F.WARNING)
        self.assertIn("another server block (other.test) has a certificate covering "
                      "shop.test", " ".join(f.evidence))
        self.assertTrue(any("[selected, served, covers shop.test]" in e for e in f.evidence))

    def test_served_certificate_from_the_default_server(self):
        session, _items = scan(self.config())
        f = session.inventory_finding(sha(get_pki().path("ecdsa_leaf.pem")))
        self.assertIn("the presented certificate belongs to server block 'other.test'",
                      " ".join(f.evidence))


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class PathFailureVerdict(unittest.TestCase):

    def test_missing_certificate_in_a_verified_configuration(self):
        p = get_pki()
        _s, items = scan(f"""http {{ server {{ listen 443 ssl; server_name shop.test;
            ssl_certificate /nonexistent/gone.pem; ssl_certificate_key {p.leaf_key}; }} }}""")
        b = {f.check: f for f in items}
        self.assertEqual(b["nginx.conf"].status, F.PASS)
        self.assertEqual(b["nginx.path_resolution"].status, F.FAIL)
        d = diagnose(items)
        self.assertEqual(d.overall, F.FAIL)
        self.assertTrue(any(c.certainty == "confirmed" and c.origin == "server"
                            and "cannot be used" in c.summary for c in d.causes))


if __name__ == "__main__":
    unittest.main()
