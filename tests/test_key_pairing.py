"""private-key-inspection: pairing is a cryptographic comparison, and an
inconclusive result is never reported as a mismatch.

Server-side cases run the real pairing script through LocalSession (/bin/sh
and openssl); local cases call certs.match_cert_key.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from fixtures.pki import get_pki, openssl_available

from ssl_doctor import certs, server
from ssl_doctor import findings as F
from ssl_doctor.analyze import diagnose

EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _derived(name, *args):
    """A key derived from the PKI leaf key with openssl, cached in a temp dir."""
    d = _derived.dir
    if d is None:
        d = _derived.dir = tempfile.mkdtemp(prefix="ssldoctor-pairing-")
    path = os.path.join(d, name)
    if not os.path.exists(path):
        subprocess.run(["openssl", *args, "-in", get_pki().leaf_key, "-out", path],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return path


_derived.dir = None


def encrypted_pem_key():
    return _derived("leaf-enc.key", "pkcs8", "-topk8", "-v2", "aes256",
                    "-passout", "pass:secret")


def encrypted_der_key():
    return _derived("leaf-enc.der", "pkcs8", "-topk8", "-v2", "aes256",
                    "-passout", "pass:secret", "-outform", "DER")


def tearDownModule():
    if _derived.dir:
        shutil.rmtree(_derived.dir, True)


def server_pairing(cert, key):
    session = server.LocalSession()
    items = session.scan_cert(cert, key, states={cert: "readable", key: "readable"})
    return {f.check: f for f in items}["srv.keymatch"], items


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class ServerPairing(unittest.TestCase):

    def test_matching_pair_passes(self):
        p = get_pki()
        f, _ = server_pairing(p.leaf, p.leaf_key)
        self.assertEqual(f.status, F.PASS)

    def test_mismatched_pair_fails_with_both_digests(self):
        p = get_pki()
        f, _ = server_pairing(p.leaf, p.cn_only_key)
        self.assertEqual(f.status, F.FAIL)
        digests = [e for e in f.evidence if "sha256" in e]
        self.assertEqual(len(digests), 2)
        self.assertFalse(any(EMPTY_SHA256 in e for e in f.evidence))

    def test_regression_r1_encrypted_server_key(self):
        """R1: an encrypted key was a confirmed mismatch (digest of empty output)."""
        f, items = server_pairing(get_pki().leaf, encrypted_pem_key())
        self.assertEqual(f.status, F.NOT_TESTED)
        self.assertEqual(f.failure_kind, "key-encrypted")
        text = " ".join(f.evidence)
        self.assertIn("passphrase-encrypted", text)
        self.assertNotIn("does NOT match", text)
        self.assertNotIn(EMPTY_SHA256, text)
        causes = diagnose(items).causes
        self.assertFalse([c for c in causes if "does not match" in c.summary])

    def test_der_encrypted_key_on_the_server(self):
        f, _ = server_pairing(get_pki().leaf, encrypted_der_key())
        self.assertEqual((f.status, f.failure_kind), (F.NOT_TESTED, "key-encrypted"))

    def test_a_certificate_given_as_key_is_not_a_mismatch(self):
        p = get_pki()
        f, _ = server_pairing(p.leaf, p.intermediate)
        self.assertEqual(f.status, F.NOT_TESTED)
        self.assertNotIn("does NOT match", " ".join(f.evidence))

    def test_failed_digest_step_is_not_tested(self):
        p = get_pki()
        session = server.LocalSession()
        reply = (0, "@@SSLDOCTOR fail=certificate public key\n"
                    f"@@SSLDOCTOR cert={EMPTY_SHA256}\n@@SSLDOCTOR key=ab\n", "", "")
        real_run = session.run

        def run(cmd):
            return reply if cmd.startswith("exec 3>&1") else real_run(cmd)

        with mock.patch.object(session, "run", side_effect=run):
            items = session.scan_cert(p.leaf, p.leaf_key,
                                      states={p.leaf: "readable", p.leaf_key: "readable"})
        f = {i.check: i for i in items}["srv.keymatch"]
        self.assertEqual((f.status, f.failure_kind), (F.NOT_TESTED, "command-failed"))
        self.assertIn("certificate public key", f.evidence[0])

    def test_an_empty_digest_is_never_compared(self):
        session = server.LocalSession()
        reply = (0, f"@@SSLDOCTOR cert={EMPTY_SHA256}\n@@SSLDOCTOR key={EMPTY_SHA256}\n",
                 "", "")
        with mock.patch.object(session, "run", return_value=reply):
            cert_h, key_h, failed = session._pairing_digests("/c.pem", "/k.key")
        self.assertEqual((cert_h, key_h), ("", ""))
        self.assertTrue(failed)

    def test_transport_failure_is_not_tested(self):
        session = server.LocalSession()
        with mock.patch.object(session, "run",
                               return_value=(124, "", "", "command timed out after 20s")):
            _c, _k, failed = session._pairing_digests("/c.pem", "/k.key")
        self.assertIn("timed out", failed)

    def test_no_key_material_in_any_finding(self):
        _f, items = server_pairing(get_pki().leaf, get_pki().leaf_key)
        with open(get_pki().leaf_key) as fh:
            body = [ln for ln in fh.read().splitlines() if ln and "-----" not in ln]
        text = "\n".join(e for f in items for e in f.evidence + [f.detail])
        for line in body:
            self.assertNotIn(line, text)


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class LocalPairing(unittest.TestCase):

    def test_matching_pair_passes(self):
        p = get_pki()
        [f] = certs.match_cert_key(p.leaf, p.leaf_key)
        self.assertEqual(f.status, F.PASS)

    def test_mismatched_pair_fails(self):
        p = get_pki()
        [f] = certs.match_cert_key(p.leaf, p.cn_only_key)
        self.assertEqual(f.status, F.FAIL)

    def test_pem_encrypted_key_is_not_tested(self):
        [f] = certs.match_cert_key(get_pki().leaf, encrypted_pem_key())
        self.assertEqual((f.status, f.failure_kind), (F.NOT_TESTED, "key-encrypted"))

    def test_regression_r8_der_encrypted_key(self):
        """R8: a DER-encoded encrypted PKCS#8 key was FAIL 'private key unreadable'."""
        [f] = certs.match_cert_key(get_pki().leaf, encrypted_der_key())
        self.assertEqual((f.status, f.failure_kind), (F.NOT_TESTED, "key-encrypted"))
        self.assertNotIn("unreadable", " ".join(f.evidence))

    def test_regression_o3_cert_pubkey_unextractable(self):
        """O3: an underivable certificate digest was FAIL 'does NOT belong'."""
        p = get_pki()
        with mock.patch.object(certs, "_public_key_sha256_from_pem_bytes",
                               return_value=(None, "unable to load certificate")):
            [f] = certs.match_cert_key(p.leaf, p.leaf_key)
        self.assertEqual((f.status, f.failure_kind), (F.NOT_TESTED, "command-failed"))
        self.assertNotIn("does NOT belong", " ".join(f.evidence))

    def test_plain_der_key_matches(self):
        p = get_pki()
        der = _derived("leaf.der", "pkey", "-outform", "DER")
        [f] = certs.match_cert_key(p.leaf, der)
        self.assertEqual(f.status, F.PASS)

    def test_missing_key_is_not_tested(self):
        [f] = certs.match_cert_key(get_pki().leaf, "/nonexistent/leaf.key")
        self.assertEqual(f.status, F.NOT_TESTED)

    def test_without_openssl_the_pairing_is_not_tested(self):
        p = get_pki()
        with mock.patch.object(certs.shutil, "which", return_value=None):
            [f] = certs.match_cert_key(p.leaf, p.leaf_key)
        self.assertEqual((f.status, f.failure_kind), (F.NOT_TESTED, "verifier-unavailable"))

    def test_local_mismatch_is_still_a_confirmed_cause(self):
        p = get_pki()
        items = certs.match_cert_key(p.leaf, p.cn_only_key)
        self.assertTrue([c for c in diagnose(items).causes
                         if c.certainty == "confirmed" and "do not match" in c.summary])

    def test_local_encrypted_key_raises_no_cause(self):
        items = certs.match_cert_key(get_pki().leaf, encrypted_der_key())
        self.assertEqual(diagnose(items).causes, [])


if __name__ == "__main__":
    unittest.main()
