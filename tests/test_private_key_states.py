"""private-key-inspection: the key state is classified before any pairing.

Every format is built with the openssl binary and classified twice: by the
local classifier and by the remote probe script (run through LocalSession,
i.e. a real /bin/sh with real openssl).
"""

import atexit
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from fixtures.pki import openssl_available

from ssl_doctor import certs, server

_KEYS = {}


def _openssl(*args, cwd):
    subprocess.run(["openssl", *args], cwd=cwd, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def keys():
    """name -> (path, expected state); built once per process."""
    if _KEYS:
        return _KEYS
    d = tempfile.mkdtemp(prefix="ssldoctor-keys-")
    atexit.register(shutil.rmtree, d, True)
    _openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
             "-out", "plain.key", cwd=d)
    _openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
             "-out", "ec.key", cwd=d)
    _openssl("pkey", "-in", "plain.key", "-traditional", "-out", "rsa-trad.key", cwd=d)
    _openssl("pkey", "-in", "plain.key", "-outform", "DER", "-out", "plain.der", cwd=d)
    _openssl("pkey", "-in", "plain.key", "-traditional", "-aes256",
             "-passout", "pass:secret", "-out", "legacy-enc.key", cwd=d)
    _openssl("pkcs8", "-topk8", "-in", "plain.key", "-v2", "aes256",
             "-passout", "pass:secret", "-out", "pkcs8-enc.key", cwd=d)
    _openssl("pkcs8", "-topk8", "-in", "plain.key", "-v2", "aes256",
             "-passout", "pass:secret", "-outform", "DER", "-out", "pkcs8-enc.der", cwd=d)
    _openssl("req", "-x509", "-key", "plain.key", "-subj", "/CN=keys.test", "-days", "1",
             "-out", "cert.pem", cwd=d)
    _openssl("pkcs12", "-export", "-in", "cert.pem", "-inkey", "plain.key",
             "-passout", "pass:secret", "-out", "bundle.p12", cwd=d)
    with open(os.path.join(d, "not-a-key.txt"), "w") as fh:
        fh.write("hello\n")
    expected = {
        "plain.key": certs.KEY_READABLE,          # PKCS#8 PEM
        "ec.key": certs.KEY_READABLE,
        "rsa-trad.key": certs.KEY_READABLE,       # BEGIN RSA PRIVATE KEY
        "plain.der": certs.KEY_READABLE,
        "legacy-enc.key": certs.KEY_ENCRYPTED,    # Proc-Type: 4,ENCRYPTED
        "pkcs8-enc.key": certs.KEY_ENCRYPTED,     # BEGIN ENCRYPTED PRIVATE KEY
        "pkcs8-enc.der": certs.KEY_ENCRYPTED,     # DER EncryptedPrivateKeyInfo
        "bundle.p12": certs.KEY_ENCRYPTED,        # PKCS#12
        "cert.pem": certs.KEY_UNSUPPORTED,        # a certificate, not a key
        "not-a-key.txt": certs.KEY_UNSUPPORTED,
    }
    _KEYS.update({name: (os.path.join(d, name), state) for name, state in expected.items()})
    return _KEYS


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class LocalKeyStates(unittest.TestCase):

    def test_every_format_is_classified(self):
        for name, (path, expected) in keys().items():
            with self.subTest(key=name):
                self.assertEqual(certs.key_file_state(path), expected)

    def test_missing_file(self):
        self.assertEqual(certs.key_file_state("/nonexistent/ssl-doctor.key"),
                         certs.KEY_MISSING)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root reads everything")
    def test_unreadable_file(self):
        path, _ = keys()["plain.key"]
        locked = path + ".locked"
        shutil.copy(path, locked)
        os.chmod(locked, 0)
        self.assertEqual(certs.key_file_state(locked), certs.KEY_UNREADABLE)

    def test_truncated_der_is_unsupported_not_readable(self):
        path, _ = keys()["plain.der"]
        with open(path, "rb") as fh:
            data = fh.read()
        self.assertEqual(certs.key_state(data[:40]), certs.KEY_UNSUPPORTED)


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class RemoteKeyStates(unittest.TestCase):
    """The same states from the server-side probe script."""

    def setUp(self):
        self.session = server.LocalSession()

    def test_every_format_is_classified(self):
        for name, (path, expected) in keys().items():
            with self.subTest(key=name):
                self.assertEqual(self.session.key_state(path), (expected, ""))

    def test_missing_file(self):
        self.assertEqual(self.session.key_state("/nonexistent/ssl-doctor.key"),
                         (certs.KEY_MISSING, ""))

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root reads everything")
    def test_unreadable_file(self):
        path, _ = keys()["plain.key"]
        locked = path + ".remote-locked"
        shutil.copy(path, locked)
        os.chmod(locked, 0)
        self.assertEqual(self.session.key_state(locked), (certs.KEY_UNREADABLE, ""))

    def test_path_with_shell_metacharacters_is_quoted(self):
        path, _ = keys()["pkcs8-enc.key"]
        odd = os.path.join(os.path.dirname(path), "a key; echo pwned.key")
        shutil.copy(path, odd)
        state, _ = self.session.key_state(odd)
        self.assertEqual(state, certs.KEY_ENCRYPTED)

    def test_without_openssl_a_plain_key_is_undetermined(self):
        bindir = tempfile.mkdtemp(prefix="ssldoctor-bin-")
        self.addCleanup(shutil.rmtree, bindir, True)
        for tool in ("head", "grep"):
            os.symlink(shutil.which(tool), os.path.join(bindir, tool))
        with mock.patch.dict(os.environ, {"PATH": bindir}):
            plain = self.session.key_state(keys()["plain.key"][0])
            encrypted = self.session.key_state(keys()["pkcs8-enc.key"][0])
        self.assertEqual(plain, ("noverifier", ""))
        self.assertEqual(encrypted, (certs.KEY_ENCRYPTED, ""))

    def test_output_is_only_the_token(self):
        path, _ = keys()["plain.der"]
        rc, out, err, fatal = self.session.run(
            server.ServerSession._KEY_STATE_SCRIPT.format(path=shlex.quote(path)))
        self.assertEqual(out.strip(), "@@SSLDOCTOR keystate=readable")
        self.assertEqual(err, "")

    def test_failed_probe_is_undetermined(self):
        with mock.patch.object(self.session, "run", return_value=(127, "", "boom", "")):
            state, reason = self.session.key_state("/etc/ssl/x.key")
        self.assertEqual(state, "")
        self.assertIn("boom", reason)


if __name__ == "__main__":
    unittest.main()
