import socket
import ssl
import subprocess
import unittest

from fixtures.pki import HOSTNAME, get_pki, openssl_available
from fixtures.tls_server import MODES, TLSServer


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class FixtureTests(unittest.TestCase):

    def test_valid_chain_verifies(self):
        p = get_pki()
        proc = subprocess.run(
            ["openssl", "verify", "-CAfile", p.root, "-untrusted", p.intermediate, p.leaf],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_wrong_intermediate_does_not_verify(self):
        p = get_pki()
        proc = subprocess.run(
            ["openssl", "verify", "-CAfile", p.root, "-untrusted", p.other_intermediate,
             p.leaf], capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)

    def test_every_server_mode_handshakes(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        for mode in MODES:
            with self.subTest(mode=mode), TLSServer(get_pki(), mode) as srv:
                raw = socket.create_connection((srv.host, srv.port), timeout=5)
                with ctx.wrap_socket(raw, server_hostname=HOSTNAME) as s:
                    self.assertTrue(s.getpeercert(binary_form=True))


if __name__ == "__main__":
    unittest.main()
