"""Tests for CLI streaming of findings as checks complete."""

import contextlib
import io
import os
import unittest

from fixtures.pki import get_pki, openssl_available

from ssl_doctor import certs, cli, local, netchecks


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class StreamingRegressionTests(unittest.TestCase):
    def setUp(self):
        self.pki = get_pki()

    def test_no_emit_produces_no_output(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            items = certs.inspect_cert_file(self.pki.leaf, "")
        self.assertTrue(len(items) > 0)
        self.assertEqual(buf.getvalue(), "")

    def test_emit_receives_every_finding(self):
        received = []
        items = certs.inspect_cert_file(self.pki.leaf, "", emit=received.append)
        self.assertEqual(len(received), len(items))
        self.assertEqual([f.title for f in received],
                        [f.title for f in items])

    def test_stream_output_false_when_piped(self):
        app = cli.SSLDoctorCLI()
        # simulate piped stdout
        fake = io.StringIO()
        old = __import__("sys").stdout
        __import__("sys").stdout = fake
        try:
            self.assertFalse(app._STREAM_OUTPUT)
        finally:
            __import__("sys").stdout = old

    def test_batch_mode_disables_streaming(self):
        app = cli.SSLDoctorCLI()
        app._BATCH_MODE = True
        self.assertFalse(app._STREAM_OUTPUT)


if __name__ == "__main__":
    unittest.main()
