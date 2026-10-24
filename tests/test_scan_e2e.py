"""End-to-end regression: `/scan --client-only` verdicts for the reproduced scenarios.

The table mirrors the reproduction that exposed the original defect: v0.2.0
reported a leaf-only nginx as PASS whenever the engineer's machine had the
intermediate cached, and called a correct full-chain server "leaf only".
"""

import contextlib
import io
import unittest

from fixtures.pki import HOSTNAME, get_pki, openssl_available
from fixtures.scan import trust_env
from fixtures.tls_server import TLSServer

from ssl_doctor import cli

# (server mode, engineer trust store, expected top cause summary fragment or None)
SCENARIOS = [
    ("leaf-only", ("root",), "does not send the full chain"),
    ("leaf-only", ("root", "intermediate"), "does not send the full chain"),
    ("full-chain", ("root",), None),
    ("wrong-chain", ("root",), "wrong or misordered certificate chain"),
]


def run_scan(mode, trust):
    app = cli.SSLDoctorCLI()
    with TLSServer(get_pki(), mode) as srv, trust_env(trust), \
            contextlib.redirect_stdout(io.StringIO()):
        app.execute(f"/scan {srv.host}:{srv.port} --sni {HOSTNAME} --client-only")
    return app


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class ScanVerdictTable(unittest.TestCase):

    def test_verdicts(self):
        for mode, trust, expected in SCENARIOS:
            with self.subTest(mode=mode, trust=trust):
                d = run_scan(mode, trust)._diagnosis
                self.assertIsNotNone(d, "/scan produced no diagnosis")
                chain_causes = [c for c in d.causes if "chain" in c.summary]
                client_causes = [c for c in d.causes if c.origin == "client"]
                self.assertEqual(client_causes, [], "client blamed")
                if expected is None:
                    self.assertEqual(chain_causes, [], "false chain alarm")
                    self.assertNotEqual(d.overall, "FAIL")
                else:
                    self.assertEqual(d.overall, "FAIL")
                    self.assertEqual(d.causes[0].origin, "server")
                    self.assertIn(expected, d.causes[0].summary)


if __name__ == "__main__":
    unittest.main()
