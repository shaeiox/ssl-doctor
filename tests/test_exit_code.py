"""diagnosis-correlation: the batch exit code follows the overall verdict.

R2 end to end: `ssl-doctor -c "/scan … --client-only"` against a server that
sends an expired intermediate used to exit 0 with an overall PASS.
"""

import contextlib
import io
import unittest
from unittest import mock

from fixtures.pki import HOSTNAME, get_pki, openssl_available
from fixtures.scan import trust_env
from fixtures.tls_server import TLSServer

from ssl_doctor import cli, local, findings as F


def batch_scan(mode, patches=()):
    """Exit status and diagnosis of a batch `/scan` against a fixture server."""
    seen = {}
    real_diagnose = cli.SSLDoctorCLI.cmd_diagnose

    def capture(self, args):
        real_diagnose(self, args)
        seen["diagnosis"] = self._diagnosis

    with TLSServer(get_pki(), mode) as srv, trust_env(("root",)), \
            contextlib.redirect_stdout(io.StringIO()), \
            mock.patch.object(cli.SSLDoctorCLI, "cmd_diagnose", capture), \
            contextlib.ExitStack() as stack:
        for patch in patches:
            stack.enter_context(patch)
        status = cli.main(["--no-tui", "-c",
                           f"/scan {srv.host}:{srv.port} --sni {HOSTNAME} --client-only"])
    return status, seen.get("diagnosis")


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class BatchExitCode(unittest.TestCase):

    def test_regression_r2_expired_intermediate_exit(self):
        status, d = batch_scan("expired-intermediate")
        self.assertEqual(d.overall, F.FAIL)
        # P0 kept it in `unexplained`; since P3 chain.validity names the cause
        self.assertTrue(any("outside its validity period" in c.summary
                            and c.certainty == "confirmed" for c in d.causes),
                        [c.summary for c in d.causes])
        self.assertEqual(status, 1)

    def test_full_valid_chain_exits_zero(self):
        status, d = batch_scan("full-chain")
        self.assertNotEqual(d.overall, F.FAIL)
        self.assertEqual(status, 0)

    def test_leaf_only_server_still_exits_one(self):
        status, d = batch_scan("leaf-only")
        self.assertEqual(d.overall, F.FAIL)
        self.assertEqual(status, 1)

    def test_client_machine_failure_alone_exits_zero(self):
        skew = F.Finding("local.clockskew", "System clock vs server clock", F.FAIL,
                         F.SCOPE_LOCAL, ["this machine is 400s ahead of the remote server's clock"])
        status, d = batch_scan("full-chain", patches=[mock.patch.object(
            local, "check_os_and_clock", return_value=[skew])])
        self.assertEqual(d.overall, F.WARNING)
        self.assertIn("local.clockskew", [u.check for u in d.unexplained])
        self.assertEqual(status, 0)


if __name__ == "__main__":
    unittest.main()
