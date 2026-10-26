"""Integration gate 9.3: `/scan --with-server` end to end, through `cli.main`.

The endpoint serves an expired intermediate.  The server's nginx uses that
chain, an encrypted key with an existing ssl_password_file, and a certificate
file newer than its running workers.  The diagnosis must name the expired
intermediate and the missing reload, name the encrypted key (startup works, so
it is not a defect), and the batch exit code must be 1.
"""

import contextlib
import io
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from fixtures.fake_server import FakeSession
from fixtures.nginx_host import worker_line
from fixtures.pki import HOSTNAME, get_pki, openssl_available
from fixtures.scan import trust_env
from fixtures.tls_server import TLSServer

from ssl_doctor import cli
from ssl_doctor import findings as F


class RunningNginx(FakeSession):
    """FakeSession whose nginx (on `port`) has young workers and real mtimes."""

    port = 443

    def nginx_probe(self):
        host = super().nginx_probe()
        host.now = int(time.time())
        host.ps += "\n" + worker_line(701, 700, etimes=600)
        host.sockets = (f"LISTEN 0 511 0.0.0.0:{self.port} 0.0.0.0:* "
                        'users:(("nginx",pid=700,fd=6))')
        host.mtimes = lambda paths: {p: int(os.stat(p).st_mtime) for p in paths
                                     if os.path.exists(p)}
        return host


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class ScanWithServer(unittest.TestCase):

    def setUp(self):
        p = get_pki()
        self.dir = tempfile.mkdtemp(prefix="ssldoctor-e2e-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.cert = os.path.join(self.dir, "chain.pem")
        shutil.copy(p.expired_intermediate_chain, self.cert)      # mtime: now (> workers)
        self.key = os.path.join(self.dir, "enc.key")
        subprocess.run(["openssl", "pkcs8", "-topk8", "-v2", "aes256", "-in", p.leaf_key,
                        "-passout", "pass:e2e-secret", "-out", self.key],
                       check=True, capture_output=True)
        self.pass_file = os.path.join(self.dir, "pass.txt")
        with open(self.pass_file, "w") as fh:
            fh.write("e2e-secret\n")

    def test_scan_names_every_problem_and_exits_one(self):
        seen = {}
        real_diagnose = cli.SSLDoctorCLI.cmd_diagnose

        def capture(app, args):
            real_diagnose(app, args)
            seen["diagnosis"], seen["items"] = app._diagnosis, app.store.all()

        def connect(app, *a, **kw):
            # the server-side nginx listens where the live endpoint does
            config = (f"http {{ server {{ listen {srv.port} ssl; server_name {HOSTNAME}; "
                      f"ssl_certificate {self.cert}; ssl_certificate_key {self.key}; "
                      f"ssl_password_file {self.pass_file}; }} }}")
            app.server = RunningNginx(config, tls_host=HOSTNAME, tls_port=srv.port)
            app.server.port = srv.port
            return True

        with TLSServer(get_pki(), "expired-intermediate") as srv, trust_env(("root",)), \
                contextlib.redirect_stdout(io.StringIO()), \
                mock.patch.object(cli.SSLDoctorCLI, "_server_connect", connect), \
                mock.patch.object(cli.SSLDoctorCLI, "cmd_diagnose", capture):
            status = cli.main(["--no-tui", "-c",
                               f"/scan {srv.host}:{srv.port} --sni {HOSTNAME} --with-server"])
        d, items = seen["diagnosis"], {f.check: f for f in seen["items"]}
        summaries = [c.summary for c in d.causes]

        self.assertTrue(any("outside its validity period" in s for s in summaries),
                        summaries)
        self.assertTrue(any("not yet served because the service was not reloaded" in s
                            or "may not run its current certificate" in s
                            for s in summaries), summaries)
        self.assertEqual(items["srv.reload"].status, F.WARNING)
        self.assertEqual(items["srv.keystartup"].status, F.PASS)
        self.assertTrue(any("passphrase-encrypted" in n for n in d.notes), d.notes)
        self.assertEqual(d.overall, F.FAIL)
        self.assertEqual(status, 1)


if __name__ == "__main__":
    unittest.main()
