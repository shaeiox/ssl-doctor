"""Integration gate 9.2: no private-key line, passphrase or SSH password reaches
any export path - terminal output, JSON, HTML, agent report, agent upload.

One session touches every secret the checks can meet: an encrypted key with an
ssl_password_file, a certificate file that also holds its private key, and an
SSH password.
"""

import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from fixtures.fake_server import FakeSession
from fixtures.pki import get_pki, openssl_available
from fixtures.scan import cli_session

from ssl_doctor import agent, netchecks, server

PASSPHRASE = "gate-passphrase-7f3a"
SSH_PASSWORD = "gate-ssh-Pa55word!"


def secret_lines(*paths):
    out = []
    for path in paths:
        with open(path) as fh:
            out += [ln.strip() for ln in fh.read().splitlines()
                    if ln.strip() and "-----" not in ln and ":" not in ln]
    return out


@unittest.skipUnless(openssl_available(), "openssl binary not available")
class NoSecretInAnyExport(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        p = get_pki()
        cls.dir = tempfile.mkdtemp(prefix="ssldoctor-gate-")
        cls.enc_key = os.path.join(cls.dir, "enc.key")
        subprocess.run(["openssl", "pkcs8", "-topk8", "-v2", "aes256", "-in", p.leaf_key,
                        "-passout", f"pass:{PASSPHRASE}", "-out", cls.enc_key],
                       check=True, capture_output=True)
        cls.pass_file = os.path.join(cls.dir, "pass.txt")
        with open(cls.pass_file, "w") as fh:
            fh.write(PASSPHRASE + "\n")
        cls.mixed = p.sample("mixed.pem")            # leaf certificate + its key
        cls.config = (f"http {{ server {{ listen 443 ssl; server_name shop.test; "
                      f"ssl_certificate {cls.mixed}; ssl_certificate_key {cls.enc_key}; "
                      f"ssl_password_file {cls.pass_file}; }} }}")
        cls.secrets = (secret_lines(p.leaf_key, cls.enc_key)
                       + [PASSPHRASE, SSH_PASSWORD])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, True)

    def assert_clean(self, label, text):
        for secret in self.secrets:
            self.assertNotIn(secret, text, f"{label} leaks secret material")

    def session(self):
        app = cli_session("full-chain")
        app.server = FakeSession(self.config)
        app.server.cfg.auth = "password"
        app.server._password = SSH_PASSWORD
        return app

    def test_every_cli_export(self):
        app = self.session()
        out_dir = tempfile.mkdtemp(prefix="ssldoctor-exports-", dir=self.dir)
        terminal = io.StringIO()
        with contextlib.redirect_stdout(terminal):
            app.execute("/server nginx shop.test")
            app.execute("/server services")
            app.execute(f"/cert inspect {self.mixed} shop.test")
            app.execute(f"/cert match {self.mixed} {self.enc_key}")
            app.execute("/diagnose")
            app.execute(f"/report both {out_dir}/r")
            app.execute(f"/report agent {out_dir}/agent")
            app.execute("/findings")
        self.assert_clean("terminal output", terminal.getvalue())
        written = []
        for root, _dirs, files in os.walk(out_dir):
            for name in files:
                path = os.path.join(root, name)
                with open(path, encoding="utf-8", errors="replace") as fh:
                    self.assert_clean(name, fh.read())
                written.append(name)
        for kind in (".json", ".html", ".md"):
            self.assertTrue(any(n.endswith(kind) for n in written), (kind, written))
        checks = {f.check for f in app.store.all()}
        self.assertIn("srv.keystartup", checks)          # the encrypted key was met
        self.assertIn("cert.keymatch", checks)

    def test_server_agent_upload(self):
        config = self.config
        with mock.patch.object(server.LocalSession, "nginx_scan",
                               lambda self, domain, port=443, **kw:
                               FakeSession(config).nginx_scan(domain)), \
                mock.patch.object(netchecks, "check_tls_basic", return_value=(None, {})):
            doc = agent.run_server_checks("127.0.0.1", 443, "shop.test")
        self.assert_clean("agent upload", json.dumps(doc))


if __name__ == "__main__":
    unittest.main()
