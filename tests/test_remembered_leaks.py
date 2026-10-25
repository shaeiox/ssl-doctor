"""A password from the vault never leaks: transcript, /copy, reports, argv.

Covers openspec change `remembered-servers`, capability `credential-vault`,
"A secret never crosses a command line, a file or output".
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from ssl_doctor import findings as F, server

from test_remembered_connect import FakeSession, Harness

SECRET = "Vault-Secret-9f3k!"


class SavedPasswordNeverLeaks(Harness):

    def setUp(self):
        super().setUp()
        FakeSession.accepted = SECRET
        profile = self.remember()
        self.vault.put(f"ssl-doctor:ssh:{profile.username}@{profile.host}:{profile.port}",
                       SECRET, profile.hostkey_fingerprints)
        self.copied = []
        self.app.copy_text = lambda text: (self.copied.append(text), "copied")[1]

    def test_transcript_and_copy_all(self):
        output = self.run_cli("/server connect files")
        output += self.run_cli("/servers")
        output += self.run_cli("/copy all")
        self.assertTrue(self.app.server.connected)
        self.assertNotIn(SECRET, output)
        self.assertTrue(self.copied)
        self.assertFalse(any(SECRET in text for text in self.copied))

    def test_reports_redact_it_even_when_a_server_echoes_it(self):
        self.run_cli("/server connect files")
        self.app.store.add(F.Finding("srv.os", "Server OS and identity", F.PASS,
                                     F.SCOPE_SERVER, [f"echoed: {SECRET}"]))
        self.app.remote_facts["host"] = "files.example.com"      # a completed scan
        base = os.path.join(self.dir, "report")
        self.run_cli(f"/report both {base}")
        self.run_cli(f"/report agent {os.path.join(self.dir, 'agent')}")
        written = []
        for root, _, names in os.walk(self.dir):
            for name in names:
                if name.endswith((".html", ".json", ".md")) and name != "profiles.json":
                    written.append(os.path.join(root, name))
        self.assertGreaterEqual(len(written), 4)
        for path in written:
            with open(path, encoding="utf-8") as fh:
                self.assertNotIn(SECRET, fh.read(), path)

    def test_the_profile_file_never_holds_it(self):
        self.run_cli("/server connect files")
        with open(self.store.path, encoding="utf-8") as fh:
            self.assertNotIn(SECRET, fh.read())


class RealSessionArgv(unittest.TestCase):
    """The password reaches ssh through the askpass environment, never argv."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)

    def test_ssh_argv_never_contains_the_password(self):
        calls = []

        def fake_run(argv, **kwargs):
            calls.append((argv, kwargs.get("env") or {}))
            return subprocess.CompletedProcess(argv, 0, "", "")

        cfg = server.SSHConfig(host="files.example.com", username="eleven", auth="password")
        session = server.ServerSession(cfg, password=SECRET)
        with mock.patch.object(server, "STATE_DIR", self.dir), \
                mock.patch.object(server.subprocess, "run", fake_run):
            session.run("true")
        session.disconnect()
        argv, env = calls[0]
        self.assertFalse(any(SECRET in arg for arg in argv))
        self.assertEqual(env.get("SSL_DOCTOR_PW"), SECRET)
