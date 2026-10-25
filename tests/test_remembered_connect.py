"""The connect pipeline with remembered servers: order, binding, consent.

Covers openspec change `remembered-servers`: the password is asked (or read
from the vault) only after the host key is trusted; a saved password is
released only for the fingerprint it was saved with; a rejected one is deleted;
remembering is offered only after success and never in batch mode.
"""

from __future__ import annotations

import contextlib
import io
import os
import shutil
import tempfile
import unittest
from unittest import mock

from ssl_doctor import cli, findings as F, profiles, server, vault

FP_A = "SHA256:" + "A" * 43
FP_B = "SHA256:" + "B" * 43


def keyinfo(status="trusted", fp=FP_A):
    return server.HostKeyInfo(status, [f"256 {fp} files.example.com (ED25519)"],
                              "" if status == "trusted" else "detail")


class FakeSession:
    """Stands in for ServerSession: accepts one password (or any key)."""

    accepted = "right"
    instances = []

    def __init__(self, cfg, password=""):
        self.cfg, self.password, self.connected = cfg, password, False
        FakeSession.instances.append(self)

    def connect(self):
        ok = self.cfg.auth == "key" or self.password == FakeSession.accepted
        self.connected = ok
        if ok:
            return [F.Finding("ssh.auth", "SSH authentication", F.PASS, F.SCOPE_SERVER,
                              ["authenticated"])]
        return [F.Finding("ssh.auth", "SSH authentication", F.FAIL, F.SCOPE_SERVER,
                          ["authentication failed: Permission denied (check username/password)"])]

    def disconnect(self):
        self.connected = False

    def known_secrets(self):
        return [self.password] if self.password else []


class Harness(unittest.TestCase):
    """A CLI whose prompts, host-key checks and SSH sessions are scripted."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.store = profiles.ProfileStore(os.path.join(self.dir, "profiles.json")).load()
        self.vault = vault.MemoryVault()
        self.app = cli.SSLDoctorCLI()
        self.app._profile_store = self.store
        self.app._secret_vault = self.vault
        self.app._interactive_session = lambda: True
        self.answers, self.asked, self.passwords = [], [], []
        self.app.prompt = self._prompt
        self.key = keyinfo()
        self.key_checks = 0
        FakeSession.instances = []
        FakeSession.accepted = "right"
        self.trusted = []
        patches = [
            mock.patch.object(cli.servermod, "ServerSession", FakeSession),
            mock.patch.object(cli.servermod, "host_key_status", self._host_key),
            mock.patch.object(cli.servermod, "store_host_key", self._store_key),
            mock.patch.object(cli.getpass, "getpass", self._getpass),
            mock.patch.dict(os.environ, {"SSL_DOCTOR_REMEMBER": ""}),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def _prompt(self, label, default=""):
        self.asked.append(label)
        if not self.answers:
            raise AssertionError(f"unexpected prompt: {label!r}")
        answer = self.answers.pop(0)
        return default if answer is None else answer

    def _getpass(self, label=""):
        self.asked.append("PASSWORD")
        if not self.passwords:
            raise AssertionError("unexpected password prompt")
        return self.passwords.pop(0)

    def _host_key(self, host, port, timeout=8.0, username=""):
        self.key_checks += 1
        return self.key

    def _store_key(self, host, port, timeout=8.0, username=""):
        self.trusted.append(host)
        return True, "host key stored"

    def run_cli(self, line):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.app.execute(line)
        return out.getvalue()

    def remember(self, saved=True, fp=FP_A, **over):
        data = dict(name="files", host="files.example.com", port=22, username="eleven",
                    auth="password", tls_host="files.example.com", password_saved=saved,
                    hostkey_fingerprints=[fp])
        data.update(over)
        profile = profiles.Profile(**data)
        self.store.save(profile)
        if saved:
            self.vault.put(vault.target_for(profile), "right", [fp])
        return profile

    # the first-connect answers, in today's order (minus the password)
    NEW_SERVER = ["files.example.com", "22", "eleven", "1", "", "443"]


class FirstConnect(Harness):

    def test_the_password_is_asked_after_the_host_key_is_trusted(self):
        self.answers = self.NEW_SERVER + ["p"]
        self.passwords = ["right"]
        self.run_cli("/server connect")
        self.assertEqual(self.asked[-2:], ["PASSWORD", self.asked[-1]])
        self.assertLess(self.asked.index("TLS target port"), self.asked.index("PASSWORD"))
        self.assertTrue(self.app.server.connected)

    def test_a_changed_key_never_asks_for_the_password(self):
        self.key = keyinfo("changed")
        self.answers = list(self.NEW_SERVER)
        self.run_cli("/server connect")
        self.assertNotIn("PASSWORD", self.asked)
        self.assertEqual(FakeSession.instances, [])

    def test_a_declined_unknown_key_never_asks_for_the_password(self):
        self.key = keyinfo("unknown")
        self.answers = self.NEW_SERVER + ["no"]
        self.run_cli("/server connect")
        self.assertNotIn("PASSWORD", self.asked)
        self.assertEqual(FakeSession.instances, [])

    def test_remember_profile_only_is_the_default(self):
        self.answers = self.NEW_SERVER + [None]          # accept the default
        self.passwords = ["right"]
        self.run_cli("/server connect")
        profile = self.store.load().get("files")
        self.assertIsNotNone(profile)
        self.assertFalse(profile.password_saved)
        self.assertEqual(self.vault.items, {})
        self.assertTrue(self.asked[-1].startswith("Remember this server?"))
        self.assertIn("[P]rofile only", self.asked[-1])

    def test_save_password_too(self):
        self.answers = self.NEW_SERVER + ["s"]
        self.passwords = ["right"]
        self.run_cli("/server connect")
        profile = self.store.load().get("files")
        self.assertTrue(profile.password_saved)
        self.assertEqual(profile.hostkey_fingerprints, [FP_A])
        self.assertEqual(self.vault.get(vault.target_for(profile), [FP_A]), "right")
        with open(self.store.path) as fh:
            self.assertNotIn("right", fh.read())

    def test_a_key_login_is_not_offered_password_saving(self):
        key_file = os.path.join(self.dir, "id_ed25519")
        open(key_file, "w").close()
        self.answers = ["files.example.com", "22", "eleven", "2", key_file, "", "443", "p"]
        self.run_cli("/server connect")
        self.assertNotIn("[S]ave password", self.asked[-1])
        self.assertEqual(self.store.load().get("files").key_path, key_file)

    def test_without_a_vault_the_reason_is_shown_and_no_password_choice(self):
        self.app._secret_vault = vault.NullVault("no Secret Service on this machine")
        self.answers = self.NEW_SERVER + ["p"]
        self.passwords = ["right"]
        output = self.run_cli("/server connect")
        self.assertNotIn("[S]ave password", self.asked[-1])
        self.assertIn("no Secret Service on this machine", output)

    def test_a_failed_connection_saves_nothing(self):
        self.answers = list(self.NEW_SERVER)
        self.passwords = ["wrong"]
        self.run_cli("/server connect")
        self.assertEqual(self.store.load().all(), [])
        self.assertFalse(any(a.startswith("Remember") for a in self.asked))

    def test_a_remembered_host_prefills_the_prompts(self):
        self.remember(saved=False, port=2222, username="deploy",
                      tls_host="www.example.com", tls_port=8443)
        self.answers = ["n", "files.example.com", None, None, None, None, None]
        self.passwords = ["right"]
        defaults = {}
        original = self._prompt

        def prompt(label, default=""):
            defaults[label] = default
            return original(label, default)
        self.app.prompt = prompt
        self.run_cli("/server connect")
        self.assertEqual(defaults["SSH port"], "2222")
        self.assertEqual(defaults["SSH username"], "deploy")
        self.assertEqual(defaults["TLS target hostname (blank = SSH host)"], "www.example.com")
        self.assertEqual(defaults["TLS target port"], "8443")
        self.assertEqual(FakeSession.instances[-1].cfg.port, 2222)


class SavedPassword(Harness):

    def test_a_saved_password_connects_without_any_prompt(self):
        self.remember()
        output = self.run_cli("/server connect files")
        self.assertEqual(self.asked, [])
        self.assertTrue(self.app.server.connected)
        self.assertIn("password from memory", output)
        self.assertNotIn("right", output)

    def test_a_changed_key_does_not_read_the_vault(self):
        self.remember()
        self.key = keyinfo("changed")
        with mock.patch.object(self.vault, "get", side_effect=AssertionError("vault read")):
            self.run_cli("/server connect files")
        self.assertEqual(FakeSession.instances, [])

    def test_a_re_trusted_key_asks_and_offers_to_re_save(self):
        self.remember(fp=FP_A)
        self.key = keyinfo(fp=FP_B)
        self.passwords = ["right"]
        self.answers = ["yes"]
        output = self.run_cli("/server connect files")
        self.assertIn("PASSWORD", self.asked)
        self.assertIn("host key", output)
        profile = self.store.load().get("files")
        self.assertEqual(profile.hostkey_fingerprints, [FP_B])
        self.assertEqual(self.vault.get(vault.target_for(profile), [FP_B]), "right")

    def test_a_profile_pointed_at_another_host_releases_nothing(self):
        self.remember()
        edited = self.store.get("files")
        edited.host = "evil.example.net"
        self.store.save(edited)
        self.key = keyinfo(fp=FP_B)
        self.passwords = ["typed"]
        FakeSession.accepted = "typed"
        self.answers = ["no"]
        self.run_cli("/server connect files")
        self.assertEqual(FakeSession.instances[-1].password, "typed")

    def test_a_rejected_saved_password_is_deleted_and_asked_once(self):
        profile = self.remember()
        FakeSession.accepted = "changed-on-server"
        self.passwords = ["changed-on-server"]
        self.answers = ["no"]                          # do not re-save
        output = self.run_cli("/server connect files")
        self.assertEqual(self.asked.count("PASSWORD"), 1)
        self.assertIsNone(self.vault.get(vault.target_for(profile), [FP_A]))
        self.assertFalse(self.store.load().get("files").password_saved)
        self.assertIn("removed", output)
        self.assertEqual([s.password for s in FakeSession.instances], ["right", "changed-on-server"])
        self.assertTrue(self.app.server.connected)

    def test_a_locked_vault_falls_back_to_the_prompt(self):
        self.remember()
        self.app._secret_vault = vault.NullVault("the keyring is locked")
        self.passwords = ["right"]
        self.run_cli("/server connect files")
        self.assertEqual(self.asked, ["PASSWORD"])
        self.assertTrue(self.app.server.connected)

    def test_last_used_is_updated(self):
        self.remember(last_used="2026-01-01T00:00:00+00:00",
                      created="2026-01-01T00:00:00+00:00")
        self.run_cli("/server connect files")
        self.assertGreater(self.store.load().get("files").last_used, "2026-01-01T00:00:00+00:00")

    def test_the_session_redacts_the_saved_password(self):
        self.remember()
        self.run_cli("/server connect files")
        self.assertEqual(self.app.server.known_secrets(), ["right"])


class Policy(Harness):

    def test_batch_mode_never_asks_to_remember_nor_reads_the_vault(self):
        self.app._secret_vault = None              # let the CLI choose
        self.app._BATCH_MODE = True
        self.remember()
        with mock.patch.object(cli.vaultmod, "open_vault",
                               wraps=cli.vaultmod.open_vault) as opened:
            self.passwords = ["right"]
            self.run_cli("/server connect files")
        self.assertEqual(opened.call_args.kwargs["enabled"], False)
        self.assertEqual(self.asked, ["PASSWORD"])

    def test_the_environment_switch_turns_remembering_off(self):
        for value in ("off", "0", "no", "false"):
            with self.subTest(value=value):
                self.assertFalse(cli.remember_enabled({"SSL_DOCTOR_REMEMBER": value},
                                                      batch=False, interactive=True))
        self.assertTrue(cli.remember_enabled({}, batch=False, interactive=True))
        self.assertFalse(cli.remember_enabled({}, batch=True, interactive=True))
        self.assertFalse(cli.remember_enabled({}, batch=False, interactive=False))
        self.assertFalse(cli.remember_enabled({}, batch=False, interactive=True,
                                              no_remember=True))

    def test_no_remember_flag_is_parsed(self):
        with mock.patch.object(cli.SSLDoctorCLI, "execute", return_value=True), \
                contextlib.redirect_stdout(io.StringIO()):
            seen = {}
            original = cli.SSLDoctorCLI.__init__

            def capture(app):
                original(app)
                seen["app"] = app
            with mock.patch.object(cli.SSLDoctorCLI, "__init__", capture):
                cli.main(["--no-remember", "-c", "/version"])
        self.assertTrue(seen["app"].no_remember)


class Fingerprints(unittest.TestCase):

    def test_sha256_tokens_are_extracted(self):
        lines = ["256 SHA256:" + "A" * 43 + " files.example.com (ED25519)",
                 "256 SHA256:" + "B" * 43 + " [files.example.com]:2222 (ECDSA)",
                 "3072 SHA256:" + "C" * 43 + " no comment (RSA)",
                 "garbage"]
        self.assertEqual(server.sha256_fingerprints(lines),
                         ["SHA256:" + c * 43 for c in "ABC"])


if __name__ == "__main__":
    unittest.main()
