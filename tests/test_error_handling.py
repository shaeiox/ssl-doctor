"""Empty passwords are refused everywhere; failures become clear messages.

Regression cover for an error-handling audit: an empty (or whitespace-only)
password could still reach the vault or the askpass helper, Ctrl-C at the
password prompt was reported as "empty password", and several file and
subprocess failures escaped as raw Python exceptions (missing `ssh-keygen` or
`openssl`, an unwritable state directory, an undecodable profiles file, a
missing agent state file).
"""

from __future__ import annotations

import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from ssl_doctor import agent, certs, cli, profiles, server, vault

from test_remembered_connect import FakeSession, Harness


class PasswordValidation(unittest.TestCase):

    def test_empty_and_blank_passwords_are_refused(self):
        for value in ("", " ", "\t", "   \t "):
            with self.subTest(value=repr(value)):
                self.assertIn("empty", cli.password_problem(value))

    def test_line_breaks_and_nul_are_refused(self):
        for value in ("pass\nword", "pass\rword", "pass\0word"):
            with self.subTest(value=repr(value)):
                self.assertIsNotNone(cli.password_problem(value))

    def test_a_real_password_is_accepted(self):
        for value in ("right", " leading space", "p@ss w%rd&|^!\"é"):
            with self.subTest(value=value):
                self.assertIsNone(cli.password_problem(value))


class PasswordPrompt(Harness):

    def test_an_empty_password_is_asked_again(self):
        self.answers = self.NEW_SERVER + ["n"]
        self.passwords = ["", "   ", "right"]
        output = self.run_cli("/server connect")
        self.assertEqual(self.asked.count("PASSWORD"), 3)
        self.assertIn("cannot be empty", output)
        self.assertEqual(FakeSession.instances[-1].password, "right")

    def test_three_empty_answers_cancel_without_connecting(self):
        self.answers = list(self.NEW_SERVER)
        self.passwords = ["", "", ""]
        output = self.run_cli("/server connect")
        self.assertEqual(FakeSession.instances, [])
        self.assertIn("no password given", output)

    def test_cancelling_the_prompt_is_not_called_an_empty_password(self):
        self.answers = list(self.NEW_SERVER)
        self.app._tui = mock.Mock()
        self.app._tui.read_secret.return_value = None          # Ctrl-C / Ctrl-D
        self.app._tui.ask.side_effect = self._prompt
        self.app.prompt = self._prompt
        output = self.run_cli("/server connect")
        self.assertIn("cancelled", output)
        self.assertNotIn("empty", output)
        self.assertEqual(FakeSession.instances, [])


class SessionRefusesEmptyPassword(unittest.TestCase):

    def test_connect_never_runs_ssh_without_a_password(self):
        cfg = server.SSHConfig(host="files.example.com", username="eleven", auth="password")
        session = server.ServerSession(cfg, password="  ")
        with mock.patch.object(server, "host_key_status",
                               side_effect=AssertionError("ssh ran")), \
                mock.patch.object(server.subprocess, "run",
                                  side_effect=AssertionError("ssh ran")):
            [finding] = session.connect()
        self.assertEqual(finding.check, "ssh.auth")
        self.assertEqual(finding.status, "FAIL")
        self.assertIn("empty", finding.evidence[0])
        self.assertFalse(session.connected)


class AskpassRefusesEmptyPassword(unittest.TestCase):

    def test_helper_mode_fails_instead_of_sending_nothing(self):
        out = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        env = {server.ASKPASS_MODE_ENV: "1", "SSL_DOCTOR_PW": ""}
        with mock.patch.dict(os.environ, env), mock.patch.object(server.sys, "stdout", out):
            self.assertEqual(server.askpass_reply(), 1)
        out.flush()
        self.assertEqual(out.buffer.getvalue(), b"")

    def test_helper_mode_is_off_by_default(self):
        with mock.patch.dict(os.environ, {}):
            os.environ.pop(server.ASKPASS_MODE_ENV, None)
            self.assertIsNone(server.askpass_reply())

    def test_the_written_helpers_exit_non_zero_on_an_empty_password(self):
        state = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, state, True)
        cfg = server.SSHConfig(host="h", username="u", auth="password")
        session = server.ServerSession(cfg, password="right")
        with mock.patch.object(server, "STATE_DIR", state):
            cmd = session._write_askpass(windows=True, frozen=False)
            line = [ln for ln in open(cmd).read().splitlines() if ln.startswith('@"')][0]
            import shlex
            argv = shlex.split(line[1:])
            empty = subprocess.run(argv, capture_output=True, timeout=20,
                                   env=dict(os.environ, SSL_DOCTOR_PW=""))
            self.assertNotEqual(empty.returncode, 0)
            self.assertEqual(empty.stdout, b"")
            if os.name != "nt":
                sh = session._write_askpass(windows=False, frozen=False)
                result = subprocess.run(["/bin/sh", sh], capture_output=True, timeout=20,
                                        env=dict(os.environ, SSL_DOCTOR_PW=""))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")


class VaultRefusesEmptyPassword(unittest.TestCase):

    def test_no_backend_saves_an_empty_password(self):
        for backend in (vault.MemoryVault(),):
            for value in ("", "   "):
                with self.subTest(backend=backend.name, value=repr(value)):
                    with self.assertRaises(vault.VaultError):
                        backend.put("t", value, ["SHA256:" + "A" * 43])

    def test_secret_service_refuses_before_running_anything(self):
        backend = vault.SecretServiceVault(run=mock.Mock(side_effect=AssertionError("ran")))
        with mock.patch.object(vault.shutil, "which", return_value="/usr/bin/secret-tool"):
            with self.assertRaises(vault.VaultError) as caught:
                backend.put("t", "", ["SHA256:" + "A" * 43])
        self.assertIn("empty", str(caught.exception))

    def test_windows_refuses_before_calling_the_api(self):
        backend = vault.WindowsCredentialVault(advapi32=mock.Mock(
            CredWriteW=mock.Mock(side_effect=AssertionError("called"))))
        with self.assertRaises(vault.VaultError):
            backend.put("t", " ", ["SHA256:" + "A" * 43])

    def test_an_empty_saved_value_is_treated_as_missing(self):
        memory = vault.MemoryVault()
        memory.items["t"] = ("", ("SHA256:" + "A" * 43,))
        self.assertIsNone(memory.get("t", ["SHA256:" + "A" * 43]))


class HostKeyToolFailures(unittest.TestCase):

    def setUp(self):
        self.state = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.state, True)
        patch = mock.patch.object(server, "STATE_DIR", self.state)
        patch.start()
        self.addCleanup(patch.stop)

    def test_missing_ssh_keygen_is_reported_not_raised(self):
        scan = (["files.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"], "")
        with mock.patch.object(server, "_scan_host_keys", return_value=scan), \
                mock.patch.object(server.subprocess, "run",
                                  side_effect=FileNotFoundError("ssh-keygen")):
            info = server.host_key_status("files.example.com", 22, 3)
        self.assertEqual(info.status, "unreachable")
        self.assertIn("ssh-keygen", info.detail)

    def test_an_unwritable_state_directory_is_reported(self):
        with mock.patch.object(server, "_ensure_state_dir",
                               side_effect=PermissionError(13, "Permission denied",
                                                           self.state)):
            info = server.host_key_status("files.example.com", 22, 3)
            ok, message = server.store_host_key("files.example.com", 22, 3)
        self.assertEqual(info.status, "unreachable")
        self.assertIn("Permission denied", info.detail)
        self.assertFalse(ok)
        self.assertIn("Permission denied", message)

    def test_an_unwritable_askpass_helper_is_a_fatal_note(self):
        cfg = server.SSHConfig(host="h", username="u", auth="password")
        session = server.ServerSession(cfg, password="right")
        with mock.patch.object(session, "_write_askpass",
                               side_effect=PermissionError(13, "Permission denied")):
            rc, out, err, fatal = session.run("true")
        self.assertNotEqual(rc, 0)
        self.assertIn("askpass", fatal)


class OpensslFailures(unittest.TestCase):

    # the first openssl call (x509 -pubkey) succeeds; the second one fails
    PUBKEY = subprocess.CompletedProcess([], 0, b"-----BEGIN PUBLIC KEY-----\n", b"")

    def test_a_missing_openssl_is_a_finding_not_a_crash(self):
        with mock.patch.object(certs.subprocess, "run",
                               side_effect=[self.PUBKEY, FileNotFoundError("openssl")]):
            fp, err = certs._public_key_sha256_from_pem_bytes(b"-----BEGIN CERTIFICATE-----")
        self.assertIsNone(fp)
        self.assertIn("openssl", err)

    def test_a_hanging_openssl_is_a_finding_not_a_crash(self):
        with mock.patch.object(certs.subprocess, "run",
                               side_effect=[self.PUBKEY,
                                            subprocess.TimeoutExpired("openssl", 10)]):
            fp, err = certs._public_key_sha256_from_pem_bytes(b"x")
        self.assertIsNone(fp)
        self.assertIn("timed out", err)


class ProfileFailures(Harness):

    def test_an_undecodable_profiles_file_is_ignored(self):
        with open(self.store.path, "wb") as fh:
            fh.write(b"\xff\xfe not utf-8 \x80")
        warnings = []
        store = profiles.ProfileStore(self.store.path, warn=warnings.append).load()
        self.assertEqual(store.all(), [])
        self.assertTrue(store.read_only)
        self.assertTrue(warnings)

    def test_a_failed_profile_save_does_not_break_the_connection(self):
        self.answers = self.NEW_SERVER + ["p"]
        self.passwords = ["right"]
        with mock.patch.object(self.store, "save",
                               side_effect=PermissionError(13, "Permission denied",
                                                           self.store.path)):
            output = self.run_cli("/server connect")
        self.assertTrue(self.app.server.connected)
        self.assertIn("could not save remembered servers", output)
        self.assertNotIn("PermissionError", output)

    def test_an_unusable_state_directory_still_allows_connecting(self):
        self.app._profile_store = None
        # never the real ~/.ssl-doctor: a leftover profile there changed this test
        unusable = os.path.join(self.dir, "no-such-state-dir")
        with mock.patch.object(server, "STATE_DIR", unusable), \
                mock.patch.object(server, "_ensure_state_dir",
                                  side_effect=PermissionError(13, "Permission denied")):
            self.answers = self.NEW_SERVER + ["p"]
            self.passwords = ["right"]
            output = self.run_cli("/server connect")
        self.assertTrue(self.app.server.connected)
        self.assertIn("remembered servers are unavailable", output)


class ReportFailures(Harness):

    def test_an_unwritable_report_path_is_a_clear_error(self):
        self.app.store.add(cli.F.Finding("x", "x", "PASS", "local", ["e"]))
        target = os.path.join(self.dir, "missing-dir", "report")
        output = self.run_cli(f"/report json {target}")
        self.assertIn("could not write the report", output)
        self.assertNotIn("FileNotFoundError", output)


class UnexpectedErrors(Harness):

    def test_a_bug_in_a_command_is_reported_without_ending_the_session(self):
        with mock.patch.object(cli.SSLDoctorCLI, "cmd_version",
                               side_effect=ZeroDivisionError("division by zero")):
            output = self.run_cli("/version")
        self.assertIn("internal error in /version", output)
        self.assertIn("ZeroDivisionError", output)
        self.assertTrue(self.app._running)

    def test_a_file_error_in_a_command_is_phrased_for_people(self):
        with mock.patch.object(cli.SSLDoctorCLI, "cmd_version",
                               side_effect=PermissionError(13, "Permission denied", "/x/y")):
            output = self.run_cli("/version")
        self.assertIn("/x/y: Permission denied", output)
        self.assertNotIn("internal error", output)


class AgentStateFailures(unittest.TestCase):

    def test_a_missing_state_file_is_an_agent_error(self):
        missing = os.path.join(tempfile.gettempdir(), "ssl-doctor-missing-state.json")
        with self.assertRaises(agent.AgentError) as caught:
            agent.load_state(missing)
        self.assertIn("enroll", str(caught.exception))

    def test_a_corrupt_state_file_is_an_agent_error(self):
        fd, path = tempfile.mkstemp()
        self.addCleanup(os.unlink, path)
        with os.fdopen(fd, "w") as fh:
            fh.write("{oops")
        with self.assertRaises(agent.AgentError):
            agent.load_state(path)

    def test_cli_main_turns_it_into_exit_status_1(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(["agent", "run", "--once", "--state",
                             os.path.join(tempfile.gettempdir(), "ssl-doctor-nope.json")])
        self.assertEqual(code, 1)
        self.assertIn("error:", out.getvalue())


if __name__ == "__main__":
    unittest.main()
