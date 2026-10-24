"""`/copy`, `/copy all` and per-command response recording.

The clipboard itself is replaced by a recorder; the clipboard routes are
covered in tests/test_clipboard.py.
"""

from __future__ import annotations

import contextlib
import io
import unittest
from unittest import mock

from ssl_doctor import __version__, cli, clipboard, tui

SECRET = "hunter2-Sup3r!"


class Copied:
    """Stands in for clipboard.copy and remembers what it was given."""

    def __init__(self):
        self.texts = []

    def __call__(self, text, **kwargs):
        self.texts.append(text)
        return clipboard.CopyResult(lines=text.count("\n") + 1, chars=len(text),
                                    routes=["xclip"])


class SecretCLI(cli.SSLDoctorCLI):
    """A command that asks for a password the way /server connect does."""

    def cmd_secret(self, args):
        import getpass
        if self._tui is not None:
            self._tui.read_secret("SSH password (hidden)")
        else:
            getpass.getpass("SSH password (hidden): ")
        self.out("password accepted")


class Base(unittest.TestCase):

    def setUp(self):
        original = cli._MODE
        self.addCleanup(cli.set_color_mode, original)
        cli.set_color_mode(cli.ColorMode.TRUECOLOR)   # recording must still be colourless
        self.copied = Copied()
        patcher = mock.patch.object(clipboard, "copy", self.copied)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.out = io.StringIO()

    def run_lines(self, app, *lines):
        with contextlib.redirect_stdout(self.out):
            for line in lines:
                app.execute(line)
        return self.out.getvalue()


class LineRepl(Base):

    def test_each_command_records_its_own_response(self):
        app = cli.SSLDoctorCLI()
        self.run_lines(app, "/version")
        self.assertEqual(app._last_response, f"SSL Doctor v{__version__}")
        self.run_lines(app, "/timeout")
        self.assertTrue(app._last_response.startswith("network timeout: 8.0s"))
        self.assertNotIn("\x1b", app._last_response)

    def test_copy_takes_the_previous_response_and_repeats_it(self):
        app = cli.SSLDoctorCLI()
        out = self.run_lines(app, "/version", "/copy", "/copy")
        self.assertEqual(self.copied.texts, [f"SSL Doctor v{__version__}"] * 2)
        self.assertIn(f"copied 1 line · {len(f'SSL Doctor v{__version__}')} chars · xclip", out)
        self.assertEqual(app._last_response, f"SSL Doctor v{__version__}")  # /copy is not a response

    def test_copy_all_takes_every_command_and_its_output(self):
        app = cli.SSLDoctorCLI()
        self.run_lines(app, "/version", "/timeout", "/copy all")
        text = self.copied.texts[-1]
        self.assertTrue(text.startswith(f"ssl-doctor> /version\nSSL Doctor v{__version__}\n"
                                        "ssl-doctor> /timeout\nnetwork timeout"), text)

    def test_nothing_to_copy_in_a_fresh_session(self):
        out = self.run_lines(cli.SSLDoctorCLI(), "/copy")
        self.assertIn("nothing to copy yet - run a command first", out)
        self.assertEqual(self.copied.texts, [])

    def test_an_empty_previous_response_is_not_copied(self):
        class Quiet(cli.SSLDoctorCLI):
            def cmd_quiet(self, args):
                pass
        out = self.run_lines(Quiet(), "/quiet", "/copy")
        self.assertIn("nothing to copy - the previous response is empty", out)
        self.assertEqual(self.copied.texts, [])

    def test_bad_arguments(self):
        out = self.run_lines(cli.SSLDoctorCLI(), "/version", "/copy everything")
        self.assertIn("usage: /copy [all]", out)
        self.assertEqual(self.copied.texts, [])

    def test_a_password_read_with_getpass_is_never_recorded(self):
        app = SecretCLI()
        with mock.patch("getpass.getpass", return_value=SECRET):
            self.run_lines(app, "/secret", "/copy all")
        self.assertNotIn(SECRET, self.copied.texts[-1])
        self.assertIn("password accepted", self.copied.texts[-1])

    def test_errors_are_part_of_the_response(self):
        app = cli.SSLDoctorCLI()
        self.run_lines(app, "/timeout abc")
        self.assertEqual(app._last_response, "error: usage: /timeout <net_s> [cmd_s]")


class ScriptedKeys:
    def __init__(self, keys):
        self.keys = list(keys)

    def read_key(self):
        return self.keys.pop(0) if self.keys else "ctrl-d"


class FullScreenShell(Base):

    def shell(self, app, keys=()):
        session = tui.TuiSession(renderer=lambda s: ([], (1, 1)), stream=io.StringIO(),
                                 keys=ScriptedKeys(keys))
        session.screen.active = False
        app._tui = session
        self.addCleanup(setattr, app, "_tui", None)
        # _tui_run sizes result frames for the shell; _repl_tui resets that on
        # exit, so a test driving _tui_run directly must too
        self.addCleanup(cli.set_capture_width, 0)
        return session

    def test_copy_in_the_shell_takes_the_previous_response(self):
        app = cli.SSLDoctorCLI()
        session = self.shell(app)
        app._tui_run(session, "/version")
        app._tui_run(session, "/copy")
        self.assertEqual(self.copied.texts, [f"SSL Doctor v{__version__}"])
        self.assertTrue(any("copied 1 line" in line for line in session.transcript.lines))

    def test_copy_all_is_the_transcript_as_shown(self):
        app = cli.SSLDoctorCLI()
        session = self.shell(app)
        session.transcript.append("Welcome.")
        app._tui_run(session, "/version")
        app._tui_run(session, "/copy all")
        text = self.copied.texts[-1]
        self.assertTrue(text.startswith(f"Welcome.\nssl-doctor> /version\nSSL Doctor v{__version__}"))

    def test_masked_input_never_reaches_copy_all(self):
        app = SecretCLI()
        session = self.shell(app, keys=list(SECRET) + ["enter"])
        app._tui_run(session, "/secret")
        app._tui_run(session, "/copy all")
        self.assertNotIn(SECRET, self.copied.texts[-1])
        self.assertIn("password accepted", self.copied.texts[-1])


if __name__ == "__main__":
    unittest.main()
