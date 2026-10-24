"""Tests for the CLI typewriter output effect."""

import contextlib
import io
import time
import unittest

from ssl_doctor import cli


class TypewriterTests(unittest.TestCase):
    def test_default_state(self):
        app = cli.SSLDoctorCLI()
        self.assertFalse(app._typewriter_enabled)
        self.assertEqual(app._typewriter_cps, 40.0)

    def test_toggle_on_off(self):
        app = cli.SSLDoctorCLI()
        # force tty-like by monkeypatching isatty on stdout
        fake = io.StringIO()
        fake.isatty = lambda: True  # type: ignore[attr-defined]
        old = __import__("sys").stdout
        __import__("sys").stdout = fake
        try:
            app.execute("/typewriter on")
            self.assertTrue(app._typewriter_enabled)
            app.execute("/typewriter off")
            self.assertFalse(app._typewriter_enabled)
        finally:
            __import__("sys").stdout = old

    def test_speed_set(self):
        app = cli.SSLDoctorCLI()
        app.execute("/typewriter speed 80")
        self.assertEqual(app._typewriter_cps, 80.0)

    def test_invalid_arg_no_change(self):
        app = cli.SSLDoctorCLI()
        app.execute("/typewriter frobnicate")
        self.assertFalse(app._typewriter_enabled)

    def test_non_tty_auto_disable(self):
        app = cli.SSLDoctorCLI()
        app._typewriter_enabled = True
        # stdout is StringIO (not tty) in tests
        self.assertFalse(app._typewriter_active)

    def test_byte_identical_output(self):
        app_off = cli.SSLDoctorCLI()
        app_on = cli.SSLDoctorCLI()
        fake_on = io.StringIO()
        fake_on.isatty = lambda: True  # type: ignore[attr-defined]
        old = __import__("sys").stdout
        __import__("sys").stdout = fake_on
        app_on._typewriter_enabled = True
        app_on._typewriter_cps = 100000.0
        buf_on = io.StringIO()
        # capture
        __import__("sys").stdout = buf_on
        buf_on.isatty = lambda: True  # type: ignore[attr-defined]
        try:
            with contextlib.redirect_stdout(buf_on):
                app_on.out("hello")
        finally:
            __import__("sys").stdout = old
        buf_off = io.StringIO()
        with contextlib.redirect_stdout(buf_off):
            app_off.out("hello")
        self.assertEqual(buf_on.getvalue(), buf_off.getvalue())


if __name__ == "__main__":
    unittest.main()
