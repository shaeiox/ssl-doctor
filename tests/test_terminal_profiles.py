"""Every terminal gets a shell it can scroll: full-screen with a working wheel,
or the line REPL with the terminal's own scrollback.

Regression cover for Windows scrolling:
- classic conhost (cmd, PowerShell) starts with Quick Edit on, which takes the
  mouse for selection, so no wheel event reached the full-screen shell;
- Git Bash runs Python through winpty, which turns the terminal's mouse on only
  when the console mode has ENABLE_MOUSE_INPUT and ENABLE_EXTENDED_FLAGS on
  and ENABLE_QUICK_EDIT_MODE off (winpty src/agent/ConsoleInput.cc);
- a console that cannot process VT output still got the alternate screen.
"""

from __future__ import annotations

import io
import unittest

from ssl_doctor import termcaps, tui

PROCESSED, LINE, ECHO, WINDOW, MOUSE, INSERT, QUICK_EDIT, EXTENDED, AUTOPOS, VT_INPUT = (
    0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200)
CMD_DEFAULT = 0x1F7           # conhost's default input mode: all but WINDOW and VT


def winpty_activates_mouse(mode):
    """winpty's shouldActivateTerminalMouse() in its default (auto) mouse mode."""
    return bool(mode & MOUSE) and not (mode & QUICK_EDIT) and bool(mode & EXTENDED)


class ConsoleModes(unittest.TestCase):

    def test_reading_with_mouse_turns_quick_edit_off_and_mouse_input_on(self):
        mode = tui.console_read_mode(CMD_DEFAULT, mouse=True)
        self.assertFalse(mode & QUICK_EDIT)
        self.assertTrue(mode & MOUSE and mode & EXTENDED and mode & VT_INPUT)
        self.assertFalse(mode & (PROCESSED | LINE | ECHO))
        self.assertTrue(winpty_activates_mouse(mode))

    def test_winpty_default_mode_also_gets_the_mouse(self):
        winpty_initial = EXTENDED | QUICK_EDIT | PROCESSED | LINE | ECHO | INSERT
        self.assertTrue(winpty_activates_mouse(tui.console_read_mode(winpty_initial, True)))

    def test_without_mouse_capture_the_console_keeps_its_selection(self):
        mode = tui.console_read_mode(CMD_DEFAULT, mouse=False)
        self.assertTrue(mode & QUICK_EDIT)
        self.assertFalse(mode & MOUSE)
        self.assertTrue(mode & VT_INPUT)

    def test_restoring_brings_quick_edit_back(self):
        self.assertEqual(tui.console_restore_mode(CMD_DEFAULT), CMD_DEFAULT)
        # Quick Edit can only be switched (back) on together with EXTENDED_FLAGS
        restored = tui.console_restore_mode(QUICK_EDIT | PROCESSED | LINE | ECHO)
        self.assertTrue(restored & QUICK_EDIT and restored & EXTENDED)
        self.assertEqual(tui.console_restore_mode(PROCESSED | LINE), PROCESSED | LINE)


class FakeKernel32:
    def __init__(self, mode=CMD_DEFAULT):
        self.mode, self.sets = mode, []

    def GetStdHandle(self, which):
        return 10

    def GetConsoleMode(self, handle, ref):
        ref._obj.value = self.mode
        return 1

    def SetConsoleMode(self, handle, mode):
        self.sets.append(mode)
        self.mode = mode
        return 1


class KeyReaderModes(unittest.TestCase):

    def reader(self, mouse):
        reader = tui.KeyReader(stream=io.StringIO(), mouse=mouse)
        reader._windows = True
        reader.kernel32 = FakeKernel32()
        return reader

    def test_mouse_mode_is_set_only_while_a_key_is_read(self):
        reader = self.reader(mouse=True)
        reader._windows_vt_input(True)
        during = reader.kernel32.mode
        reader._windows_vt_input(False)
        self.assertTrue(winpty_activates_mouse(during))
        self.assertEqual(reader.kernel32.mode, CMD_DEFAULT)

    def test_mouse_off_leaves_quick_edit_alone(self):
        reader = self.reader(mouse=False)
        reader._windows_vt_input(True)
        self.assertTrue(reader.kernel32.mode & QUICK_EDIT)


class SessionMouse(unittest.TestCase):

    def test_no_mouse_reporting_is_requested_when_mouse_is_off(self):
        out = io.StringIO()
        keys = tui.KeyReader(stream=io.StringIO(), mouse=False)
        keys.read_key = lambda: "ctrl-d"
        session = tui.TuiSession(renderer=lambda s: ([], (1, 1)), stream=out, keys=keys,
                                 mouse=False)
        session.screen.active = True
        session.read_line()
        self.assertNotIn("\033[?1002h", out.getvalue())

    def test_mouse_reporting_is_requested_by_default(self):
        out = io.StringIO()
        keys = tui.KeyReader(stream=io.StringIO())
        keys.read_key = lambda: "ctrl-d"
        session = tui.TuiSession(renderer=lambda s: ([], (1, 1)), stream=out, keys=keys)
        session.screen.active = True
        session.read_line()
        self.assertIn("\033[?1002h", out.getvalue())


def detect(env=None, windows=False, tty=True, keys=True, vt=True):
    return termcaps.detect(env or {}, windows=windows, stdin_tty=tty, stdout_tty=tty,
                           keys_ok=keys, vt_ok=vt)


class Profiles(unittest.TestCase):

    def test_windows_terminal(self):
        p = detect({"WT_SESSION": "x"}, windows=True)
        self.assertEqual((p.host, p.fullscreen, p.mouse), ("Windows Terminal", True, True))

    def test_classic_console(self):
        p = detect({}, windows=True)
        self.assertEqual((p.host, p.fullscreen, p.mouse),
                         ("Windows console (conhost)", True, True))

    def test_git_bash_through_winpty(self):
        p = detect({"MSYSTEM": "MINGW64", "TERM": "xterm"}, windows=True)
        self.assertEqual((p.host, p.fullscreen), ("mintty (Git Bash / MSYS2)", True))

    def test_git_bash_without_a_console_uses_the_line_repl(self):
        p = detect({"MSYSTEM": "MINGW64"}, windows=True, tty=False)
        self.assertFalse(p.fullscreen)
        self.assertIn("not a terminal", p.reason)

    def test_console_without_vt_output_uses_the_line_repl(self):
        p = detect({}, windows=True, vt=False)
        self.assertFalse(p.fullscreen)
        self.assertIn("VT", p.reason)
        self.assertIn("scrollback", p.reason)

    def test_switches(self):
        self.assertFalse(detect({"SSL_DOCTOR_TUI": "0"}).fullscreen)
        self.assertFalse(detect({"TERM": "dumb"}).fullscreen)
        self.assertFalse(detect(keys=False).fullscreen)
        p = detect({"SSL_DOCTOR_MOUSE": "off"})
        self.assertEqual((p.fullscreen, p.mouse), (True, False))

    def test_posix_terminal(self):
        p = detect({"TERM": "xterm-256color"})
        self.assertEqual((p.fullscreen, p.mouse), (True, True))

    def test_enabled_follows_the_profile(self):
        class Tty(io.StringIO):
            def isatty(self):
                return True
        self.assertFalse(tui.enabled(Tty(), Tty(), {"SSL_DOCTOR_TUI": "off"}))
        self.assertTrue(tui.enabled(Tty(), Tty(), {"TERM": "xterm"}))


if __name__ == "__main__":
    unittest.main()


class CliUsesTheProfile(unittest.TestCase):

    def run_repl(self, profile):
        import contextlib
        from unittest import mock
        from ssl_doctor import cli
        app = cli.SSLDoctorCLI()
        seen = {}

        def fake_tui():
            seen["tui"] = True
            return 0
        out = io.StringIO()
        with mock.patch.object(tui, "profile", return_value=profile), \
                mock.patch.object(app, "_repl_tui", fake_tui), \
                mock.patch("builtins.input", side_effect=EOFError), \
                contextlib.redirect_stdout(out):
            app.repl()
        return seen, out.getvalue()

    def test_a_console_without_vt_gets_line_mode_and_says_why(self):
        p = termcaps.TerminalProfile("Windows console (conhost)", False, False,
                                     "this console cannot process VT sequences ...")
        seen, output = self.run_repl(p)
        self.assertNotIn("tui", seen)
        self.assertIn("line mode on Windows console (conhost)", output)

    def test_a_pipe_falls_back_quietly(self):
        p = termcaps.TerminalProfile("terminal", False, False, "input or output is not a terminal")
        _, output = self.run_repl(p)
        self.assertNotIn("line mode on", output)

    def test_full_screen_profile_starts_the_shell(self):
        seen, _ = self.run_repl(termcaps.TerminalProfile("Windows Terminal", True, True))
        self.assertTrue(seen.get("tui"))

    def test_mouse_setting_reaches_the_session(self):
        from unittest import mock
        from ssl_doctor import cli
        app = cli.SSLDoctorCLI()
        app.terminal = termcaps.TerminalProfile("conhost", True, False, "mouse off")
        captured = {}

        class Stop(Exception):
            pass

        def fake_session(**kwargs):
            captured.update(kwargs)
            raise Stop
        with mock.patch.object(tui, "TuiSession", side_effect=fake_session):
            with self.assertRaises(Stop):
                app._repl_tui()
        self.assertIs(captured["mouse"], False)
