"""Clipboard delivery: routes, honesty of the confirmation, and failure handling.

Every route is injected (terminal stream, environment, tool runner, `which`),
so no test touches the real clipboard or starts a process.
"""

from __future__ import annotations

import base64
import io
import os
import subprocess
import unittest
from unittest import mock

from ssl_doctor import clipboard


class Terminal(io.StringIO):
    def isatty(self):
        return True


class Pipe(io.StringIO):
    def isatty(self):
        return False


class Runner:
    """Records tool invocations; answers with `returncode` or raises `error`."""

    def __init__(self, returncode=0, error=None):
        self.calls, self.returncode, self.error = [], returncode, error

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        if self.error:
            raise self.error
        return subprocess.CompletedProcess(argv, self.returncode, b"", b"")


def which_any(*names):
    return lambda name: f"/usr/bin/{name}" if name in names else None


def copy(text="hello\nworld", stream=None, env=None, run=None, which=None,
         platform="linux", release="6.1.0", native=()):
    """clipboard.copy with every route injected; no native route unless given,
    so no test forks an X11 helper or touches a real clipboard."""
    return clipboard.copy(text, stream=stream if stream is not None else Terminal(),
                          env=env or {}, run=run or Runner(), which=which or which_any(),
                          platform=platform, release=release, native=list(native))


class TerminalEscape(unittest.TestCase):

    def test_osc52_carries_the_text_as_base64(self):
        stream = Terminal()
        result = copy("ação ✓", stream=stream)
        payload = base64.b64encode("ação ✓".encode()).decode()
        self.assertEqual(stream.getvalue(), f"\033]52;c;{payload}\a")
        self.assertEqual(result.routes, [clipboard.TERMINAL_ROUTE])
        self.assertFalse(result.confirmed)

    def test_tmux_wraps_the_escape_in_passthrough(self):
        stream = Terminal()
        copy("x", stream=stream, env={"TMUX": "/tmp/tmux-0/default,1,0"})
        out = stream.getvalue()
        self.assertTrue(out.startswith("\033Ptmux;\033\033]52;c;"))
        self.assertTrue(out.endswith("\033\\"))

    def test_no_escape_into_a_pipe(self):
        stream = Pipe()
        result = copy(stream=stream)
        self.assertEqual(stream.getvalue(), "")
        self.assertNotIn(clipboard.TERMINAL_ROUTE, result.routes)

    def test_large_text_skips_the_escape(self):
        stream = Terminal()
        result = copy("x" * (clipboard.OSC52_LIMIT), stream=stream)
        self.assertEqual(stream.getvalue(), "")
        self.assertTrue(any("too large" in s for s in result.skipped))

    def test_a_broken_terminal_is_a_failure_not_a_crash(self):
        class Broken(Terminal):
            def write(self, text):
                raise OSError("EIO")
        result = copy(stream=Broken())
        self.assertEqual(result.routes, [])
        self.assertTrue(result.failures[0].startswith(clipboard.TERMINAL_ROUTE))


class LocalTools(unittest.TestCase):

    def test_tool_choice_follows_the_environment(self):
        cases = [
            ({"WAYLAND_DISPLAY": "wayland-0"}, "linux", which_any("wl-copy", "xclip"), "wl-copy"),
            ({"DISPLAY": ":0"}, "linux", which_any("xclip"), "xclip"),
            ({"DISPLAY": ":0"}, "linux", which_any("xsel"), "xsel"),
            ({}, "darwin", which_any("pbcopy"), "pbcopy"),
            ({}, "win32", which_any("clip.exe"), "clip.exe"),
            ({}, "linux", which_any("xclip", "wl-copy"), None),     # no display: no tool
        ]
        for env, platform, which, expected in cases:
            with self.subTest(env=env, platform=platform):
                argv = clipboard.local_tool(env, which, platform, release="6.1.0")
                self.assertEqual(argv[0] if argv else None, expected)

    def test_wsl_uses_clip_exe(self):
        argv = clipboard.local_tool({}, which_any("clip.exe"), "linux",
                                    release="5.15.90.1-microsoft-standard-WSL2")
        self.assertEqual(argv, ["clip.exe"])

    def test_the_tool_gets_the_text_without_a_shell(self):
        run = Runner()
        result = copy("payload", env={"DISPLAY": ":0"}, run=run, which=which_any("xclip"))
        argv, kwargs = run.calls[0]
        self.assertEqual(argv, ["xclip", "-selection", "clipboard"])
        self.assertIs(kwargs["shell"], False)
        self.assertEqual(kwargs["input"], b"payload")
        self.assertEqual(kwargs["timeout"], clipboard.TOOL_TIMEOUT)
        self.assertTrue(result.confirmed)
        self.assertEqual(result.routes, [clipboard.TERMINAL_ROUTE, "xclip"])

    def test_clip_exe_receives_utf16_with_a_bom(self):
        run = Runner()
        copy("ç", run=run, which=which_any("clip.exe"), platform="win32")
        self.assertEqual(run.calls[0][1]["input"], b"\xff\xfe" + "ç".encode("utf-16-le"))

    def test_tool_failures_are_reported(self):
        for runner, expected in ((Runner(returncode=1), "exit status 1"),
                                 (Runner(error=subprocess.TimeoutExpired("xclip", 2)), "timed out"),
                                 (Runner(error=FileNotFoundError(2, "No such file")), "No such file")):
            with self.subTest(expected=expected):
                result = copy(env={"DISPLAY": ":0"}, run=runner, which=which_any("xclip"))
                self.assertEqual(result.failures, [f"xclip: {expected}"])
                self.assertFalse(result.confirmed)


class Confirmation(unittest.TestCase):

    def test_counts_and_routes_never_the_text(self):
        result = copy("secret line one\nsecret line two", env={"DISPLAY": ":0"},
                      which=which_any("xclip"))
        message = clipboard.describe(result)
        self.assertEqual(message, "copied 2 lines · 31 chars · terminal clipboard + xclip")
        self.assertNotIn("secret", message)

    def test_escape_only_is_not_called_a_copy(self):
        message = clipboard.describe(copy("abc"))
        self.assertTrue(message.startswith("copy not confirmed: 1 line · 3 chars sent only "
                                           "to the terminal clipboard (OSC 52)"), message)
        self.assertIn(clipboard.SHIFT_DRAG_HINT, message)
        self.assertFalse(message.startswith("copied"))

    def test_no_route_says_so_with_reasons_and_a_way_out(self):
        message = clipboard.describe(copy("abc", stream=Pipe()))
        self.assertTrue(message.startswith("copy failed: no clipboard reachable"), message)
        self.assertIn(clipboard.SHIFT_DRAG_HINT, message)
        self.assertIn("not a terminal", message)

    def test_a_tool_failure_is_appended(self):
        result = copy(env={"DISPLAY": ":0"}, run=Runner(returncode=1), which=which_any("xclip"))
        message = clipboard.describe(result)
        self.assertIn("terminal clipboard", message)
        self.assertIn("xclip: exit status 1", message)


class NativeRoutes(unittest.TestCase):
    """The OS clipboard first; a tool only when no native route took the text."""

    def test_route_choice_per_platform(self):
        self.assertEqual([n for n, _ in clipboard.native_routes({}, "win32")],
                         [clipboard.WINDOWS_ROUTE])
        self.assertEqual([n for n, _ in clipboard.native_routes({"DISPLAY": ":0"}, "linux")],
                         [clipboard.X11_ROUTE])
        self.assertEqual(clipboard.native_routes({"WAYLAND_DISPLAY": "w-0"}, "linux"), [])
        self.assertEqual(clipboard.native_routes({}, "darwin"), [])

    def test_a_native_copy_is_confirmed_and_skips_the_tool(self):
        run, seen = Runner(), []
        result = copy("text", env={"DISPLAY": ":0"}, run=run, which=which_any("xclip"),
                      native=[(clipboard.X11_ROUTE, lambda t: seen.append(t))])
        self.assertEqual(seen, ["text"])
        self.assertEqual(result.routes, [clipboard.TERMINAL_ROUTE, clipboard.X11_ROUTE])
        self.assertEqual(run.calls, [])              # no tool needed
        self.assertTrue(clipboard.describe(result).startswith("copied"))

    def test_a_failed_native_route_falls_back_to_the_tool(self):
        run = Runner()
        result = copy(env={"DISPLAY": ":0"}, run=run, which=which_any("xclip"),
                      native=[(clipboard.X11_ROUTE, lambda t: "cannot open the X display")])
        self.assertEqual(result.routes, [clipboard.TERMINAL_ROUTE, "xclip"])
        self.assertIn("X11 clipboard: cannot open the X display", result.failures)

    def test_a_crashing_native_route_is_a_failure_not_a_crash(self):
        def boom(text):
            raise OSError("libX11 exploded")
        result = copy(native=[(clipboard.X11_ROUTE, boom)])
        self.assertTrue(result.failures[0].startswith("X11 clipboard: OSError"))

    def test_the_xfce_case_without_tools_is_reported_with_a_way_out(self):
        """VTE terminal (ignores OSC 52), no xclip, X11 route failing."""
        result = copy(env={"DISPLAY": ":0"},
                      native=[(clipboard.X11_ROUTE, lambda t: "libX11 is not installed")])
        message = clipboard.describe(result)
        self.assertTrue(message.startswith("copy not confirmed"), message)
        self.assertIn("libX11 is not installed", message)


class WindowsClipboard(unittest.TestCase):
    """The Win32 sequence, against recording stand-ins for user32/kernel32."""

    class User32:
        def __init__(self, open_ok=True, set_ok=True):
            self.calls, self.open_ok, self.set_ok = [], open_ok, set_ok

        def OpenClipboard(self, hwnd):
            self.calls.append("open")
            return self.open_ok

        def EmptyClipboard(self):
            self.calls.append("empty")
            return True

        def SetClipboardData(self, fmt, handle):
            self.calls.append(("set", fmt))
            return handle if self.set_ok else 0

        def CloseClipboard(self):
            self.calls.append("close")
            return True

    class Kernel32:
        def __init__(self):
            self.buffers, self.freed = {}, []

        def GlobalAlloc(self, flags, size):
            import ctypes
            buffer = ctypes.create_string_buffer(size)
            self.buffers[ctypes.addressof(buffer)] = buffer
            return ctypes.addressof(buffer)

        def GlobalLock(self, handle):
            return handle

        def GlobalUnlock(self, handle):
            return True

        def GlobalFree(self, handle):
            self.freed.append(handle)

    def test_unicode_text_with_crlf_line_ends(self):
        user32, kernel32 = self.User32(), self.Kernel32()
        self.assertIsNone(clipboard.windows_copy("a\nç", user32, kernel32))
        self.assertEqual(user32.calls, ["open", "empty", ("set", 13), "close"])
        [buffer] = kernel32.buffers.values()
        self.assertEqual(buffer.raw, "a\r\nç".encode("utf-16-le") + b"\0\0")

    def test_a_busy_clipboard_is_reported(self):
        user32 = self.User32(open_ok=False)
        with mock.patch.object(clipboard.time, "sleep"):
            self.assertEqual(clipboard.windows_copy("x", user32, self.Kernel32()),
                             "the clipboard is in use by another program")
        self.assertNotIn("close", user32.calls)          # never opened, never closed

    def test_a_refused_handle_is_freed_and_the_clipboard_closed(self):
        user32, kernel32 = self.User32(set_ok=False), self.Kernel32()
        self.assertEqual(clipboard.windows_copy("x", user32, kernel32),
                         "the clipboard refused the text")
        self.assertEqual(len(kernel32.freed), 1)
        self.assertEqual(user32.calls[-1], "close")


@unittest.skipUnless(os.environ.get("SSL_DOCTOR_TEST_X11") == "1",
                     "set SSL_DOCTOR_TEST_X11=1 to test against the real X display "
                     "(it replaces the clipboard)")
class RealX11(unittest.TestCase):
    """Opt-in: copy through the real X server and read it back."""

    def test_round_trip(self):
        marker = f"ssl-doctor x11 round trip {os.getpid()} ✓"
        self.assertIsNone(clipboard.x11_copy(marker))


if __name__ == "__main__":
    unittest.main()
