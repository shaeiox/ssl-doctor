"""Full-screen application shell: layout, transcript, keys and the command bar.

The layout is a pure function, so the whole visual contract is asserted without
a terminal: exact widths, centring, panel contents and cursor cell. Keyboard and
editing tests drive the session with a scripted key source.
"""

from __future__ import annotations

import contextlib
import io
import os
import re
import unittest
from unittest import mock

from ssl_doctor import cli, tui

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def plain(lines):
    return [ANSI.sub("", line) for line in lines]


def paint(text, role="", bold=False):
    """The real painter, pinned to TrueColor for the layout tests."""
    with mock.patch.object(cli, "_MODE", cli.ColorMode.TRUECOLOR), \
            mock.patch.object(cli, "_CAPTURE", False):
        return cli.paint(text, role, bold)


class StubGlyphs:
    """Unicode glyphs without going through a real terminal."""

    vert = "│"
    h = "─"
    unicode = True
    box = True
    ellipsis = "…"
    double = "═"
    block = "█"

    def corner(self, unicode_char, ascii_char):
        return unicode_char

    def __getitem__(self, key):
        return {"pass": "✓", "fail": "✗", "warn": "⚠", "run": "▸",
                "bullet": "•", "sep": "·", "unknown": "?"}[key]


class FakeTerminal(io.StringIO):
    def __init__(self, encoding="utf-8"):
        super().__init__()
        self._encoding = encoding

    def isatty(self):
        return True

    @property
    def encoding(self):
        return self._encoding


def frame(**overrides):
    kwargs = dict(
        columns=100, rows=30,
        header=[[(" HEADER ", "primary", True)], []],
        body=["[   + PASS] a finding  - network", "plain line"],
        status=[("status text", "muted", False)],
        prompt_text="/scan shop.test", hints=[("hints here", "muted", False)],
        painter=paint, glyphs=StubGlyphs(), cursor=5,
    )
    kwargs.update(overrides)
    return tui.build_frame(**kwargs)


class FrameLayout(unittest.TestCase):
    """The composition: exact widths, centring, regions and cursor."""

    def test_every_line_is_exactly_the_terminal_width(self):
        for columns, rows in ((160, 40), (100, 30), (80, 24), (50, 16), (40, 12)):
            with self.subTest(columns=columns, rows=rows):
                lines, _ = frame(columns=columns, rows=rows)
                self.assertEqual(len(lines), rows)
                self.assertEqual({len(ANSI.sub("", line)) for line in lines},
                                 {columns})

    def test_column_is_centred_and_clamped(self):
        wide, _ = frame(columns=160)
        wide = plain(wide)
        margins = {len(line) - len(line.lstrip(" ")) for line in wide if line.strip()}
        self.assertIn(32, margins)  # (160 - 96) // 2

        narrow, _ = frame(columns=50)
        narrow = plain(narrow)
        self.assertTrue(all(len(line) == 50 for line in narrow))
        self.assertTrue(any(line.startswith(" ┌─ output") for line in narrow))

    def test_regions_appear_in_order(self):
        text = "\n".join(plain(frame()[0]))
        order = ["HEADER", "┌─ output", "a finding", "status text",
                 "┌─ command", "/scan shop.test", "hints here"]
        positions = [text.index(token) for token in order]
        self.assertEqual(positions, sorted(positions))

    def test_body_is_inside_the_panel_and_keeps_its_text(self):
        lines = plain(frame(body=["[   + PASS] a finding  - network"])[0])
        row = next(line for line in lines if "a finding" in line)
        self.assertTrue(row.lstrip().startswith("│"))
        self.assertTrue(row.rstrip().endswith("│"))

    def test_cursor_sits_after_the_typed_text(self):
        lines, (row, column) = frame(prompt_text="/scan", cursor=5)
        bar_row = plain(lines)[row - 1]
        self.assertIn("/scan", bar_row)
        # column 1 + margin(2) + "│ "(2) + "> "(2) + 5 typed characters
        self.assertEqual(column, 2 + 2 + 2 + 5 + 1)

    def test_header_collapses_when_rows_are_short(self):
        compact = [[(" SSL DOCTOR · v0.3.0 ", "primary", True)], []]
        lines, _ = frame(rows=14, header=compact)
        self.assertEqual(len(lines), 14)
        self.assertIn("SSL DOCTOR", "\n".join(plain(lines)))

    def test_hints_are_dropped_first(self):
        lines, _ = frame(rows=10, hints=())
        self.assertEqual(len(lines), 10)
        text = "\n".join(plain(lines))
        self.assertNotIn("hints here", text)
        self.assertIn("┌─ command", text)  # the bar survives

    def test_panel_height_floor(self):
        self.assertGreaterEqual(tui.panel_height(6, 4, True), 1)
        self.assertEqual(tui.panel_height(30, 7, True), 16)


class TranscriptBehaviour(unittest.TestCase):
    def test_feed_splits_lines_and_keeps_partial_text(self):
        transcript = tui.Transcript()
        transcript.feed("one\ntwo\npar")
        self.assertEqual(transcript.lines, ["one", "two"])
        transcript.feed("tial\n")
        self.assertEqual(transcript.lines, ["one", "two", "partial"])

    def test_carriage_return_overwrites_instead_of_appending(self):
        transcript = tui.Transcript()
        transcript.feed("progress 10%\rprogress 50%\rdone\n")
        self.assertEqual(transcript.lines, ["done"])

    def test_flush_partial_keeps_a_trailing_line(self):
        transcript = tui.Transcript()
        transcript.feed("no newline")
        transcript.flush_partial()
        self.assertEqual(transcript.lines, ["no newline"])

    def test_wrapping_never_drops_characters(self):
        long_line = "  " + "abcdefghij" * 12
        wrapped = tui.wrap_line(long_line, 40)
        self.assertTrue(all(len(chunk) <= 40 for chunk in wrapped))
        self.assertEqual("".join(chunk.strip() for chunk in wrapped),
                         long_line.strip())

    def test_tail_scrolls_and_clamps(self):
        transcript = tui.Transcript()
        for index in range(50):
            transcript.append(f"line {index}")
        newest = transcript.tail(40, 5)
        self.assertEqual(newest[-1], "line 49")
        self.assertEqual(len(newest), 5)
        back = transcript.tail(40, 5, scroll=10)
        self.assertEqual(back[-1], "line 39")
        clamped = transcript.tail(40, 5, scroll=10_000)
        self.assertEqual(clamped[0], "line 0")
        self.assertEqual(len(clamped), 5)

    def test_status_colouring_follows_the_status_word(self):
        role = {"PASS": "success", "FAIL": "error", "WARNING": "warning",
                "NOT TESTED": "muted"}
        for status, expected in role.items():
            with self.subTest(status=status):
                spans = tui.colorize(f"[   + {status}] something")
                self.assertEqual(spans[0][1], expected)
                self.assertEqual(spans[0][0], f"[   + {status}]")
        self.assertEqual(tui.colorize("error: boom")[0][1], "error")
        self.assertEqual(tui.colorize("          fix: do this")[0][1], "accent")
        self.assertEqual(tui.colorize("error: boom")[0][0], "error: boom")


class Capabilities(unittest.TestCase):
    def test_enabled_requires_a_terminal(self):
        self.assertFalse(tui.enabled(stream=io.StringIO(), stdin=io.StringIO(),
                                     env={}))
        self.assertTrue(tui.enabled(stream=FakeTerminal(), stdin=FakeTerminal(),
                                    env={}))

    def test_opt_outs(self):
        for value in ("0", "false", "no", "off"):
            with self.subTest(value=value):
                self.assertFalse(tui.enabled(stream=FakeTerminal(),
                                             stdin=FakeTerminal(),
                                             env={"SSL_DOCTOR_TUI": value}))
        self.assertFalse(tui.enabled(stream=FakeTerminal(), stdin=FakeTerminal(),
                                     env={"TERM": "dumb"}))

    def test_no_tui_flag(self):
        with mock.patch("ssl_doctor.tui.enabled", return_value=True) as probe, \
                contextlib.redirect_stdout(io.StringIO()):
            cli.main(["--no-tui", "-c", "/version"])
        probe.assert_not_called()

    def test_batch_never_enters_the_shell(self):
        buf = io.StringIO()
        with mock.patch("ssl_doctor.tui.enabled", return_value=True) as probe, \
                contextlib.redirect_stdout(buf):
            code = cli.main(["-c", "/version"])
        self.assertEqual(code, 0)
        probe.assert_not_called()
        self.assertNotIn("\x1b[?1049h", buf.getvalue())


class KeyDecoding(unittest.TestCase):
    def reader(self):
        reader = tui.KeyReader(stream=io.StringIO())
        reader._windows = False
        return reader

    def test_escape_sequences(self):
        reader = self.reader()
        cases = {b"[A": "up", b"[B": "down", b"[C": "right", b"[D": "left",
                 b"[5~": "pageup", b"[6~": "pagedown", b"[H": "home", b"[F": "end"}
        for sequence, expected in cases.items():
            with self.subTest(sequence=sequence):
                self.assertEqual(reader._decode_escape(sequence), expected)

    def test_control_characters(self):
        reader = self.reader()
        cases = {"\r": "enter", "\n": "enter", "\x7f": "backspace",
                 "\x03": "ctrl-c", "\x04": "ctrl-d", "\x15": "ctrl-u",
                 "a": "a", " ": " "}
        for char, expected in cases.items():
            with self.subTest(char=repr(char)):
                self.assertEqual(reader._decode_bytes(char.encode("utf-8")), expected)

    def test_utf8_input_is_decoded(self):
        reader = self.reader()
        encoded = "é".encode("utf-8")
        self.assertEqual(reader._decode_bytes(encoded[:1]), "pending")
        self.assertEqual(reader._decode_bytes(encoded[1:]), "é")


class ScriptedKeys:
    """A key source that replays a script and records what was rendered."""

    def __init__(self, keys):
        self.keys = list(keys)
        self.drawn = []

    def read_key(self):
        return self.keys.pop(0) if self.keys else "ctrl-d"


def session_with(keys, renderer=None):
    session = tui.TuiSession(renderer=renderer or (lambda s: ([], (1, 1))),
                             stream=io.StringIO(), keys=ScriptedKeys(keys))
    session.screen.active = False  # no alternate screen in tests
    return session


class CommandBar(unittest.TestCase):
    def type_text(self, session, text):
        for char in text:
            session.keys.keys.insert(0, char)

    def test_typing_and_enter(self):
        session = session_with(list("/help") + ["enter"])
        self.assertEqual(session.read_line(), "/help")

    def test_backspace_and_ctrl_u(self):
        session = session_with(list("abc") + ["backspace", "enter"])
        self.assertEqual(session.read_line(), "ab")
        session = session_with(list("abc") + ["ctrl-u"] + list("x") + ["enter"])
        self.assertEqual(session.read_line(), "x")

    def test_cursor_editing(self):
        # type "ac", move left, insert "b"
        session = session_with(list("ac") + ["left"] + ["b", "enter"])
        self.assertEqual(session.read_line(), "abc")

    def test_home_and_end(self):
        session = session_with(list("bc") + ["home", "a", "end", "d", "enter"])
        self.assertEqual(session.read_line(), "abcd")

    def test_history_recall(self):
        session = session_with(["enter"])
        session = session_with(["up", "up", "enter"])
        session.history.extend(["/tls a", "/local"])
        self.assertEqual(session.read_line(), "/tls a")

    def test_down_restores_the_draft(self):
        session = session_with(list("dra") + ["up", "down", "enter"])
        session.history.append("/local")
        self.assertEqual(session.read_line(), "dra")

    def test_ctrl_d_and_eof_return_none(self):
        self.assertIsNone(session_with(["ctrl-d"]).read_line())
        self.assertIsNone(session_with(["eof"]).read_line())

    def test_password_is_not_echoed(self):
        session = session_with(list("s3cret") + ["enter"])
        self.assertEqual(session.read_line(secret=True), "s3cret")
        self.assertFalse(session.masked)

    def test_scrolling_keeps_the_typed_text(self):
        session = session_with(list("ab") + ["pageup", "pagedown", "enter"])
        self.assertEqual(session.read_line(), "ab")
        self.assertEqual(session.scroll, 0)


class StatusAndCapture(unittest.TestCase):
    def test_capture_stream_feeds_the_transcript(self):
        session = session_with([])
        stream = session.capture()
        self.assertTrue(stream.isatty())
        stream.write("line one\nline two\n")
        stream.flush()
        self.assertEqual(session.transcript.lines, ["line one", "line two"])

    def test_spinner_uses_the_status_line_not_the_panel(self):
        session = session_with([])
        started, stopped = [], []
        session.start_status = lambda spans: started.append(spans)
        session.stop_status = lambda: stopped.append(True)
        cli.set_active_tui(session)
        self.addCleanup(cli.set_active_tui, None)
        before = len(session.transcript.lines)
        with cli.Spinner("checking", verb="chaining"):
            pass
        self.assertEqual(len(session.transcript.lines), before)
        self.assertEqual(len(started), 1)
        self.assertEqual(len(stopped), 1)
        self.assertIn("chaining", started[0][0][0])

    def test_ask_returns_the_default_on_empty_input(self):
        session = session_with(["enter"])
        self.assertEqual(session.ask("SSH port", "22"), "22")

    def test_ask_reads_the_answer(self):
        session = session_with(list("yes") + ["enter"])
        self.assertEqual(session.ask("run server checks? (yes/no)", "no"), "yes")


class ShellIntegration(unittest.TestCase):
    def test_renderer_composes_a_full_frame_without_a_terminal(self):
        app = cli.SSLDoctorCLI()
        app.remote_facts = {"host": "shop.example", "port": 443}

        class Session:
            size = lambda self: (100, 30)  # noqa: E731
            transcript = type("T", (), {"tail": staticmethod(
                lambda w, h, scroll=0: ["[   x FAIL] tls.chain  - network"])})()
            status = []
            input = "/scan shop.example"
            cursor = 9
            scroll = 0
            masked = False

            def display_text(self):
                return self.input

        lines, cursor = app._tui_frame(Session())
        text = "\n".join(plain(lines))
        self.assertIn("output", text)
        self.assertIn("tls.chain", text)
        self.assertIn("/scan shop.example", text)
        self.assertIn("shop.example:443", text)
        self.assertEqual(len(lines), 30)

    def test_newest_output_is_never_clipped_by_the_layout(self):
        """The renderer and the layout must agree on the panel height."""
        app = cli.SSLDoctorCLI()
        cli.set_color_mode(cli.ColorMode.PLAIN)
        self.addCleanup(cli.set_color_mode, cli.ColorMode.PLAIN)

        session = session_with([])
        session.transcript.lines = [f"line {index}" for index in range(30)]
        session.size = lambda: (80, 24)

        lines, _ = app._tui_frame(session)
        text = "\n".join(plain(lines))
        self.assertIn("line 29", text)  # the newest line is on screen

    def test_ctrl_c_at_the_prompt_exits_and_closes_the_shell(self):
        class StubSession:
            def __init__(self, renderer, **kwargs):
                self.renderer = renderer
                self.transcript = tui.Transcript()
                self.closed = False

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self.closed = True

            def read_line(self):
                raise KeyboardInterrupt

            def render(self):
                pass

            def display_text(self):
                return ""

        created = {}

        def factory(renderer, **kwargs):
            created["session"] = StubSession(renderer, **kwargs)
            return created["session"]

        app = cli.SSLDoctorCLI()
        with mock.patch("ssl_doctor.tui.TuiSession", side_effect=factory), \
                contextlib.redirect_stdout(io.StringIO()):
            code = app._repl_tui()
        self.assertEqual(code, 0)
        self.assertTrue(created["session"].closed)
        self.assertIsNone(app._tui)

    def test_capture_flag_produces_plain_rows(self):
        """While capturing, findings must arrive as plain, escape-free text."""
        app = cli.SSLDoctorCLI()
        session = session_with([])
        stream = session.capture()
        finding = cli.F.Finding("tls.chain", "chain", cli.F.FAIL,
                                cli.F.SCOPE_REMOTE_NET, ["only the leaf"])
        old_mode = cli._MODE
        self.addCleanup(cli.set_color_mode, old_mode)
        cli.set_color_mode(cli.ColorMode.TRUECOLOR)
        with mock.patch.object(cli, "_CAPTURE", True), \
                contextlib.redirect_stdout(stream):
            cli.print_findings([finding])
        stream.flush()
        joined = "\n".join(session.transcript.lines)
        self.assertIn("FAIL", joined)
        self.assertNotIn("\x1b", joined)
        self.assertNotIn("┌", joined)  # the panel is the frame, not the output


if __name__ == "__main__":
    unittest.main()
