"""Result frames survive streaming, and the composer reflects the shell state.

Regression cover for merging the full-screen shell with streamed findings: a
finding printed as its check completes used to be a bare row outside any box,
the shell's capture stream reports itself as a terminal (so it streamed too),
and `/server compare` printed its finding twice when not streaming.
"""

from __future__ import annotations

import contextlib
import io
import re
import unittest
from unittest import mock

from ssl_doctor import cli, findings as F, tui

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def finding(check="tls.chain", status=F.PASS, title="chain complete"):
    return F.Finding(check, title, status, F.SCOPE_REMOTE_NET, ["evidence row"])


class Terminal(io.StringIO):
    """A stdout that claims to be an interactive terminal."""

    encoding = "utf-8"

    def isatty(self):
        return True


class Themed(unittest.TestCase):
    """Unicode glyphs and colour, restored after every test."""

    mode = cli.ColorMode.TRUECOLOR

    def setUp(self):
        original = cli._MODE
        self.addCleanup(cli.set_color_mode, original)
        cli.set_color_mode(self.mode)
        if self.mode != cli.ColorMode.PLAIN:
            cli._GLYPHS = cli.Glyphs(True, True)
        cli.set_block_label("/tls shop.test")
        self.addCleanup(cli.set_block_label, "")

    def run_phase(self, stream, body):
        app = cli.SSLDoctorCLI()
        with contextlib.redirect_stdout(stream):
            with app._results("checking shop.test") as phase:
                body(phase)
        return ANSI.sub("", stream.getvalue())


class StreamingKeepsTheFrame(Themed):

    def test_streamed_findings_land_in_one_box(self):
        stream = Terminal()
        seen_before_first = []

        def body(phase):
            seen_before_first.append(ANSI.sub("", stream.getvalue()))
            phase.add(finding("tls.chain", F.PASS))
            phase.add(finding("tls.verify", F.FAIL, "validation fails"))

        out = self.run_phase(stream, body).splitlines()
        # the frame and the phase row are drawn before any finding arrives
        self.assertIn("╭─ /tls shop.test", seen_before_first[0])
        self.assertIn("▸ checking shop.test", seen_before_first[0])
        self.assertTrue(out[0].strip().startswith("╭─ /tls shop.test"))
        self.assertTrue(out[-1].strip().startswith("╰─ 1 passed"))
        self.assertIn("1 failed", out[-1])
        interior = out[1:-1]
        self.assertTrue(all(row.strip().startswith("│") and row.strip().endswith("│")
                            for row in interior), interior)
        self.assertEqual({len(row) for row in out}, {len(out[0])})

    def test_a_returned_finding_that_was_not_emitted_is_still_shown(self):
        quiet = finding("srv.logs", F.WARNING, "returned only")

        def body(phase):
            phase.add(finding())
            phase.done([quiet])

        out = self.run_phase(Terminal(), body)
        self.assertIn("returned only", out)
        self.assertIn("1 warnings", out)

    def test_an_emitted_and_returned_finding_is_shown_once(self):
        both = finding(title="emitted and returned")

        def body(phase):
            phase.add(both)
            phase.done([both])

        self.assertEqual(self.run_phase(Terminal(), body).count("emitted and returned"), 1)

    def test_without_streaming_the_finished_box_is_drawn(self):
        app = cli.SSLDoctorCLI()
        app._BATCH_MODE = True
        stream = Terminal()
        with contextlib.redirect_stdout(stream):
            with app._results("checking") as phase:
                phase.add(finding())
                # only the spinner runs until the phase ends
                self.assertNotIn("chain complete", stream.getvalue())
                self.assertNotIn("╭", stream.getvalue())
        out = ANSI.sub("", stream.getvalue())
        self.assertIn("╭─ /tls shop.test", out)
        self.assertIn("chain complete", out)

    def test_a_profile_added_first_leads_the_finished_box(self):
        app = cli.SSLDoctorCLI()
        app._BATCH_MODE = True
        stream = Terminal()
        with contextlib.redirect_stdout(stream):
            with app._results("checking") as phase:
                phase.add(finding(title="second"))
                phase.add(finding("scan.domain", title="profile"), first=True)
        out = ANSI.sub("", stream.getvalue())
        self.assertLess(out.index("profile"), out.index("second"))


class PlainStreaming(Themed):
    mode = cli.ColorMode.PLAIN

    def test_plain_output_streams_bare_rows_and_counts(self):
        out = self.run_phase(Terminal(), lambda phase: phase.add(finding()))
        self.assertNotIn("╭", out)
        self.assertIn("... checking shop.test", out)
        self.assertRegex(out, r"\[\s*\+ PASS\] chain complete")
        self.assertIn("1 passed", out)


class ShellCapture(Themed):
    """Inside the shell, streaming draws into the transcript and the status."""

    def test_streamed_findings_are_boxed_in_the_transcript(self):
        session = tui.TuiSession(renderer=lambda s: ([], (1, 1)), stream=io.StringIO())
        started = []
        session.start_status = lambda spans: started.append(spans)
        session.stop_status = lambda: None
        cli.set_active_tui(session)
        self.addCleanup(cli.set_active_tui, None)
        cli.set_capture_width(60)
        self.addCleanup(cli.set_capture_width, 0)
        app = cli.SSLDoctorCLI()
        with mock.patch.object(cli, "_CAPTURE", True), \
                contextlib.redirect_stdout(session.capture()):
            with app._results("checking shop.test") as phase:
                phase.add(finding())
        lines = session.transcript.lines
        self.assertTrue(lines[0].strip().startswith("╭─ /tls shop.test"))
        self.assertTrue(lines[-1].strip().startswith("╰─ 1 passed"))
        self.assertTrue(all("\x1b" not in line for line in lines))
        self.assertEqual({len(line) for line in lines}, {60})
        self.assertEqual(len(started), 1)  # progress went to the status line

    def test_the_typewriter_never_types_into_the_capture(self):
        with mock.patch.object(cli, "_TW_ENABLED", True), \
                mock.patch.object(cli, "_CAPTURE", True), \
                mock.patch.object(cli.time, "sleep") as sleep, \
                contextlib.redirect_stdout(Terminal()):
            cli._tw_type("typed at once")
        sleep.assert_not_called()


class ServerCompareOnce(Themed):

    def test_compare_prints_its_finding_once(self):
        class Server:
            connected = True

            def compare_configured_vs_presented(self, presented, emit=None):
                f = finding("srv.compare", F.PASS, "configured matches presented")
                if emit:
                    emit(f)
                return f

        for batch in (True, False):
            with self.subTest(batch=batch):
                app = cli.SSLDoctorCLI()
                app._BATCH_MODE = batch
                app.server = Server()
                stream = Terminal()
                with contextlib.redirect_stdout(stream):
                    app.cmd_server(["compare"])
                self.assertEqual(stream.getvalue().count("configured matches presented"), 1)
                self.assertEqual(len(app.store), 1)


class ComposerState(Themed):
    """What the shell's composer shows for each state of the session."""

    def frame(self, **attrs):
        app = cli.SSLDoctorCLI()
        session = tui.TuiSession(renderer=app._tui_frame, stream=io.StringIO())
        session.size = lambda: (100, 30)
        for name, value in attrs.items():
            setattr(session, name, value)
        lines, _ = app._tui_frame(session)
        text = [ANSI.sub("", line) for line in lines]
        top = next(i for i, line in enumerate(text) if "╭" in line)
        return text[top], text[top + 1], text[top + 2]

    def test_ready_shows_the_label_placeholder_and_hints(self):
        top, row, bottom = self.frame()
        self.assertIn("╭─ ssl-doctor ", top)
        self.assertIn("ssh off", top)
        self.assertIn("❯ Type a command", row)
        self.assertIn("Tab complete", bottom)
        self.assertIn("⏎ send", bottom)

    def test_a_question_takes_over_the_label(self):
        top, row, bottom = self.frame(question="SSH port", default="22",
                                      status=[("SSH port  [22]", "accent", False)])
        self.assertIn("╭─ SSH port  [22] ", top)
        self.assertIn("Enter for 22", row)
        self.assertIn("Enter accepts the default", bottom)

    def test_a_yes_no_question_hints_its_answers(self):
        _, _, bottom = self.frame(question="trust this key? (yes/no)", default="no",
                                  status=[("trust this key? (yes/no)", "accent", False)])
        self.assertIn("[Y]es  [N]o", bottom)

    def test_a_running_check_shows_busy_without_hints(self):
        top, row, bottom = self.frame(status=[("✻ handshaking… shop.test", "primary", True)])
        self.assertIn("handshaking", top)
        self.assertIn("Ctrl-C to interrupt", row)
        self.assertNotIn("send", bottom)
        self.assertEqual(set(bottom.strip()[1:-1]), {"─"})

    def test_an_open_menu_changes_the_hints(self):
        _, _, bottom = self.frame(menu=[("/scan", "full workflow")], menu_index=0)
        self.assertIn("Esc close", bottom)

    def test_the_banner_is_the_full_wordmark_on_a_tall_screen(self):
        app = cli.SSLDoctorCLI()
        self.assertEqual(sum("█" in "".join(t for t, _, _ in row)
                             for row in app._tui_header(100, 30)), cli.WORDMARK_ROWS)
        compact = app._tui_header(100, 20)
        self.assertFalse(any("█" in "".join(t for t, _, _ in row) for row in compact))


class LineComposer(Themed):
    """The line REPL draws the same rounded composer around its prompt."""

    def test_the_prompt_sits_in_a_rounded_composer(self):
        app = cli.SSLDoctorCLI()
        app.use_tui = False
        stream = Terminal()
        prompts = []

        def fake_input(text):
            prompts.append(ANSI.sub("", text))
            if len(prompts) == 1:
                return "/version"
            raise EOFError

        with mock.patch("builtins.input", fake_input), contextlib.redirect_stdout(stream):
            app.repl()
        out = ANSI.sub("", stream.getvalue())
        self.assertIn("╭─ ssl-doctor ", out)
        self.assertIn("╰─ /help · Ctrl-D quit ", out)
        self.assertEqual(prompts[0], "  │ ❯ ")
        # the composer closes before the command's output
        self.assertLess(out.index("╰─"), out.index("SSL Doctor v"))


if __name__ == "__main__":
    unittest.main()
