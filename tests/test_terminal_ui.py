"""Terminal presentation: theme degradation, frames, prompts and report skin.

These tests pin the rules of the Claude Code-inspired design system without
snapshotting escape sequences: the token resolver and glyph fallback are tested
as pure functions, and the frames are asserted on their escape-stripped text.
"""

from __future__ import annotations

import contextlib
import io
import os
import re
import unittest
from unittest import mock

from ssl_doctor import cli, findings as F, report

ANSI = re.compile(r"\x1b\[[0-9;]*m")


class FakeTerminal(io.StringIO):
    """A stream that claims to be a terminal and has an encoding."""

    def __init__(self, encoding: str = "utf-8") -> None:
        super().__init__()
        self._encoding = encoding

    def isatty(self) -> bool:  # noqa: D102 - test double
        return True

    @property
    def encoding(self) -> str:  # noqa: D102 - test double
        return self._encoding


def stripped(text: str) -> str:
    return ANSI.sub("", text)


class ThemeModeSelection(unittest.TestCase):
    """1.2 — one colour level per process, chosen by the documented precedence."""

    def resolve(self, env, stream, windows=False, vt=True):
        return cli.resolve_color_mode(stream=stream, env=env, windows=windows,
                                      enable_vt=lambda: vt)

    def test_no_color_beats_truecolor(self):
        mode = self.resolve({"NO_COLOR": "1", "COLORTERM": "truecolor"},
                            FakeTerminal())
        self.assertEqual(mode, cli.ColorMode.PLAIN)

    def test_piped_output_is_plain(self):
        self.assertEqual(self.resolve({}, io.StringIO()), cli.ColorMode.PLAIN)

    def test_256color_terminal(self):
        mode = self.resolve({"TERM": "xterm-256color"}, FakeTerminal())
        self.assertEqual(mode, cli.ColorMode.ANSI256)

    def test_truecolor_terminal(self):
        mode = self.resolve({"TERM": "xterm-256color", "COLORTERM": "truecolor"},
                            FakeTerminal())
        self.assertEqual(mode, cli.ColorMode.TRUECOLOR)

    def test_16color_fallback(self):
        self.assertEqual(self.resolve({"TERM": "xterm"}, FakeTerminal()),
                         cli.ColorMode.ANSI16)

    def test_never_and_always(self):
        self.assertEqual(self.resolve({"SSL_DOCTOR_COLOR": "never",
                                       "COLORTERM": "truecolor"}, FakeTerminal()),
                         cli.ColorMode.PLAIN)
        self.assertEqual(self.resolve({"SSL_DOCTOR_COLOR": "always",
                                       "TERM": "xterm-256color"}, FakeTerminal()),
                         cli.ColorMode.ANSI256)
        # always must not defeat redirection
        self.assertEqual(self.resolve({"SSL_DOCTOR_COLOR": "always"}, io.StringIO()),
                         cli.ColorMode.PLAIN)

    def test_dumb_terminal_is_plain(self):
        self.assertEqual(self.resolve({"TERM": "dumb"}, FakeTerminal()),
                         cli.ColorMode.PLAIN)

    def test_every_role_has_all_four_levels(self):
        for role, (rgb, index, basic) in cli.ROLES.items():
            with self.subTest(role=role):
                self.assertEqual(len(rgb), 3)
                self.assertTrue(0 <= index <= 255)
                self.assertIsInstance(basic, int)

    def test_unknown_role_is_a_bug_not_a_crash(self):
        with mock.patch.object(cli, "_MODE", cli.ColorMode.TRUECOLOR):
            with self.assertRaises(KeyError):
                cli.paint("x", "not-a-role")

    def test_role_paint_per_mode(self):
        with mock.patch.object(cli, "_MODE", cli.ColorMode.TRUECOLOR):
            self.assertEqual(cli.paint("x", "primary"), "\x1b[38;2;215;119;87mx\x1b[0m")
        with mock.patch.object(cli, "_MODE", cli.ColorMode.ANSI256):
            self.assertEqual(cli.paint("x", "primary"), "\x1b[38;5;173mx\x1b[0m")
        with mock.patch.object(cli, "_MODE", cli.ColorMode.ANSI16):
            self.assertEqual(cli.paint("x", "primary"), "\x1b[33mx\x1b[0m")
        with mock.patch.object(cli, "_MODE", cli.ColorMode.PLAIN):
            self.assertEqual(cli.paint("x", "primary", bold=True), "x")


class GlyphFallback(unittest.TestCase):
    """1.4 — ASCII everywhere a terminal cannot render the design glyphs."""

    def test_plain_mode_is_ascii(self):
        glyphs = cli.resolve_glyphs(cli.ColorMode.PLAIN)
        self.assertFalse(glyphs.unicode)
        self.assertFalse(glyphs.box)
        for key in ("pass", "fail", "warn", "run", "bullet"):
            self.assertTrue(glyphs[key].isascii(), key)

    def test_cp1252_terminal_falls_back(self):
        glyphs = cli.resolve_glyphs(cli.ColorMode.ANSI16, FakeTerminal("cp1252"))
        self.assertFalse(glyphs.unicode)
        self.assertFalse(glyphs.box)

    def test_utf8_terminal_keeps_design_glyphs(self):
        glyphs = cli.resolve_glyphs(cli.ColorMode.TRUECOLOR, FakeTerminal("utf-8"))
        self.assertEqual(glyphs["pass"], "✓")
        self.assertEqual(glyphs.vert, "│")

    def test_cp1252_session_emits_no_unicode(self):
        original = cli._MODE
        self.addCleanup(cli.set_color_mode, original)
        phone = FakeTerminal("cp1252")
        with mock.patch.object(cli, "_MODE", cli.ColorMode.ANSI16), \
                mock.patch.object(cli, "_GLYPHS", cli.resolve_glyphs(cli.ColorMode.ANSI16, phone)):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                cli.print_findings([F.Finding("tls.chain", "chain", F.FAIL,
                                              F.SCOPE_REMOTE_NET, ["only the leaf"])])
            out = stripped(buf.getvalue())
            self.assertNotIn("✓", out)
            self.assertNotIn("│", out)
            self.assertNotIn("┌", out)
            out.encode("cp1252")  # must survive a cp1252 console


class WindowsTerminal(unittest.TestCase):
    """1.5 — degrade to plain when the console cannot do ANSI."""

    def test_failed_vt_enable_falls_back_to_plain(self):
        mode = cli.resolve_color_mode(stream=FakeTerminal(), env={"TERM": "xterm-256color"},
                                      windows=True, enable_vt=lambda: False)
        self.assertEqual(mode, cli.ColorMode.PLAIN)

    def test_working_vt_enable_keeps_colour(self):
        mode = cli.resolve_color_mode(stream=FakeTerminal(), env={"TERM": "xterm-256color"},
                                      windows=True, enable_vt=lambda: True)
        self.assertEqual(mode, cli.ColorMode.ANSI256)


class CommandBlock(unittest.TestCase):
    """2.3 / 2.4 — one frame per command, complete evidence, no elision."""

    def setUp(self):
        self.original = cli._MODE
        self.addCleanup(cli.set_color_mode, self.original)
        self.addCleanup(cli.set_block_label, "")
        self.finding = F.Finding(
            "tls.chain", "server presents a complete, linked chain", F.FAIL,
            F.SCOPE_REMOTE_NET,
            ["the server sends only the leaf certificate (1 certificate)",
             "clients without the intermediate cached in their store will fail"],
            detail="the leaf is issued by an intermediate that is not sent",
            recommendation="append the intermediate to ssl_certificate on the nginx server",
        )

    def rendered(self, items, columns=None):
        cli.set_color_mode(cli.ColorMode.TRUECOLOR)
        cli.set_block_label("/scan shop.example:443")
        buf = io.StringIO()
        env = {"COLUMNS": str(columns)} if columns else {}
        with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(buf):
            cli.print_findings(items)
        return stripped(buf.getvalue())

    def test_block_keeps_all_content(self):
        out = self.rendered([self.finding])
        for line in self.finding.evidence:
            self.assertIn(line, out)
        self.assertIn(self.finding.detail, out)
        self.assertIn("append the intermediate to ssl_certificate", out)
        self.assertIn("/scan shop.example:443", out)  # header names the command
        self.assertIn("1 failed", out)  # footer keeps the counters
        self.assertIn("┌", out)
        self.assertIn("└", out)

    def test_rows_keep_the_finding_order(self):
        second = F.Finding("tls.hostname", "name coverage", F.PASS, F.SCOPE_REMOTE_NET,
                           ["covered"])
        out = self.rendered([self.finding, second])
        self.assertLess(out.index("tls.chain"), out.index("tls.hostname"))

    def test_narrow_terminal_never_elides_evidence(self):
        out = self.rendered([self.finding], columns=40)
        # wrapping may split a line, but no words may be dropped or elided
        flowed = " ".join(re.sub(r"[│|•]", " ", out).split())
        for line in self.finding.evidence:
            with self.subTest(evidence=line):
                self.assertIn(" ".join(line.split()), flowed)
        self.assertIn(" ".join(self.finding.detail.split()), flowed)
        self.assertNotIn("…", out)
        self.assertNotIn("...", out)

    def test_status_word_is_present_without_colour(self):
        for status in (F.PASS, F.FAIL, F.WARNING, F.NOT_TESTED):
            with self.subTest(status=status):
                f = F.Finding("tls.misc", "title", status, F.SCOPE_REMOTE_NET, ["e"])
                self.assertIn(status, self.rendered([f]))


class HelpListing(unittest.TestCase):
    """2.2 — every command and description survives the restyle."""

    def test_all_rows_present_in_order(self):
        app = cli.SSLDoctorCLI()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            app.cmd_help([])
        lines = [line for line in buf.getvalue().splitlines() if line.startswith("  /")]
        self.assertGreaterEqual(len(lines), 24)
        self.assertTrue(any("/scan" in line and "--client-only" in line for line in lines))
        self.assertTrue(any("/server nginx" in line for line in lines))
        self.assertLess(buf.getvalue().index("/scan"), buf.getvalue().index("/version"))


class Prompts(unittest.TestCase):
    """3.3 — questions look different, answer handling is identical."""

    def test_yes_no_hints(self):
        self.assertEqual(cli._answer_hints("run server checks? (yes/no)", "no"),
                         "[Y]es  [N]o")
        self.assertEqual(cli._answer_hints("Trust this key? (yes/no)", "no"),
                         "[Y]es  [N]o")
        self.assertEqual(cli._answer_hints("auth method: 1=password  2=private key", "2"),
                         "[1] password  [2] private key")
        self.assertEqual(cli._answer_hints("SSH hostname or IP", ""), "")

    def test_eof_returns_default(self):
        app = cli.SSLDoctorCLI()
        with mock.patch.object(cli, "_MODE", cli.ColorMode.PLAIN), \
                mock.patch("builtins.input", side_effect=EOFError), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(app.prompt("SSH port", "22"), "22")

    def test_empty_answer_returns_default(self):
        app = cli.SSLDoctorCLI()
        with mock.patch.object(cli, "_MODE", cli.ColorMode.PLAIN), \
                mock.patch("builtins.input", return_value="   "), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(app.prompt("SSH port", "22"), "22")

    def test_plain_prompt_text_is_unchanged(self):
        app = cli.SSLDoctorCLI()
        seen = {}

        def fake_input(text):
            seen["prompt"] = text
            return "y"

        with mock.patch.object(cli, "_MODE", cli.ColorMode.PLAIN), \
                mock.patch("builtins.input", side_effect=fake_input), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(app.prompt("run server checks? (yes/no)", "no"), "y")
        self.assertEqual(seen["prompt"], "run server checks? (yes/no) [no]: ")

    def test_question_frame_is_lavender_and_closed(self):
        app = cli.SSLDoctorCLI()
        buf = io.StringIO()
        with mock.patch.object(cli, "_MODE", cli.ColorMode.TRUECOLOR), \
                mock.patch.object(cli, "_GLYPHS", cli.Glyphs()), \
                mock.patch("builtins.input", return_value="no"), \
                mock.patch.dict(os.environ, {"COLUMNS": "80"}), \
                contextlib.redirect_stdout(buf):
            app.prompt("Run authorized server-side checks (SSH)? (yes/no)", "no")
        raw = buf.getvalue()
        self.assertIn("\x1b[38;2;177;185;249m", raw)  # lavender accent
        out = stripped(raw)
        self.assertIn("[Y]es  [N]o", out)
        self.assertIn("default: no", out)
        self.assertEqual(out.count("┌"), 1)
        self.assertEqual(out.count("└"), 1)


class SpinnerBehaviour(unittest.TestCase):
    """4.2 / 4.3 — one plain line when redirected, clean stop otherwise."""

    def test_plain_mode_prints_one_line(self):
        buf = io.StringIO()
        with mock.patch.object(cli, "_MODE", cli.ColorMode.PLAIN), \
                mock.patch.object(cli, "_GLYPHS", cli.Glyphs(False, False)), \
                contextlib.redirect_stdout(buf):
            with cli.Spinner("inspecting leaf.pem", verb="chaining"):
                pass
        lines = [line for line in buf.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(lines), 1)
        self.assertIn("inspecting leaf.pem", lines[0])
        self.assertNotIn("\r", buf.getvalue())
        self.assertNotIn("\x1b", buf.getvalue())

    def test_frame_cycle_is_reverse_mirror(self):
        self.assertEqual(cli.SPINNER_CYCLE[:6], cli.SPINNER_FRAMES)
        self.assertEqual(cli.SPINNER_CYCLE[6:], ["✻", "✶", "✳", "✢"])

    def test_interrupt_clears_the_line(self):
        stream = FakeTerminal()
        with mock.patch.object(cli, "_MODE", cli.ColorMode.TRUECOLOR), \
                mock.patch.object(cli, "_GLYPHS", cli.Glyphs()), \
                mock.patch.object(cli.sys, "stdout", stream), \
                self.assertRaises(KeyboardInterrupt):
            with cli.Spinner("checking", verb="chaining"):
                raise KeyboardInterrupt
        self.assertTrue(stream.getvalue().endswith("\r\x1b[K"))


class PlainModeContract(unittest.TestCase):
    """Full commands stay escape-free and pipe friendly."""

    def test_batch_commands_emit_no_escapes(self):
        buf = io.StringIO()
        env = {k: v for k, v in os.environ.items() if k != "NO_COLOR"}
        with mock.patch.dict(os.environ, env, clear=True), \
                contextlib.redirect_stdout(buf):
            code = cli.main(["-c", "/help", "-c", "/version", "-c", "/findings"])
        self.assertEqual(code, 0)
        out = buf.getvalue()
        self.assertNotIn("\x1b", out)
        self.assertIn("creator: eleven", out)
        self.assertIn("/server nginx", out)




class StartupBanner(unittest.TestCase):
    """The wordmark banner: two-stroke art, width honesty, fixed credit."""

    def render(self, columns, mode=cli.ColorMode.PLAIN, glyphs=None):
        original = cli._MODE
        self.addCleanup(cli.set_color_mode, original)
        glyphs = glyphs or cli.Glyphs(mode != cli.ColorMode.PLAIN,
                                      mode != cli.ColorMode.PLAIN)
        with mock.patch.object(cli, "_MODE", mode), mock.patch.object(cli, "_GLYPHS", glyphs):
            return cli.banner_lines(columns)

    def test_wordmark_is_five_rows_of_two_stroke_letters(self):
        rows = cli.wordmark("SSL DOCTOR", "#")
        self.assertEqual(len(rows), cli.WORDMARK_ROWS)
        self.assertEqual(max(len(row) for row in rows), 64)
        # every glyph is six columns wide and every stem is two characters wide
        for letter, glyph in cli.WORDMARK.items():
            with self.subTest(letter=letter):
                self.assertEqual(len(glyph), cli.WORDMARK_ROWS)
                self.assertTrue(all(len(row) == 6 for row in glyph))
        self.assertEqual(cli.WORDMARK["L"][0].rstrip(), "##")
        self.assertEqual(cli.WORDMARK["T"][1], "  ##  ")

    def test_full_banner_on_a_wide_terminal(self):
        lines = self.render(80, cli.ColorMode.TRUECOLOR, cli.Glyphs())
        plain = [stripped(line) for line in lines]
        art = [line for line in plain if "█" in line]
        self.assertEqual(len(art), cli.WORDMARK_ROWS)
        text = "\n".join(plain)
        self.assertIn("offline ssl/tls diagnostics", text)
        self.assertIn("client", text)
        self.assertIn("nginx", text)
        self.assertIn(cli.BANNER_NOTE, text)
        self.assertIn("creator: eleven", text)
        self.assertIn("v0.6.0", text)
        self.assertEqual(plain[0], "═" * len(plain[0]))
        self.assertEqual(plain[-1], "═" * len(plain[-1]))
        self.assertEqual(plain[0], plain[-1])

    def test_compact_banner_when_narrow(self):
        lines = self.render(40)
        plain = [stripped(line) for line in lines]
        text = "\n".join(plain)
        self.assertNotIn("█", text)
        self.assertNotIn("#", text)
        self.assertIn("SSL DOCTOR", text)
        self.assertIn("offline ssl/tls diagnostics", text)
        self.assertIn("creator: eleven", text)
        self.assertIn("v0.6.0", text)

    def test_no_line_is_wider_than_the_terminal(self):
        for columns in (30, 40, 60, 72, 80, 100, 120):
            for line in self.render(columns):
                with self.subTest(columns=columns, line=stripped(line)):
                    self.assertLessEqual(len(stripped(line)), max(columns, 20))

    def test_credit_is_present_at_every_width(self):
        for columns in (30, 40, 72, 80, 132):
            with self.subTest(columns=columns):
                self.assertIn("creator: eleven",
                              "\n".join(stripped(line) for line in self.render(columns)))

    def test_plain_banner_is_ascii_and_escape_free(self):
        lines = self.render(80)
        for line in lines:
            self.assertNotIn("\x1b", line)
            line.encode("ascii")  # must survive a cp1252/ascii console
        self.assertIn("#", "\n".join(lines))
        self.assertTrue(all(not line.endswith(" ") for line in lines))

    def test_colour_banner_uses_roles(self):
        lines = self.render(80, cli.ColorMode.TRUECOLOR, cli.Glyphs())
        joined = "\n".join(lines)
        self.assertIn("\x1b[38;2;215;119;87m", joined)  # primary: rules + wordmark
        self.assertIn("\x1b[38;2;177;185;249", joined)  # accent: creator credit

    def test_banner_is_printed_once_per_run(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cli.main(["-c", "/version"])
        self.assertEqual(buf.getvalue().count("creator: eleven"), 1)
        self.assertIn("SSL Doctor v", buf.getvalue())  # /version output unchanged


class ReportSkin(unittest.TestCase):
    """5.1 / 5.2 — same content, restyled, self-contained and legible."""

    def payload(self):
        items = [
            F.Finding("tls.chain", "chain", F.FAIL, F.SCOPE_REMOTE_NET, ["only the leaf"]),
            F.Finding("tls.handshake", "handshake", F.PASS, F.SCOPE_REMOTE_NET, ["TLS 1.3"]),
            F.Finding("local.clock", "clock", F.NOT_TESTED, F.SCOPE_LOCAL, ["no server time"]),
        ]
        from ssl_doctor.analyze import diagnose
        return report.build_payload(items, diagnose(items, {}), {"target": "fixture"})

    def test_report_is_self_contained(self):
        html = report.html_from_payload(self.payload())
        for needle in ("http://", "https://", "<script", "@import", "src="):
            self.assertNotIn(needle, html)
        self.assertIn("<style>", html)

    def test_every_rendered_class_has_a_rule(self):
        html = report.html_from_payload(self.payload())
        classes = set()
        for match in re.finditer(r'class="([^"]+)"', html):
            classes.update(match.group(1).split())
        for name in classes:
            with self.subTest(cls=name):
                self.assertIn("." + name, report._CSS)

    def test_palette_colours_are_used(self):
        html = report.html_from_payload(self.payload())
        for colour in ("#d77757", "#fd5db1", "#4eba65", "#ffc107", "#ff6b80"):
            self.assertIn(colour, report._CSS)

    def test_status_labels_are_unchanged(self):
        html = report.html_from_payload(self.payload())
        for status in ("PASS", "FAIL", "NOT TESTED"):
            self.assertIn(status, html)

    def test_contrast_meets_wcag_aa(self):
        def luminance(hex_colour):
            channels = [int(hex_colour[i:i + 2], 16) / 255 for i in (1, 3, 5)]
            linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
                      for c in channels]
            return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

        def ratio(a, b):
            la, lb = sorted((luminance(a), luminance(b)), reverse=True)
            return (la + 0.05) / (lb + 0.05)

        self.assertGreaterEqual(ratio("#1f2328", "#ffffff"), 4.5)  # body on card
        for pill in ("#4eba65", "#ffc107", "#ff6b80", "#888888"):
            with self.subTest(pill=pill):
                self.assertGreaterEqual(ratio("#1a1a1a", pill), 4.5)


if __name__ == "__main__":
    unittest.main()
