"""Result frames stay intact at every width the shell is drawn at.

Regression cover for two field bugs: a frame was baked into the transcript at
the width the command ran with, so narrowing the window re-wrapped its border
rows (the right edge broke onto the next row); and every width was counted in
code points, so a CJK or emoji character (an IDN host, a certificate subject)
pushed the right border one cell out per wide character.
"""

from __future__ import annotations

import contextlib
import io
import unicodedata
import unittest

from ssl_doctor import cli, findings as F, textcells, tui


def cells(text: str) -> int:
    """Terminal cells, computed independently of the code under test."""
    total = 0
    for char in text:
        if unicodedata.combining(char) or char in "‍️":
            continue
        total += 2 if unicodedata.east_asian_width(char) in "WF" else 1
    return total


PASSING = F.Finding("tls.version", "Negotiated protocol is TLS 1.2 or newer", F.PASS,
                    F.SCOPE_REMOTE_NET, ["negotiated TLSv1.3 with TLS_AES_256_GCM_SHA384"],
                    recommendation="nothing to do; keep TLS 1.0 and 1.1 disabled")
WIDE = F.Finding("tls.hostname", "主机名 covered by the SAN of 证书 ✅", F.WARNING,
                 F.SCOPE_REMOTE_NET, ["subject CN=例え.jp, SAN DNS:例え.jp, DNS:www.例え.jp"])


class FrameCase(unittest.TestCase):
    unicode = True

    def setUp(self):
        self._glyphs = cli._GLYPHS
        cli._GLYPHS = cli.Glyphs(self.unicode, self.unicode)
        self.addCleanup(setattr, cli, "_GLYPHS", self._glyphs)
        self.addCleanup(cli.set_capture_width, 0)
        self.addCleanup(cli.set_block_label, "")

    def capture(self, width, items, label="/tls example.com", live=False):
        """What the shell's transcript receives for one command."""
        cli.set_capture_width(width)
        cli.set_block_label(label)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            if live:                                   # a frame still streaming
                frame = cli.LiveFrame("checking TLS").open()
                for f in items:
                    frame.add(f)
            else:
                cli.print_findings(items)
        transcript = tui.Transcript()
        transcript.append("ssl-doctor> /tls example.com")
        for line in out.getvalue().splitlines():
            transcript.append(line)
        transcript.append("")
        return transcript

    def frame_rows(self, rows):
        bars = ("│", "|") if self.unicode else ("|",)
        return [r for r in rows if r.lstrip()[:1] in ("╭", "╰", "+") + bars]

    def assertIntact(self, rows, width, closed=True):
        frame = self.frame_rows(rows)
        self.assertTrue(frame, "no frame drawn")
        top, bottom = ("╭", "╮"), ("╰", "╯")
        bar = "│"
        if not self.unicode:
            top, bottom, bar = ("+", "+"), ("+", "+"), "|"
        self.assertEqual(frame[0].strip()[0], top[0])
        self.assertEqual(frame[0].rstrip()[-1], top[1])
        interior = frame[1:-1] if closed else frame[1:]
        for row in interior:
            self.assertEqual(row.strip()[0], bar, row)
            self.assertEqual(row.rstrip()[-1], bar, row)
        if closed:
            self.assertEqual(frame[-1].strip()[0], bottom[0])
            self.assertEqual(frame[-1].rstrip()[-1], bottom[1])
        self.assertEqual({cells(r) for r in frame}, {width - tui.FRAME_MARGIN},
                         "\n".join(frame))


class ResizedTranscript(FrameCase):

    def test_narrowing_the_window_redraws_the_frame_at_the_new_width(self):
        transcript = self.capture(100, [PASSING])
        self.assertIntact(transcript.wrapped(70), 70)

    def test_widening_the_window_stretches_the_frame(self):
        transcript = self.capture(60, [PASSING])
        self.assertIntact(transcript.wrapped(118), 118)

    def test_every_width_from_narrow_to_wide_is_intact(self):
        transcript = self.capture(100, [PASSING, WIDE])
        for width in range(16, 121):
            with self.subTest(width=width):
                self.assertIntact(transcript.wrapped(width), width)

    def test_a_streaming_frame_without_its_base_is_redrawn_too(self):
        transcript = self.capture(100, [PASSING], live=True)
        self.assertIntact(transcript.wrapped(64), 64, closed=False)

    def test_no_text_is_lost_when_a_frame_is_narrowed(self):
        transcript = self.capture(100, [PASSING])
        words = lambda rows: "".join("".join(rows).split()).replace("│", "").replace("─", "")
        narrow = words(transcript.wrapped(50))
        for word in ("TLS_AES_256_GCM_SHA384", "Negotiated", "disabled", "tls.version"):
            self.assertIn(word, narrow)

    def test_wrapped_rows_hang_under_their_text(self):
        transcript = self.capture(100, [PASSING])
        rows = [r.strip()[1:-1].rstrip() for r in self.frame_rows(transcript.wrapped(64))[1:-1]]
        title_at = rows[0].index("Negotiated")
        self.assertEqual(len(rows[1]) - len(rows[1].lstrip()), title_at)   # title continues
        bullet = next(i for i, r in enumerate(rows) if "negotiated TLSv1.3" in r)
        evidence = rows[bullet + 1]
        self.assertEqual(len(evidence) - len(evidence.lstrip()),
                         rows[bullet].index("negotiated"))                 # past the bullet

    def test_lines_outside_a_frame_still_wrap_as_text(self):
        transcript = self.capture(100, [PASSING])
        self.assertEqual(transcript.wrapped(70)[0], "ssl-doctor> /tls example.com")

    def test_the_frame_is_not_redrawn_when_the_width_is_unchanged(self):
        transcript = self.capture(100, [PASSING])
        frame = self.frame_rows(transcript.lines)
        self.assertEqual(self.frame_rows(transcript.wrapped(100 + tui.FRAME_MARGIN)), frame)


class ResizedTranscriptAscii(ResizedTranscript):
    unicode = False


class WideCharacters(FrameCase):

    def test_wide_characters_keep_the_right_border_straight(self):
        transcript = self.capture(100, [WIDE])
        self.assertIntact(transcript.lines, 100 + tui.FRAME_MARGIN)

    def test_wide_characters_wrap_by_cells(self):
        transcript = self.capture(40, [WIDE])
        self.assertIntact(transcript.lines, 40 + tui.FRAME_MARGIN)

    def test_a_wide_title_is_cut_on_a_cell_boundary(self):
        transcript = self.capture(40, [PASSING], label="/tls " + "例" * 40)
        self.assertIntact(transcript.lines, 40 + tui.FRAME_MARGIN)


class CellHelpers(unittest.TestCase):

    def test_width_counts_terminal_cells(self):
        self.assertEqual(textcells.width("abc"), 3)
        self.assertEqual(textcells.width("例え"), 4)
        self.assertEqual(textcells.width("é"), 1)          # combining accent
        self.assertEqual(textcells.width("✅"), 2)

    def test_clip_never_splits_a_wide_character(self):
        self.assertEqual(textcells.clip("a例b", 2), "a")
        self.assertEqual(textcells.clip("a例b", 3), "a例")

    def test_wrap_breaks_long_words_by_cells(self):
        rows = textcells.wrap("例" * 7, 4)
        self.assertEqual(rows, ["例例", "例例", "例例", "例"])

    def test_wrap_keeps_words_whole_when_they_fit(self):
        self.assertEqual(textcells.wrap("alpha beta gamma", 10), ["alpha beta", "gamma"])

    def test_slice_selects_by_column(self):
        self.assertEqual(textcells.slice("a例bc", 1, 3), "例")
        self.assertEqual(textcells.slice("a例bc", 3, 5), "bc")


if __name__ == "__main__":
    unittest.main()
