"""Mouse selection in the full-screen shell: layout map, highlight, copy, Ctrl-Y.

The real renderer and session are driven with scripted keys; mouse cells are
computed from the layout map the renderer reports, so the tests follow the
layout instead of hard-coding screen rows.
"""

from __future__ import annotations

import io
import re
import unittest

from ssl_doctor import __version__, cli, tui
from ssl_doctor.tui import MouseEvent

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
LINES = ["first line of output", "  │ ✓ PASS   tls.chain   chain complete      │",
         "  │   • SHA-256 ab12cd34ef56                   │", "last line"]


class Keys:
    """Scripted keys; when they run out, records the session's notice (what the
    composer shows at that moment) and ends input."""

    def __init__(self, keys=()):
        self.keys = list(keys)
        self.session = None
        self.notice_at_end = None

    def read_key(self):
        if self.keys:
            return self.keys.pop(0)
        if self.session is not None:
            self.notice_at_end = list(self.session.notice)
        return "ctrl-d"


class Shell(unittest.TestCase):

    def setUp(self):
        original = cli._MODE
        self.addCleanup(cli.set_color_mode, original)
        cli.set_color_mode(cli.ColorMode.TRUECOLOR)
        cli._GLYPHS = cli.Glyphs(True, True)
        self.copied = []
        self.app = cli.SSLDoctorCLI()
        self.session = tui.TuiSession(
            renderer=self.app._tui_frame, stream=io.StringIO(), keys=Keys(),
            on_copy=lambda text: (self.copied.append(text),
                                  f"copied {len(text)} chars · xclip")[1],
            last_response=lambda: self.app._last_response)
        self.session.screen.active = False
        self.session.keys.session = self.session
        self.session.size = lambda: (100, 30)
        for line in LINES:
            self.session.transcript.append(line)

    def frame(self):
        return self.app._tui_frame(self.session)

    def cell(self, row, col):
        """Screen cell (1-based x, y) of transcript-visible row `row`, column `col`."""
        self.frame()
        lay = self.session.layout
        return lay["left"] + col, lay["body_top"] + row

    def drive(self, *keys):
        self.session.keys.keys = list(keys) + ["enter"]
        self.frame()
        return self.session.read_line()


class LayoutMap(Shell):

    def test_the_map_points_at_the_drawn_transcript(self):
        for columns, rows in ((100, 30), (80, 24), (60, 20)):
            with self.subTest(columns=columns, rows=rows):
                self.session.size = lambda c=columns, r=rows: (c, r)
                lines = [ANSI.sub("", line) for line in self.frame()[0]]
                lay = self.session.layout
                first = lines[lay["body_top"] - 1]
                self.assertEqual(first[lay["left"] - 1:].rstrip(), LINES[0])
                self.assertEqual(lay["body_rows"], len(LINES))
                self.assertEqual(lay["start"], 0)

    def test_a_scrolled_transcript_maps_to_the_rows_it_shows(self):
        for index in range(60):
            self.session.transcript.append(f"row {index}")
        self.session.scroll = 10
        lines = [ANSI.sub("", line) for line in self.frame()[0]]
        lay = self.session.layout
        wrapped = self.session.transcript.wrapped(lay["width"])
        second = lines[lay["body_top"]][lay["left"] - 1:].rstrip()   # row 0 is the scroll note
        self.assertEqual(second, wrapped[lay["start"] + 1])
        x, y = lay["left"], lay["body_top"] + 1
        self.assertEqual(self.session.cell_at(x, y), (lay["start"] + 1, 0))

    def test_cells_outside_the_transcript_are_not_selectable(self):
        self.frame()
        lay = self.session.layout
        self.assertIsNone(self.session.cell_at(lay["left"], 1))                    # banner
        self.assertIsNone(self.session.cell_at(lay["left"], lay["body_top"] + 10))  # composer
        # a drag that leaves the transcript pins to its first/last row
        self.assertEqual(self.session.cell_at(lay["left"], 1, clamp=True), (0, 0))
        self.assertEqual(self.session.cell_at(lay["left"], 29, clamp=True),
                         (len(LINES) - 1, lay["width"] - 1))


class Highlight(Shell):

    def test_only_the_selected_cells_are_reversed(self):
        self.frame()
        self.session.selection = tui.Selection((1, 4), (1, 9), self.session.layout["width"])
        lines, _ = self.frame()
        lay = self.session.layout
        row = lines[lay["body_top"]]          # visible row 1
        self.assertEqual(row.count("\x1b[7m"), 1)
        reversed_text = ANSI.sub("", row.split("\x1b[7m", 1)[1].split("\x1b[27m", 1)[0])
        self.assertEqual(reversed_text, LINES[1][4:10])
        self.assertEqual(sum("\x1b[7m" in line for line in lines), 1)
        self.assertEqual({len(ANSI.sub("", line)) for line in lines}, {100})

    def test_a_multi_row_selection_reverses_to_the_row_ends(self):
        self.frame()
        width = self.session.layout["width"]
        self.session.selection = tui.Selection((2, 6), (0, 6), width)   # dragged upwards
        spans = self.session.highlight(0, len(LINES), width)
        self.assertEqual(spans, {0: (6, width), 1: (0, width), 2: (0, 7)})

    def test_reverse_video_is_shown_without_colour(self):
        cli.set_color_mode(cli.ColorMode.PLAIN)
        self.frame()
        self.session.selection = tui.Selection((0, 0), (0, 4), self.session.layout["width"])
        lines, _ = self.frame()
        self.assertTrue(any("\x1b[7mfirst\x1b[27m" in line for line in lines))


class DragToCopy(Shell):

    def test_drag_across_two_rows_copies_what_is_shown(self):
        press, drag = self.cell(1, 6), self.cell(2, 20)
        self.drive(MouseEvent("press", *press), MouseEvent("drag", *drag),
                   MouseEvent("release", *drag))
        self.assertEqual(self.copied, [LINES[1][6:].rstrip() + "\n" + LINES[2][:21].rstrip()])

    def test_a_fingerprint_is_copied_exactly(self):
        start = LINES[2].index("ab12")
        a, b = self.cell(2, start), self.cell(2, start + len("ab12cd34ef56") - 1)
        self.session.keys.keys = [MouseEvent("press", *a), MouseEvent("drag", *b),
                                  MouseEvent("release", *b)]
        self.frame()
        self.session.read_line()
        self.assertEqual(self.copied, ["ab12cd34ef56"])
        self.assertIn("copied 12 chars", self.session.keys.notice_at_end[0][0])

    def test_the_confirmation_appears_in_the_composer(self):
        a, b = self.cell(0, 0), self.cell(0, 4)
        self.session.keys.keys = [MouseEvent("press", *a), MouseEvent("drag", *b),
                                  MouseEvent("release", *b)]
        self.frame()
        rendered = []
        original = self.session.render
        self.session.render = lambda: (original(), rendered.append(
            [ANSI.sub("", line) for line in self.frame()[0]]))
        self.session.read_line()
        composer_tops = [next(line for line in frame if "╭" in line) for frame in rendered]
        self.assertTrue(any("╭─ copied 5 chars · xclip " in top for top in composer_tops))

    def test_a_click_copies_nothing_and_clears(self):
        self.session.selection = tui.Selection((0, 0), (0, 3), 96)
        x, y = self.cell(1, 3)
        self.drive(MouseEvent("press", x, y), MouseEvent("release", x, y))
        self.assertEqual(self.copied, [])
        self.assertIsNone(self.session.selection)

    def test_a_drag_into_the_composer_stops_at_the_last_row(self):
        a = self.cell(2, 2)
        self.drive(MouseEvent("press", *a), MouseEvent("drag", a[0], 29),
                   MouseEvent("release", a[0], 29))
        self.assertEqual(self.copied, [LINES[2][2:].rstrip() + "\n" + LINES[3]])

    def test_pressing_on_the_banner_starts_no_selection(self):
        self.drive(MouseEvent("press", 10, 2), MouseEvent("drag", 20, 2),
                   MouseEvent("release", 20, 2))
        self.assertEqual(self.copied, [])

    def test_typing_after_a_copy_clears_selection_and_notice(self):
        a, b = self.cell(0, 0), self.cell(0, 4)
        self.assertEqual(self.drive(MouseEvent("press", *a), MouseEvent("drag", *b),
                                    MouseEvent("release", *b), "x"), "x")
        self.assertIsNone(self.session.selection)
        self.assertEqual(self.session.notice, [])


class CtrlY(Shell):

    def test_ctrl_y_copies_the_previous_response_and_keeps_the_input(self):
        self.app._last_response = f"SSL Doctor v{__version__}"
        line = self.drive(*"/diag", "ctrl-y")
        self.assertEqual(self.copied, [f"SSL Doctor v{__version__}"])
        self.assertEqual(line, "/diag")
        self.assertEqual(self.session.history, ["/diag"])     # Ctrl-Y added nothing

    def test_ctrl_y_with_nothing_to_copy(self):
        self.session.keys.keys = ["ctrl-y"]
        self.frame()
        self.session.read_line()
        self.assertEqual(self.copied, [])
        self.assertIn("nothing to copy yet", self.session.keys.notice_at_end[0][0])

    def test_ctrl_y_is_decoded(self):
        reader = tui.KeyReader(stream=io.StringIO())
        reader._windows = False
        self.assertEqual(reader._decode_bytes(b"\x19"), "ctrl-y")

    def test_the_hint_names_the_copy_keys(self):
        self.session.size = lambda: (120, 30)
        lines = [ANSI.sub("", line) for line in self.frame()[0]]
        bottom = next(line for line in lines if "╰" in line)
        self.assertIn("drag or Ctrl-Y copies", bottom)


if __name__ == "__main__":
    unittest.main()


class WindowsConsoleInput(unittest.TestCase):
    """The Windows reader: console records read under a raw VT input mode."""

    class Kernel32:
        """A console input buffer: key records for text, plus mouse records.

        Records are read only through ReadConsoleInputW, and the mode in force
        at each read is recorded -- `msvcrt.getwch` forced it to 0, which is
        what kept mouse reports from ever arriving (the field bug).
        """

        def __init__(self, records=(), mode=0x01F7):
            self.mode, self.sets, self.read_modes = mode, [], []
            self.records = list(records)

        def GetStdHandle(self, which):
            return 10

        def GetConsoleMode(self, handle, mode_ref):
            mode_ref._obj.value = self.mode
            return 1

        def SetConsoleMode(self, handle, mode):
            self.sets.append(mode)
            self.mode = mode
            return 1

        def GetNumberOfConsoleInputEvents(self, handle, count_ref):
            count_ref._obj.value = len(self.records)
            return 1

        def WaitForSingleObject(self, handle, ms):
            return 0 if self.records else 0x102           # WAIT_TIMEOUT

        def ReadConsoleInputW(self, handle, record_ref, length, count_ref):
            if not self.records:
                return 0
            self.read_modes.append(self.mode)
            kind, fields = self.records.pop(0)
            record = record_ref._obj
            record.EventType = kind
            target = record.Event.KeyEvent if kind == tui._KEY_EVENT else record.Event.MouseEvent
            for name, value in fields.items():
                setattr(target, name, value)
            count_ref._obj.value = 1
            return 1

    @staticmethod
    def keys(text):
        return [(tui._KEY_EVENT, {"bKeyDown": 1, "UnicodeChar": ord(c), "wVirtualKeyCode": 0})
                for c in text]

    @staticmethod
    def vkey(code):
        return (tui._KEY_EVENT, {"bKeyDown": 1, "UnicodeChar": 0, "wVirtualKeyCode": code})

    @staticmethod
    def mouse(x, y, buttons=0, flags=0):
        return (tui._MOUSE_EVENT, {"X": x, "Y": y, "dwButtonState": buttons,
                                   "dwEventFlags": flags})

    def reader(self, records, kernel32=None):
        reader = tui.KeyReader(stream=io.StringIO())
        reader._windows = True
        reader.kernel32 = kernel32 or self.Kernel32(records)
        return reader

    def test_mouse_reports_are_decoded_not_typed(self):
        reader = self.reader(self.keys("\x1b[<0;12;5M\x1b[<32;20;6M\x1b[<0;20;6m\x1b[<64;1;1M"))
        self.assertEqual([reader.read_key() for _ in range(4)],
                         [MouseEvent("press", 12, 5), MouseEvent("drag", 20, 6),
                          MouseEvent("release", 20, 6), "wheelup"])

    def test_records_are_read_in_raw_vt_mode(self):
        # regression: msvcrt.getwch reset the mode to 0 while it read, so the
        # console never sent wheel/drag reports and Windows Terminal kept them
        kernel32 = self.Kernel32(self.keys("a"), mode=0x01F7)
        reader = self.reader(None, kernel32)
        self.assertEqual(reader.read_key(), "a")
        [mode] = kernel32.read_modes
        self.assertTrue(mode & tui._ENABLE_VT_INPUT)
        self.assertFalse(mode & 0x0007)                     # no line/echo/processed input
        # raw VT input, plus Quick Edit off / mouse input on so conhost and winpty
        # deliver the wheel (test_terminal_profiles); the original mode comes back
        expected = ((0x01F7 & ~0x0007) | 0x0200 | 0x0010 | 0x0080) & ~0x0040
        self.assertEqual(kernel32.sets, [expected, 0x01F7])

    def test_native_mouse_records_scroll_and_select(self):
        # a report that arrives between keys (VT input off) is a MOUSE_EVENT record
        reader = self.reader([
            self.mouse(0, 0, buttons=0x00780000, flags=tui._MOUSE_WHEELED),
            self.mouse(0, 0, buttons=0xFF880000, flags=tui._MOUSE_WHEELED),
            self.mouse(11, 4, buttons=1),
            self.mouse(19, 5, buttons=1, flags=tui._MOUSE_MOVED),
            self.mouse(19, 5, flags=tui._MOUSE_MOVED),      # hover: skipped
            self.mouse(19, 5, buttons=0),
        ] + self.keys("z"))
        self.assertEqual([reader.read_key() for _ in range(6)],
                         ["wheelup", "wheeldown", MouseEvent("press", 12, 5),
                          MouseEvent("drag", 20, 6), MouseEvent("release", 20, 6), "z"])

    def test_keys_still_decode(self):
        records = self.keys("\x1b[A\x1bOB\x1b[5~") + [self.vkey(0x25)] + self.keys("x\x03\x1b")
        records.insert(1, (tui._KEY_EVENT, {"bKeyDown": 0, "UnicodeChar": 0x1b}))  # key-up: skipped
        reader = self.reader(records)
        self.assertEqual([reader.read_key() for _ in range(7)],
                         ["up", "down", "pageup", "left", "x", "ctrl-c", "escape"])

    def test_surrogate_pairs_are_one_key(self):
        reader = self.reader(self.keys("\ud83d\udd12"))
        self.assertEqual(reader.read_key(), "\U0001F512")

    def test_a_console_without_modes_still_reads_keys(self):
        class NoConsole(self.Kernel32):
            def GetConsoleMode(self, handle, mode_ref):
                return 0
        kernel32 = NoConsole(self.keys("q"))
        reader = self.reader(None, kernel32)
        self.assertEqual(reader.read_key(), "q")
        self.assertEqual(kernel32.sets, [])                 # nothing to restore
