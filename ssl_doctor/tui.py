"""Full-screen application shell for SSL Doctor.

The interactive session runs inside the terminal's alternate screen as a
left-aligned, terminal-like log under a centred banner: the transcript, then a
rounded chat-style composer whose top border carries the label and status and
whose bottom border carries the key hints, with a three-row completion menu.
Output is captured into a scrollback the renderer draws, so the wheel and
PageUp/PageDown can walk it, but it is laid out the way a terminal lays out a
log -- same left gutter, wrapping at the right edge, never centred.

This module owns presentation only.  It never imports the check code: the CLI
passes in a renderer, a capture stream and the command handler, which keeps the
same ``execute()`` dispatch serving both presentations.

Stdlib only: ``termios``/``select`` on POSIX, console input records through
``ctypes`` on Windows.  When
neither is usable, :func:`enabled` returns ``False`` and the line-oriented REPL
runs instead.
"""

from __future__ import annotations

import codecs
import ctypes
import os
import re
import select
import shutil
import sys
import threading
import time
from typing import Callable, Dict, List, NamedTuple, Optional, Sequence, Tuple

from . import textcells

MIN_WIDTH = 40
MAX_WIDTH = 120          # beyond this a diagnostic sentence is hard to follow
GUTTER = 2               # every row starts here
FRAME_MARGIN = 2         # a result frame stops this many cells short of the column
ALT_SCREEN_ON = "\033[?1049h"
ALT_SCREEN_OFF = "\033[?1049l"
CURSOR_HIDE = "\033[?25l"
CURSOR_SHOW = "\033[?25h"
CLEAR_SCREEN = "\033[2J"
# SGR extended mouse reporting with button-event tracking (press, drag with a
# button held, release, wheel) -- only while the composer is reading. Any-motion
# tracking (?1003) is not used: hover events would redraw for nothing.
MOUSE_ON = "\033[?1002h\033[?1006h"
MOUSE_OFF = "\033[?1006l\033[?1002l"

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# how many wrapped body rows a PageUp/PageDown moves
PAGE_STEP = 10
# how many rows one wheel notch moves
WHEEL_STEP = 3
# how many completion rows the command bar shows
MENU_ROWS = 3
# the composer: top border (label, status), input row, bottom border (hints)
COMPOSER_ROWS = 3
# what the composer border says about the shell: waiting for a command,
# waiting for an answer, or running one (input is not accepted)
COMPOSER_ROLES = {"ready": "primary", "ask": "accent", "busy": "muted"}
HISTORY_LIMIT = 200


# Windows console input (ReadConsoleInputW)
_ENABLE_VT_INPUT = 0x0200
_CONSOLE_COOKED = 0x0001 | 0x0002 | 0x0004   # processed, line, echo input
_KEY_EVENT = 0x0001
_MOUSE_EVENT = 0x0002
_MOUSE_MOVED = 0x0001
_MOUSE_WHEELED = 0x0004
_WINDOWS_VKEYS = {0x26: "up", 0x28: "down", 0x27: "right", 0x25: "left",
                  0x24: "home", 0x23: "end", 0x21: "pageup", 0x22: "pagedown"}


class _KEY_EVENT_RECORD(ctypes.Structure):
    _fields_ = [("bKeyDown", ctypes.c_int32), ("wRepeatCount", ctypes.c_uint16),
                ("wVirtualKeyCode", ctypes.c_uint16), ("wVirtualScanCode", ctypes.c_uint16),
                ("UnicodeChar", ctypes.c_uint16), ("dwControlKeyState", ctypes.c_uint32)]


class _MOUSE_EVENT_RECORD(ctypes.Structure):
    _fields_ = [("X", ctypes.c_int16), ("Y", ctypes.c_int16),
                ("dwButtonState", ctypes.c_uint32), ("dwControlKeyState", ctypes.c_uint32),
                ("dwEventFlags", ctypes.c_uint32)]


class _INPUT_EVENT(ctypes.Union):
    _fields_ = [("KeyEvent", _KEY_EVENT_RECORD), ("MouseEvent", _MOUSE_EVENT_RECORD)]


class _INPUT_RECORD(ctypes.Structure):
    _fields_ = [("EventType", ctypes.c_uint16), ("Event", _INPUT_EVENT)]


class MouseEvent(NamedTuple):
    """A left-button event at a 1-based terminal cell: press, drag or release."""
    kind: str
    x: int
    y: int


# --------------------------------------------------------------- capabilities

def _posix_keys_available() -> bool:
    try:
        import termios  # noqa: F401
        import select as _select  # noqa: F401
    except Exception:
        return False
    return True


def _windows_keys_available() -> bool:
    try:
        import msvcrt  # noqa: F401
    except Exception:
        return False
    return True


def keys_available() -> bool:
    return _posix_keys_available() or _windows_keys_available()


def enabled(stream=None, stdin=None, env=None) -> bool:
    """True when the full-screen shell can and should be used."""
    env = os.environ if env is None else env
    stream = sys.stdout if stream is None else stream
    stdin = sys.stdin if stdin is None else stdin
    setting = (env.get("SSL_DOCTOR_TUI") or "").strip().lower()
    if setting in ("0", "false", "no", "off", "plain"):
        return False
    try:
        if not (stream.isatty() and stdin.isatty()):
            return False
    except Exception:
        return False
    term = (env.get("TERM") or "").strip().lower()
    if term == "dumb":
        return False
    return keys_available()


# ------------------------------------------------------------------ transcript

def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def visible_len(text: str) -> int:
    """Terminal cells, not code points: a CJK character or emoji takes two."""
    return textcells.width(strip_ansi(text))


def wrap_line(line: str, width: int) -> List[str]:
    """Wrap one output line to `width` columns, keeping its own indentation."""
    if width <= 0:
        return [line]
    if not line:
        return [""]
    indent = len(line) - len(line.lstrip(" "))
    indent = min(indent, max(0, width - 8))
    body = line[indent:]
    if not body:
        return [textcells.clip(line, width)]
    if textcells.width(line) <= width:
        return [line]
    lead = " " * indent
    return textcells.wrap(body.strip(), max(4, width), lead, lead)


# ------------------------------------------------------------ result frames
#
# Result frames reach the transcript as text drawn at the width the command ran
# with. A frame is redrawn at the current width whenever the transcript is laid
# out, so a resized window never re-wraps (and breaks) its border rows.

_FRAME_TOP = re.compile(r"^( *)([╭┌+])([─-])(?: (.*?) )?\3+([╮┐+])$")
_FRAME_BOTTOM = re.compile(r"^( *)([╰└+])([─-])(?: (.*?) )?\3+([╯┘+])$")
_FRAME_PAIRS = {"╭": "╮", "┌": "┐", "+": "+", "╰": "╯", "└": "┘"}
# a finding's first row: glyph, status, check id, title (continuations hang
# under the title; evidence continuations hang past their bullet)
_FRAME_STATUS = re.compile(r"^(\S\s+(?:PASS|FAIL|WARNING|NOT TESTED)\s+\S+\s+)\S")


def _frame_border(match, line: str) -> bool:
    return bool(match) and _FRAME_PAIRS.get(match.group(2)) == match.group(5)


def _frame_row(line: str, indent: str, bar: str) -> Optional[str]:
    """The content of an interior row (`│ content │`), or None."""
    head = indent + bar + " "
    if len(line) >= len(head) + 2 and line.startswith(head) and line.endswith(" " + bar):
        return line[len(head):-2]
    return None


def _frame_span(lines: Sequence[str], start: int) -> int:
    """End index of the frame whose top border is lines[start], or 0."""
    top = _FRAME_TOP.match(lines[start])
    if not _frame_border(top, lines[start]):
        return 0
    indent, h = top.group(1), top.group(3)
    bar = "│" if h == "─" else "|"
    end = start + 1
    while end < len(lines) and _frame_row(lines[end], indent, bar) is not None:
        end += 1
    if end < len(lines):
        bottom = _FRAME_BOTTOM.match(lines[end])
        if (_frame_border(bottom, lines[end]) and bottom.group(1) == indent
                and bottom.group(3) == h):
            return end + 1
    return end if end > start + 1 else 0          # a frame still streaming


def _fit_label(text: str, room: int, ellipsis: str) -> str:
    if textcells.width(text) <= room:
        return text
    if room <= textcells.width(ellipsis):
        return textcells.clip(text, room)
    return textcells.clip(text, room - textcells.width(ellipsis)) + ellipsis


def _fit_counts(text: str, room: int) -> str:
    """Counters for a narrower base: drop the zero counts, then cut."""
    if textcells.width(text) <= room:
        return text
    sep = " · " if " · " in text else " - "
    kept = [part for part in text.split(sep) if not part.startswith("0 ")]
    text = sep.join(kept) or text
    return textcells.clip(text, room)


def reflow_frame(lines: Sequence[str], width: int) -> List[str]:
    """Redraw a result frame so every row is exactly `width` cells.

    Borders are rebuilt to the width, interior rows re-padded, and a row too
    long for the new width is word-wrapped inside the frame (a finding's title
    hangs under itself). A frame that already fits is returned as it is.
    """
    if all(textcells.width(line) == width for line in lines):
        return list(lines)
    top = _FRAME_TOP.match(lines[0])
    indent, tl, h, title, tr = top.groups()
    unicode = h == "─"
    bar = "│" if unicode else "|"
    ellipsis = "…" if unicode else "..."
    if width - len(indent) < 12:
        indent = ""                               # a very narrow column keeps the box
    inner = max(1, width - len(indent) - 4)
    span = max(2, width - len(indent))           # corner to corner
    out: List[str] = []

    def border(left: str, right: str, label: str) -> str:
        if label and span - 6 >= 1:
            fill = span - 5 - textcells.width(label)
            return f"{indent}{left}{h} {label} {h * fill}{right}"
        return f"{indent}{left}{h * (span - 2)}{right}"

    out.append(border(tl, tr, _fit_label(title or "", span - 6, ellipsis)))
    end = len(lines)
    bottom = _FRAME_BOTTOM.match(lines[-1])
    closed = len(lines) > 1 and _frame_border(bottom, lines[-1])
    if closed:
        end -= 1
    for line in lines[1:end]:
        content = _frame_row(line, top.group(1), bar).rstrip()
        if textcells.width(content) <= inner:
            rows = [content]
        else:
            lead = len(content) - len(content.lstrip(" "))
            status = _FRAME_STATUS.match(content)
            hang = len(status.group(1)) if status else lead
            if content.lstrip(" ")[:2] in ("• ", "- "):   # evidence: hang past the bullet
                hang = lead + 2
            if inner - hang < 20:                 # too narrow to hang: start flush
                hang = min(lead, inner // 2)
            rows = textcells.wrap(content.lstrip(" "), inner, " " * lead, " " * hang)
        out.extend(f"{indent}{bar} {textcells.pad(row, inner)} {bar}" for row in rows)
    if closed:
        bl, footer, br = bottom.group(2), bottom.group(4) or "", bottom.group(5)
        out.append(border(bl, br, _fit_counts(footer, span - 6)))
    return out


class Transcript:
    """Ordered scrollback of everything a command printed."""

    def __init__(self) -> None:
        self.lines: List[str] = []
        self._partial = ""

    def __len__(self) -> int:
        return len(self.lines)

    def append(self, line: str = "") -> None:
        self.lines.append(strip_ansi(line.rstrip("\n")))

    def feed(self, text: str) -> None:
        """Accept stream writes, honouring CR overwrites and partial lines."""
        text = strip_ansi(text)
        buffer = self._partial + text
        self._partial = ""
        parts = buffer.split("\n")
        self._partial = parts.pop()
        for raw in parts:
            # a bare CR means "overwrite the current line" (spinner frames)
            self.lines.append(raw.rsplit("\r", 1)[-1] if "\r" in raw else raw)
        # a bare CR means "overwrite the current line" (spinner frames)
        if "\r" in self._partial:
            self._partial = self._partial.rsplit("\r", 1)[1]

    def flush_partial(self) -> None:
        if self._partial:
            self.lines.append(self._partial)
            self._partial = ""

    def wrapped(self, width: int) -> List[str]:
        """The rows drawn at `width`; result frames are redrawn to fit it."""
        out: List[str] = []
        lines, index = self.lines, 0
        frame_width = max(1, width - FRAME_MARGIN)
        while index < len(lines):
            end = _frame_span(lines, index) if lines[index][-1:] in "╮┐+" else 0
            if end:
                out.extend(reflow_frame(lines[index:end], frame_width))
                index = end
                continue
            out.extend(wrap_line(lines[index], width))
            index += 1
        return out

    def window(self, width: int, height: int, scroll: int = 0) -> Tuple[int, List[str]]:
        """(index of the first visible wrapped row, the visible rows)."""
        rows = self.wrapped(width)
        if height <= 0:
            return len(rows), []
        offset = max(0, min(scroll, max(0, len(rows) - height)))
        end = len(rows) - offset
        start = max(0, end - height)
        return start, rows[start:end]

    def tail(self, width: int, height: int, scroll: int = 0,
             fill: bool = True) -> List[str]:
        """Return up to `height` rows ending `scroll` rows above the newest line.

        With `fill=False` only the real lines are returned, so a caller can
        top-align them (the layout grows downward from the banner).
        """
        if height <= 0:
            return []
        _, visible = self.window(width, height, scroll)
        if fill:
            while len(visible) < height:
                visible.insert(0, "")
        return visible


# ---------------------------------------------------------------------- layout

Span = Tuple[str, str, bool]  # (text, role, bold)


def spans_plain(spans: Sequence[Span]) -> str:
    return "".join(span[0] for span in spans)


def _paint_spans(spans: Sequence[Span], painter) -> str:
    out = []
    for text, role, bold in spans:
        if role.startswith(f"{REVERSE}:"):
            # SGR 7 survives every colour mode, so a selection is always visible
            inner_role = role.split(":", 1)[1]
            body = painter(text, inner_role, bold) if (inner_role or bold) else text
            out.append(f"\033[7m{body}\033[27m")
        elif role or bold:
            out.append(painter(text, role, bold))
        else:
            out.append(text)
    return "".join(out)


def truncate_spans(spans: Sequence[Span], width: int) -> List[Span]:
    """Cut spans to `width` visible columns (spans never contain escapes)."""
    out: List[Span] = []
    room = width
    for text, role, bold in spans:
        if room <= 0:
            break
        size = textcells.width(text)
        if size > room:
            out.append((textcells.clip(text, room), role, bold))
            break
        out.append((text, role, bold))
        room -= size
    return out


REVERSE = "reverse"    # a pseudo-role: the painter is bypassed for these cells


def _reverse(spans: Sequence[Span], start: int, end: int) -> List[Span]:
    """Mark columns [start, end) of `spans` for reverse video (the selection)."""
    out: List[Span] = []
    column = 0
    for text, role, bold in spans:
        size = textcells.width(text)
        cut_a = max(0, min(size, start - column))
        cut_b = max(0, min(size, end - column))
        for piece, inside in ((textcells.slice(text, 0, cut_a), False),
                              (textcells.slice(text, cut_a, cut_b), True),
                              (textcells.slice(text, cut_b, size), False)):
            if piece:
                out.append((piece, f"{REVERSE}:{role}" if inside else role, bold))
        column += size
    return out


def block_width(columns: int) -> int:
    """Application column width: the terminal, capped for readability."""
    return max(20, min(columns, MAX_WIDTH))


def top_margin(rows: int) -> int:
    """One blank row above the header when the frame has the room for it."""
    return 1 if rows >= 20 else 0


def content_height(rows: int, header_len: int, menu: int = 0) -> int:
    """Rows available to the transcript between the header and the composer."""
    chrome = 1 + COMPOSER_ROWS + max(0, menu)  # a spacer above the composer
    return max(1, rows - top_margin(rows) - header_len - 1 - chrome)


def composer_border(left: Sequence[Span], right: Sequence[Span], inner: int,
            corners: Tuple[str, str], h: str, role: str) -> List[Span]:
    """`╭─ left ──── right ─╮`: labels set into a rule exactly `inner` wide.

    When room runs out the right label is dropped first, then the left is cut.
    """
    open_, close = corners
    room = inner - 4                                  # the two corner pairs
    left = truncate_spans(left, max(0, room - 2))
    used = textcells.width(spans_plain(left)) + 2 if left else 0  # " label "
    right_used = textcells.width(spans_plain(right)) + 2 if right else 0
    if used + right_used > room:
        right, right_used = [], 0
    spans: List[Span] = [(open_ + h, role, False)]
    if left:
        spans += [(" ", "", False), *left, (" ", "", False)]
    spans.append((h * (room - used - right_used), role, False))
    if right:
        spans += [(" ", "", False), *right, (" ", "", False)]
    spans.append((h + close, role, False))
    return spans


def build_frame(*, columns: int, rows: int, header: Sequence[Sequence[Span]],
                body: Sequence[str], status: Sequence[Span] = (),
                prompt_text: str = "", hints: Sequence[Span] = (),
                painter, glyphs, width: Optional[int] = None,
                cursor: int = 0, menu: Sequence[Sequence[Span]] = (),
                label: Sequence[Span] = (), placeholder: str = "",
                state: str = "ready",
                send: Sequence[Span] = (),
                layout: Optional[Dict[str, int]] = None,
                highlight: Optional[Dict[int, Tuple[int, int]]] = None
                ) -> Tuple[List[str], Tuple[int, int]]:
    """Compose one screen.

    The banner is centred in the column; the transcript, completion menu and
    composer are left-aligned on :data:`GUTTER`, the way a terminal log reads.
    The transcript grows downward from the header and the composer follows it,
    so a short session has no dead gap under the input.

    The composer is a rounded box: `label` and `status` sit in its top border,
    the typed text (or a dim `placeholder`) on its one input row, `hints` and
    `send` in its bottom border.  `state` picks the border colour from
    :data:`COMPOSER_ROLES`.  `cursor` is an index into the typed text; the input
    scrolls horizontally to keep it visible.  Returns (lines, (row, column)),
    both 1-based.

    `layout`, when given, receives where the transcript was drawn:
    `body_top` (1-based screen row of the first body row), `body_rows`,
    `left` (1-based column of the first text cell) and `width`.
    `highlight` maps a body row index to the (start, end) columns to draw in
    reverse video -- the mouse selection.
    """
    width = min(block_width(columns) if width is None else width, columns)
    gutter = min(GUTTER, max(0, width - 4))
    inner = max(4, width - gutter * 2)

    def pad(spans: Sequence[Span], fill: str = " ", align: str = "left") -> str:
        spans = truncate_spans(spans, width)
        text = spans_plain(spans)
        room = max(0, width - textcells.width(text))
        lead = room // 2 if align == "center" else 0
        trail = room - lead
        body_text = fill * lead + _paint_spans(spans, painter) + fill * trail
        return body_text + " " * max(0, columns - width)

    def row(spans: Sequence[Span]) -> str:
        """A gutter-indented row, truncated to the column."""
        return pad([(" " * gutter, "", False), *truncate_spans(spans, inner)])

    margin = top_margin(rows)
    limit = content_height(rows, len(header), len(menu))
    lines: List[str] = [""] * margin
    for span_line in header:
        lines.append(pad(span_line, align="center"))
    lines.append("")  # breathing room under the banner

    visible = [textcells.clip(line, inner) for line in list(body)[:limit]]
    if layout is not None:
        layout.update(body_top=len(lines) + 1, body_rows=len(visible),
                      left=gutter + 1, width=inner)
    for index, row_text in enumerate(visible):
        span = (highlight or {}).get(index)
        lines.append(row(_reverse(colorize(row_text), *span)) if span
                     else row(colorize(row_text)))

    if not visible or visible[-1].strip():
        lines.append("")  # the composer never touches the last output line

    # ---- completion menu (a dropdown on top of the composer) ---------------
    for menu_row in menu:
        lines.append(row(menu_row))

    # ---- composer ----------------------------------------------------------
    role = COMPOSER_ROLES.get(state, "primary")
    h, bar = glyphs.h, glyphs.vert
    mark = "❯ " if glyphs.unicode else "> "
    lines.append(row(composer_border(label, status, inner,
                             (glyphs.corner("╭", "+"), glyphs.corner("╮", "+")),
                             h, role)))
    field = max(1, inner - 4 - len(mark))          # "│ ❯ " + text + " │"
    # scroll so the cursor cell stays inside the field (measured in cells)
    start = 0
    while start < cursor and textcells.width(prompt_text[start:cursor + 1]) > field:
        start += 1
    shown = textcells.clip(prompt_text[start:], field)
    if shown:
        content: List[Span] = [(shown, "", False)]
    else:
        content = [(textcells.clip(placeholder, field), "muted", False)]
    gap = field - textcells.width(spans_plain(content))
    input_index = len(lines)
    lines.append(row([(bar, role, False), (" ", "", False),
                      (mark, COMPOSER_ROLES["ready"] if state == "ready" else role,
                       state == "ready"),
                      *content, (" " * gap + " ", "", False), (bar, role, False)]))
    lines.append(row(composer_border(hints, send, inner,
                             (glyphs.corner("╰", "+"), glyphs.corner("╯", "+")),
                             h, role)))

    while len(lines) < rows:
        lines.append(" " * columns)
    # pad on *visible* width: painted spans carry escape sequences
    padded = [line + " " * max(0, columns - visible_len(line)) for line in lines[:rows]]
    cursor_col = gutter + 2 + len(mark) + textcells.width(
        shown[:max(0, min(cursor - start, len(shown)))])
    return padded, (input_index + 1, cursor_col + 1)


_STATUS_ROLE_RE = re.compile(
    r"^(\[\s*(?:\+|x|!|\?)?\s*(PASS|FAIL|WARNING|NOT TESTED)\s*\])")
_STATUS_ROLES = {"PASS": "success", "FAIL": "error", "WARNING": "warning",
                 "NOT TESTED": "muted"}
# a row inside a result frame: " ✓ PASS   tls.version   ..."
_BOX_STATUS_RE = re.compile(r"^(\s*)([^\s])(\s+)(PASS|FAIL|WARNING|NOT TESTED)(\b)")
_COUNT_ROLES = ((re.compile(r"\d+ passed"), "success"),
                (re.compile(r"\d+ failed"), "error"),
                (re.compile(r"\d+ warnings"), "warning"),
                (re.compile(r"\d+ not tested"), "muted"))
_BOX_BARS = ("│", "|")
_BOX_TOP = ("╭", "┌", "+")
_BOX_BOTTOM = ("╰", "└", "+")
_BOX_TOP_RIGHT = ("╮", "┐", "+")
_BOX_BOTTOM_RIGHT = ("╯", "┘", "+")


def colorize(text: str) -> List[Span]:
    """Give a captured output line the right colours without changing its text."""
    boxed = _box_spans(text)
    if boxed is not None:
        return boxed
    return _colorize_text(text)


def _colorize_text(text: str, base: str = "") -> List[Span]:
    match = _STATUS_ROLE_RE.match(text)
    if match:
        head, status = match.group(1), match.group(2)
        return [(head, _STATUS_ROLES[status], True), (text[len(head):], base, False)]
    stripped = text.strip()
    lead = text[:len(text) - len(text.lstrip(" "))]
    if stripped.startswith("error:"):
        return [(text, "error", False)]
    if stripped.startswith("fix:") or stripped.startswith("report written:"):
        return [(text, "accent", False)]
    if stripped.startswith("Diagnosis") or stripped.startswith("SSL Doctor commands"):
        return [(text, "primary", True)]
    if stripped.startswith("next:") or stripped.startswith("interrupted"):
        return [(text, "muted", False)]
    if stripped.startswith(("•", "▸")):
        bullet = stripped[0]
        return [(lead + bullet, "muted", False), (text[len(lead) + 1:], base, False)]
    return [(text, base, False)]


def _colorize_interior(text: str) -> List[Span]:
    """Colour the inside of a frame row: status chip, bullets, fix text."""
    match = _BOX_STATUS_RE.match(text)
    if match:
        lead, glyph, gap, status = match.group(1, 2, 3, 4)
        head = lead + glyph + gap + status
        return [(head, _STATUS_ROLES[status], True),
                *(_colorize_text(text[len(head):]))]
    return _colorize_text(text)


def _colorize_counts(text: str) -> List[Span]:
    spans: List[Span] = []
    cursor = 0
    for match in re.finditer(r"\d+ (?:passed|failed|warnings|not tested)", text):
        if match.start() > cursor:
            spans.append((text[cursor:match.start()], "muted", False))
        role = next(role for pattern, role in _COUNT_ROLES
                    if pattern.fullmatch(match.group(0)))
        spans.append((match.group(0), role, False))
        cursor = match.end()
    if cursor < len(text):
        spans.append((text[cursor:], "muted", False))
    return spans


def _box_spans(text: str) -> Optional[List[Span]]:
    """Re-colour a row produced by the result frame, or None if it is not one."""
    core = text.strip()
    if len(core) < 2:
        return None
    first, last = core[0], core[-1]
    top = first in _BOX_TOP and last in _BOX_TOP_RIGHT and first != last
    bottom = first in _BOX_BOTTOM and last in _BOX_BOTTOM_RIGHT and first != last
    body = first in _BOX_BARS and last in _BOX_BARS
    if not (top or bottom or body):
        return None
    lead = text[:len(text) - len(text.lstrip(" "))]
    trail = text[len(text.rstrip(" ")):]
    inside = core[1:-1]
    spans: List[Span] = [(lead, "", False), (first, "tool", False)]
    if body:
        spans.extend(_colorize_interior(inside))
    else:
        # "─ title ─────" between the corners: the label is the first segment
        label_start = 2 if inside[:1] in ("─", "-") else 0
        marker = (" ─" if inside[:1] == "─" else " -") if inside[:1] in ("─", "-") else ""
        cut = inside.find(marker, label_start) if marker else -1
        if cut < 0:
            label, filler = inside, ""
        else:
            label, filler = inside[:cut], inside[cut:]
        border_prefix, label_text = inside[:label_start], label[label_start:]
        spans.append((border_prefix, "tool", False))
        if top:
            spans.append((label_text, "primary", True))
        else:
            spans.extend(_colorize_counts(label_text))
        spans.append((filler, "tool", False))
    spans.extend([(last, "tool", False), (trail, "", False)])
    return spans


class Screen:
    """Alternate-screen writer. Every failure leaves the terminal usable."""

    def __init__(self, stream=None) -> None:
        self.stream = sys.stdout if stream is None else stream
        self.active = False
        self._lock = threading.RLock()

    def size(self) -> Tuple[int, int]:
        try:
            size = shutil.get_terminal_size((80, 24))
        except Exception:
            return 80, 24
        return max(20, size.columns), max(8, size.lines)

    def enter(self) -> None:
        if self.active:
            return
        self.active = True
        self._write(ALT_SCREEN_ON + CURSOR_HIDE + CLEAR_SCREEN)

    def leave(self) -> None:
        if not self.active:
            return
        self.active = False
        self._write(MOUSE_OFF + CURSOR_SHOW + ALT_SCREEN_OFF)

    def mouse(self, on: bool) -> None:
        """Report wheel events; only while the command bar owns the keyboard.

        Left on, the bytes a wheel produces during a network check would queue
        up in the tty and be typed into the next command, so the shell turns
        reporting off the moment it hands the terminal back.
        """
        if not self.active:
            return
        self._write(MOUSE_ON if on else MOUSE_OFF)

    def draw(self, lines: Sequence[str], cursor: Tuple[int, int]) -> None:
        with self._lock:
            if not self.active:
                return
            chunks = [CURSOR_HIDE]
            for index, line in enumerate(lines, 1):
                chunks.append(f"\033[{index};1H{line}")
            row, column = cursor
            chunks.append(f"\033[{max(1, row)};{max(1, column)}H{CURSOR_SHOW}")
            self._write("".join(chunks))

    def _write(self, text: str) -> None:
        try:
            self.stream.write(text)
            self.stream.flush()
        except (OSError, ValueError):
            pass            # the terminal went away (closed pipe or stream); nothing to draw on


# ------------------------------------------------------------------- keyboard

class KeyReader:
    """Decode key presses from a raw terminal (POSIX or Windows)."""

    def __init__(self, stream=None) -> None:
        self.stream = sys.stdin if stream is None else stream
        self._fd = None
        try:
            self._fd = self.stream.fileno()
        except Exception:
            self._fd = None
        self._decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self._pending: List[str] = []
        self._saved = None
        self._windows = False
        self._console_mode = None        # Windows: input mode to restore after a key
        self._left_down = False          # Windows: left button state of MOUSE_EVENT records
        self.kernel32 = None             # injectable for tests
        try:
            import termios  # noqa: F401
        except Exception:
            self._windows = True

    # -- raw mode is entered for a single keystroke only
    def _raw(self) -> None:
        if self._windows:
            self._windows_vt_input(True)
            return
        if self._fd is None:
            return
        import termios
        import tty
        try:
            self._saved = termios.tcgetattr(self._fd)
            tty.setraw(self._fd, termios.TCSADRAIN)
            attrs = termios.tcgetattr(self._fd)
            attrs[3] |= termios.ISIG  # keep Ctrl-C as a real signal
            termios.tcsetattr(self._fd, termios.TCSADRAIN, attrs)
        except Exception:
            self._saved = None

    def _restore(self) -> None:
        if self._windows:
            self._windows_vt_input(False)
            return
        if self._saved is None or self._fd is None:
            return
        import termios
        try:
            termios.tcsetattr(self._fd, termios.TCSADRAIN, self._saved)
        except Exception:  # noqa: BLE001 - the tty is gone; there is no mode left to restore
            pass
        self._saved = None

    def read_key(self) -> str:
        if self._pending:
            return self._pending.pop(0)
        self._raw()
        try:
            key = self._read_key_raw()
        finally:
            self._restore()  # a command must never run with a raw terminal
        return key

    def _read_key_raw(self) -> str:
        if self._windows or self._fd is None:
            return self._read_key_windows()
        data = os.read(self._fd, 1)
        if not data:
            return "eof"
        if data == b"\x1b":
            more = b""
            while True:
                ready, _, _ = select.select([self._fd], [], [], 0.02)
                if not ready:
                    break
                chunk = os.read(self._fd, 1)
                more += chunk
                if chunk.isalpha() or chunk == b"~":
                    break
            return self._decode_escape(more)
        return self._decode_bytes(data)

    def _decode_escape(self, sequence: bytes):
        if sequence.startswith(b"[<"):
            return self._decode_mouse(sequence)
        mapping = {
            b"[A": "up", b"[B": "down", b"[C": "right", b"[D": "left",
            b"[H": "home", b"[F": "end", b"[1~": "home", b"[4~": "end",
            b"[7~": "home", b"[8~": "end",
            b"[5~": "pageup", b"[6~": "pagedown",
            b"OA": "up", b"OB": "down", b"OC": "right", b"OD": "left",
            b"OH": "home", b"OF": "end",
        }
        if sequence in mapping:
            return mapping[sequence]
        if sequence in (b"[Z",):
            return "backtab"
        if not sequence:
            return "escape"
        return "unknown"

    @staticmethod
    def _decode_mouse(sequence: bytes):
        """SGR report `[<b;x;yM` (press/drag) or `...m` (release).

        Left button only: 0 = press, 32 = drag (motion bit + left), any final
        `m` with the left button = release; 64/65 are the wheel.
        """
        try:
            button, x, y = (int(part) for part in sequence[2:-1].split(b";"))
        except ValueError:
            return "unknown"
        final = sequence[-1:]
        if final == b"M" and button in (64, 65):
            return "wheelup" if button == 64 else "wheeldown"
        if button & 3 != 0 or button & 64:          # middle/right buttons, wheel release
            return "unknown"
        if final == b"m":
            return MouseEvent("release", x, y)
        return MouseEvent("drag" if button & 32 else "press", x, y)

    def _decode_bytes(self, data: bytes) -> str:
        char = self._decoder.decode(data)
        if not char:
            return "pending"
        if char in ("\r", "\n"):
            return "enter"
        if char in ("\x7f", "\b"):
            return "backspace"
        if char == "\x03":
            return "ctrl-c"
        if char == "\x04":
            return "ctrl-d"
        if char == "\x15":
            return "ctrl-u"
        if char == "\x19":
            return "ctrl-y"
        if char == "\x0c":
            return "ctrl-l"
        if char == "\x01":
            return "home"
        if char == "\x05":
            return "end"
        if char == "\t":
            return "tab"
        if char.isprintable():
            return char
        return "unknown"

    def _windows_vt_input(self, on: bool) -> None:
        """Put the console in raw VT input for one key, then restore it.

        Raw means no line editing, no echo and no Ctrl-C processing (Ctrl-C is
        read as a key, as `msvcrt.getwch` used to deliver it). VT input makes
        Windows Terminal's SGR mouse reports (wheel, press, drag, release)
        arrive as escape sequences. The previous mode comes back after every
        key, like the POSIX raw mode.
        """
        try:
            kernel32 = self._kernel32()
            handle = kernel32.GetStdHandle(-10)           # STD_INPUT_HANDLE
            if on:
                mode = ctypes.c_uint32()
                if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                    return
                self._console_mode = mode.value
                kernel32.SetConsoleMode(
                    handle, (mode.value & ~_CONSOLE_COOKED) | _ENABLE_VT_INPUT)
            elif self._console_mode is not None:
                kernel32.SetConsoleMode(handle, self._console_mode)
                self._console_mode = None
        except Exception:
            self._console_mode = None                     # never strand the console

    def _kernel32(self):
        if self.kernel32 is None:
            self.kernel32 = ctypes.windll.kernel32
        return self.kernel32

    def _read_key_windows(self):
        """Read console input records directly.

        `msvcrt.getwch` cannot be used: the UCRT sets the input mode to 0 for
        the duration of the call (dropping ENABLE_VIRTUAL_TERMINAL_INPUT) and
        skips every non-key record, so no mouse report could ever arrive.
        """
        while True:
            event = self._windows_event(None)
            if event is None:
                return "eof"
            if event == "\x1b":
                return self._windows_escape()
            if event != "":
                return event

    def _windows_escape(self):
        # with VT input, keys and mouse reports arrive as escape sequences;
        # read the rest of one so it is never typed into the composer
        sequence = ""
        deadline = time.monotonic() + 0.05
        while True:
            part = self._windows_event(deadline)
            if part is None:
                break
            if not isinstance(part, str) or len(part) != 1:
                if part != "":
                    self._pending.append(part)            # a whole key; keep it
                continue
            sequence += part
            if part == "~" or (part.isalpha() and sequence not in ("[", "O")):
                break
        return self._decode_escape(sequence.encode("utf-8", "replace"))

    def _windows_event(self, deadline: Optional[float]):
        """One input record decoded: a character, a key name, a MouseEvent,
        "" for a record to skip, or None (no console, or `deadline` passed)."""
        kernel32 = self._kernel32()
        handle = kernel32.GetStdHandle(-10)
        if deadline is not None:
            pending = ctypes.c_uint32()
            if not kernel32.GetNumberOfConsoleInputEvents(handle, ctypes.byref(pending)):
                return None
            if not pending.value:
                wait = int(max(0.0, deadline - time.monotonic()) * 1000)
                if not wait or kernel32.WaitForSingleObject(handle, wait) != 0:
                    return None
        record = _INPUT_RECORD()
        count = ctypes.c_uint32()
        if not kernel32.ReadConsoleInputW(handle, ctypes.byref(record), 1,
                                          ctypes.byref(count)) or not count.value:
            return None
        if record.EventType == _KEY_EVENT:
            key = record.Event.KeyEvent
            if not key.bKeyDown:
                return ""
            code = key.UnicodeChar
            if not code:
                return _WINDOWS_VKEYS.get(key.wVirtualKeyCode, "")
            if 0xD800 <= code < 0xDC00:                   # high surrogate: one more record
                low = self._windows_event(time.monotonic() + 0.05)
                if isinstance(low, str) and len(low) == 1 and 0xDC00 <= ord(low) < 0xE000:
                    return chr(0x10000 + ((code - 0xD800) << 10) + (ord(low) - 0xDC00))
                return ""
            char = chr(code)
            if char == "\x1b" or 0xDC00 <= code < 0xE000:  # escape, or a pair's low half
                return char
            return self._decode_bytes(char.encode("utf-8", "replace"))
        if record.EventType == _MOUSE_EVENT:
            return self._windows_mouse(record.Event.MouseEvent)
        return ""

    def _windows_mouse(self, mouse):
        """A native MOUSE_EVENT record (VT input was off when it arrived)."""
        x, y = mouse.X + 1, mouse.Y + 1
        if mouse.dwEventFlags & _MOUSE_WHEELED:
            delta = (mouse.dwButtonState >> 16) & 0xFFFF
            return "wheeldown" if delta & 0x8000 else "wheelup"
        left = bool(mouse.dwButtonState & 0x1)
        was_down, self._left_down = self._left_down, left
        if left and not was_down:
            return MouseEvent("press", x, y)
        if left and mouse.dwEventFlags & _MOUSE_MOVED:
            return MouseEvent("drag", x, y)
        if was_down and not left:
            return MouseEvent("release", x, y)
        return ""


# -------------------------------------------------------------------- session

class Selection(NamedTuple):
    """A mouse selection in transcript coordinates: (wrapped row, column).

    Stored against the wrapped transcript, not the screen, so a redraw or a
    scroll keeps it on the same text; `width` is the wrap width it refers to.
    """
    anchor: Tuple[int, int]
    head: Tuple[int, int]
    width: int

    def ordered(self) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        return (self.anchor, self.head) if self.anchor <= self.head else (self.head, self.anchor)


class TuiSession:
    """Alternate-screen session: transcript, status, command bar, renderer."""

    def __init__(self, renderer: Callable[["TuiSession"], Tuple[List[str], Tuple[int, int]]],
                 stream=None, keys: Optional[KeyReader] = None,
                 completer: Optional[Callable[[str], Sequence[Tuple[str, str]]]] = None,
                 on_copy: Optional[Callable[[str], str]] = None,
                 last_response: Optional[Callable[[], Optional[str]]] = None) -> None:
        self.screen = Screen(stream)
        self.transcript = Transcript()
        self.renderer = renderer
        self.keys = keys or KeyReader()
        self.completer = completer
        self.menu: List[Tuple[str, str]] = []
        self.menu_index = 0
        self.status: List[Span] = []
        self.question = ""
        self.default = ""
        self.input = ""
        self.cursor = 0
        self.masked = False
        self.scroll = 0
        self.history: List[str] = []
        self.hints: List[Span] = []
        # copying: `on_copy(text)` delivers text and returns the confirmation;
        # `last_response()` is what Ctrl-Y copies
        self.on_copy = on_copy
        self.last_response = last_response
        self.layout: Dict[str, int] = {}       # where the renderer drew the transcript
        self.selection: Optional[Selection] = None
        self.notice: List[Span] = []            # one-shot confirmation in the composer
        self._dragging = False
        self._ticker: Optional[threading.Thread] = None
        self._ticker_stop = threading.Event()
        self._busy = threading.Event()
        self._render_lock = threading.RLock()

    # -- lifecycle -------------------------------------------------------
    def open(self) -> None:
        self.screen.enter()
        self.render()

    def close(self) -> None:
        self.stop_status()
        self.screen.leave()

    def __enter__(self) -> "TuiSession":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- rendering -------------------------------------------------------
    def render(self) -> None:
        with self._render_lock:
            try:
                lines, cursor = self.renderer(self)
            except Exception:
                return
            self.screen.draw(lines, cursor)

    def size(self) -> Tuple[int, int]:
        return self.screen.size()

    # -- output capture --------------------------------------------------
    def feed(self, text: str) -> None:
        self.transcript.feed(text)

    def capture(self) -> "CaptureStream":
        return CaptureStream(self)

    # -- status / progress ----------------------------------------------
    def set_status(self, spans: Sequence[Span], hints: Optional[Sequence[Span]] = None) -> None:
        self.status = list(spans)
        if hints is not None:
            self.hints = list(hints)
        self.render()

    def start_status(self, spans: Sequence[Span]) -> None:
        """Show a spinner in the status line until stop_status()."""
        self.status = list(spans)
        if not self.screen.active:
            return
        self.stop_status()
        self._ticker_stop.clear()

        def tick() -> None:
            frames = "·✢✳✶✻✽✻✶✳✢"
            index = 0
            while not self._ticker_stop.wait(0.12):
                index += 1
                frame = frames[index % len(frames)]
                base = spans_plain(self.status)
                text = base
                for candidate in frames:
                    if base.startswith(candidate):
                        text = frame + base[1:]
                        break
                self.status = [(text, "primary", True)]
                self.render()

        self._ticker = threading.Thread(target=tick, daemon=True)
        self._ticker.start()
        self.render()

    def stop_status(self) -> None:
        self._ticker_stop.set()
        if self._ticker is not None:
            self._ticker.join(timeout=0.3)
            self._ticker = None
        self.status = []
        self.render()

    # -- questions -------------------------------------------------------
    def ask(self, label: str, default: str = "", secret: bool = False) -> str:
        value = self._question(label, default, secret)
        if value is None:
            return default
        return value or default

    def read_secret(self, label: str = "password") -> Optional[str]:
        """Masked input; None when cancelled (Ctrl-C, Ctrl-D, end of input).

        Unlike `ask`, a cancel is not turned into an empty answer, so the
        caller can tell "cancelled" from "pressed Enter".
        """
        return self._question(label, "", True)

    def _question(self, label: str, default: str, secret: bool) -> Optional[str]:
        self.question = label
        self.default = default
        self.set_status([(f"{label}" + (f"  [{default}]" if default else ""),
                          "accent", False)])
        try:
            return self.read_line(secret=secret)
        finally:
            self.question = ""
            self.default = ""
            self.status = []

    # -- the command bar -------------------------------------------------
    def read_line(self, secret: bool = False) -> Optional[str]:
        """Read one edited line. Returns None on EOF/Ctrl-D."""
        self.input = ""
        self.cursor = 0
        self.masked = secret
        self.menu = []
        self.menu_index = 0
        history_index = len(self.history)
        draft = ""
        self.screen.mouse(True)
        try:
            while True:
                self.render()
                key = self.keys.read_key()
                if isinstance(key, MouseEvent):
                    self.handle_mouse(key)
                    continue
                if key not in ("pending", "unknown"):
                    self.selection, self.notice = None, []
                if key == "ctrl-y":
                    self.copy_last_response()
                    continue
                if key in ("enter", "eof", "ctrl-d") or key == "ctrl-c":
                    if key in ("eof", "ctrl-d"):
                        return None
                    if key == "ctrl-c":
                        return None
                    line = self.input
                    self.input = ""
                    self.cursor = 0
                    self.masked = False
                    if line.strip() and not secret:
                        self.history.append(line)
                        del self.history[:-HISTORY_LIMIT]
                    return line
                if key == "backspace":
                    if self.cursor > 0:
                        self.input = self.input[:self.cursor - 1] + self.input[self.cursor:]
                        self.cursor -= 1
                elif key == "ctrl-u":
                    self.input = ""
                    self.cursor = 0
                elif key == "left":
                    self.cursor = max(0, self.cursor - 1)
                elif key == "right":
                    self.cursor = min(len(self.input), self.cursor + 1)
                elif key == "home":
                    self.cursor = 0
                elif key == "end":
                    self.cursor = len(self.input)
                elif key == "up":
                    if self.menu:
                        self.menu_index = max(0, self.menu_index - 1)
                    elif history_index > 0:
                        if history_index == len(self.history):
                            draft = self.input
                        history_index -= 1
                        self.input = self.history[history_index]
                        self.cursor = len(self.input)
                elif key == "down":
                    if self.menu:
                        self.menu_index = min(len(self.menu) - 1, self.menu_index + 1)
                    else:
                        if history_index < len(self.history) - 1:
                            history_index += 1
                            self.input = self.history[history_index]
                        elif history_index == len(self.history) - 1:
                            history_index = len(self.history)
                            self.input = draft
                        self.cursor = len(self.input)
                elif key in ("wheelup", "wheeldown"):
                    self.scroll_rows(WHEEL_STEP if key == "wheelup" else -WHEEL_STEP)
                elif key in ("pageup", "pagedown"):
                    self.scroll_rows(PAGE_STEP if key == "pageup" else -PAGE_STEP)
                elif key == "escape":
                    if self.menu:
                        self.menu = []
                        self.menu_index = 0
                    else:
                        self.scroll_rows(-PAGE_STEP)
                elif key == "ctrl-l":
                    self.scroll = 0
                    self.screen.enter()
                elif key == "tab":
                    if self.menu:
                        self.accept_completion()
                elif key in ("backtab", "unknown", "pending"):
                    continue
                elif len(key) == 1 and key.isprintable():
                    self.input = self.input[:self.cursor] + key + self.input[self.cursor:]
                    self.cursor += 1
                self.refresh_menu()
        finally:
            self.menu = []
            self.menu_index = 0
            self.masked = self.masked and secret
            self._dragging = False
            self.screen.mouse(False)

    # -- completion ------------------------------------------------------
    def refresh_menu(self) -> None:
        """Ask the completer for suggestions for the current command word."""
        if self.masked or self.completer is None:
            self.menu = []
            self.menu_index = 0
            return
        text = self.input
        arguments = getattr(self.completer, "completes_arguments", False)
        if not text.startswith("/") or (" " in text and not arguments):
            self.menu = []
            self.menu_index = 0
            return
        try:
            items = [tuple(item) for item in self.completer(text)][:MENU_ROWS]
        except Exception:
            items = []
        if [name for name, _ in items] != [name for name, _ in self.menu]:
            self.menu_index = 0
        self.menu = items  # type: ignore[assignment]
        self.menu_index = min(self.menu_index, max(0, len(self.menu) - 1))

    def accept_completion(self) -> None:
        """Tab: put the highlighted command in the bar with its trailing space."""
        if not self.menu:
            return
        name = self.menu[self.menu_index][0]
        self.input = name + " "
        self.cursor = len(self.input)
        self.menu = []
        self.menu_index = 0

    # -- selection and copy ---------------------------------------------
    def cell_at(self, x: int, y: int, clamp: bool = False) -> Optional[Tuple[int, int]]:
        """The transcript cell under screen cell (x, y), both 1-based.

        Outside the drawn transcript this is None, unless `clamp` (a drag that
        left the transcript): then it pins to the first or last drawn row.
        """
        lay = self.layout
        rows = lay.get("body_rows", 0)
        if not rows:
            return None
        row, col = y - lay["body_top"], x - lay["left"]
        width = lay["width"]
        if not clamp and not (0 <= row < rows and 0 <= col < width):
            return None
        if row < 0:
            row, col = 0, 0
        elif row >= rows:
            row, col = rows - 1, width - 1
        return lay["start"] + row, min(max(col, 0), width - 1)

    def handle_mouse(self, event: MouseEvent) -> None:
        """Press starts a selection, drag extends it, release copies it."""
        if event.kind == "press":
            cell = self.cell_at(event.x, event.y)
            self.notice = []
            self.selection = (Selection(cell, cell, self.layout["width"])
                              if cell is not None else None)
            self._dragging = cell is not None
        elif event.kind == "drag" and self._dragging and self.selection:
            cell = self.cell_at(event.x, event.y, clamp=True)
            if cell is not None:
                self.selection = self.selection._replace(head=cell)
        elif event.kind == "release" and self._dragging:
            self._dragging = False
            if self.selection and self.selection.head != self.selection.anchor:
                self.copy(self.selected_text())
            else:
                self.selection = None              # a click copies nothing

    def selected_text(self) -> str:
        """The selected characters as shown, rows joined, trailing space dropped."""
        if not self.selection:
            return ""
        (r1, c1), (r2, c2) = self.selection.ordered()
        rows = self.transcript.wrapped(self.selection.width)
        if r1 >= len(rows):
            return ""
        r2 = min(r2, len(rows) - 1)
        cut = textcells.slice
        if r1 == r2:
            parts = [cut(rows[r1], c1, c2 + 1)]
        else:
            parts = [cut(rows[r1], c1, 1 << 30), *rows[r1 + 1:r2], cut(rows[r2], 0, c2 + 1)]
        return "\n".join(part.rstrip() for part in parts)

    def highlight(self, start: int, count: int, width: int) -> Dict[int, Tuple[int, int]]:
        """Reverse-video columns per visible body row for the current selection."""
        if not self.selection or self.selection.width != width:
            return {}
        (r1, c1), (r2, c2) = self.selection.ordered()
        spans = {}
        for row in range(max(r1, start), min(r2, start + count - 1) + 1):
            spans[row - start] = (c1 if row == r1 else 0, c2 + 1 if row == r2 else width)
        return spans

    def copy(self, text: str) -> None:
        if not text:
            self.notice = [("nothing to copy - the selection is empty", "muted", False)]
            return
        message = self.on_copy(text) if self.on_copy else "copying is not available"
        self.notice = [(message, "success" if message.startswith("copied") else "accent",
                        False)]

    def copy_last_response(self) -> None:
        """Ctrl-Y: copy the previous response; the composer text is untouched."""
        response = self.last_response() if self.last_response else None
        if response is None:
            self.notice = [("nothing to copy yet - run a command first", "muted", False)]
        elif not response:
            self.notice = [("nothing to copy - the previous response is empty", "muted",
                            False)]
        else:
            self.copy(response)

    def scroll_rows(self, delta: int) -> None:
        """Positive delta scrolls back into the transcript."""
        self.scroll = max(0, self.scroll + delta)

    def display_text(self) -> str:
        """What the command bar shows (masked for passwords, never the value)."""
        return "*" * len(self.input) if self.masked else self.input



class CaptureStream:
    """`sys.stdout` replacement that appends to a session transcript."""

    encoding = "utf-8"
    errors = "replace"

    def __init__(self, session: TuiSession) -> None:
        self.session = session

    def write(self, text: str) -> int:
        if text:
            self.session.feed(text)
        return len(text)

    def flush(self) -> None:
        self.session.transcript.flush_partial()

    def isatty(self) -> bool:
        return True

    def fileno(self):  # pragma: no cover - some libs probe for it
        raise OSError("capture stream has no file descriptor")

    def __getattr__(self, name):
        return getattr(sys.__stdout__, name)


# a tiny helper for renderers that want the raw frame without a session
def render_once(session: TuiSession) -> Tuple[List[str], Tuple[int, int]]:
    lines, cursor = session.renderer(session)
    return lines, cursor
