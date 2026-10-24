"""Full-screen application shell for SSL Doctor.

The interactive session runs inside the terminal's alternate screen: one centred
column holding a header, a bounded output panel with scrollback, a status line,
a command bar and a key-hint footer.  Command output is captured into the panel
instead of being appended to the scrollback, so the composition behaves like an
application rather than a log.

This module owns presentation only.  It never imports the check code: the CLI
passes in a renderer, a capture stream and the command handler, which keeps the
same ``execute()`` dispatch serving both presentations.

Stdlib only: ``termios``/``select`` on POSIX, ``msvcrt`` on Windows.  When
neither is usable, :func:`enabled` returns ``False`` and the line-oriented REPL
runs instead.
"""

from __future__ import annotations

import codecs
import os
import re
import select
import shutil
import sys
import textwrap
import threading
from typing import Callable, List, Optional, Sequence, Tuple

MIN_WIDTH = 40
MAX_WIDTH = 96
ALT_SCREEN_ON = "\033[?1049h"
ALT_SCREEN_OFF = "\033[?1049l"
CURSOR_HIDE = "\033[?25l"
CURSOR_SHOW = "\033[?25h"
CLEAR_SCREEN = "\033[2J"

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# how many wrapped body rows a PageUp/PageDown moves
PAGE_STEP = 10
HISTORY_LIMIT = 200


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
    return len(strip_ansi(text))


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
        return [line[:width]]
    if len(line) <= width:
        return [line]
    chunks = textwrap.wrap(body, width=max(4, width - indent),
                           break_long_words=True, break_on_hyphens=False,
                           replace_whitespace=False, drop_whitespace=True)
    if not chunks:
        return [line[:width]]
    return [(" " * indent) + chunks[0]] + [(" " * indent) + c for c in chunks[1:]]


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
        out: List[str] = []
        for line in self.lines:
            out.extend(wrap_line(line, width))
        return out

    def tail(self, width: int, height: int, scroll: int = 0) -> List[str]:
        """Return `height` rows ending `scroll` rows above the newest line."""
        rows = self.wrapped(width)
        if height <= 0:
            return []
        offset = max(0, min(scroll, max(0, len(rows) - height)))
        end = len(rows) - offset
        start = max(0, end - height)
        visible = rows[start:end]
        while len(visible) < height:
            visible.insert(0, "")
        return visible


# ---------------------------------------------------------------------- layout

Span = Tuple[str, str, bool]  # (text, role, bold)


def spans_plain(spans: Sequence[Span]) -> str:
    return "".join(span[0] for span in spans)


def _paint_spans(spans: Sequence[Span], painter) -> str:
    return "".join(painter(text, role, bold) if (role or bold) else text
                   for text, role, bold in spans)


def truncate_spans(spans: Sequence[Span], width: int) -> List[Span]:
    """Cut spans to `width` visible columns (spans never contain escapes)."""
    out: List[Span] = []
    room = width
    for text, role, bold in spans:
        if room <= 0:
            break
        if len(text) > room:
            out.append((text[:room], role, bold))
            break
        out.append((text, role, bold))
        room -= len(text)
    return out


def block_width(columns: int) -> int:
    """Centred column width: clamped to the terminal and to MAX_WIDTH."""
    return max(20, min(max(20, columns - 2), MAX_WIDTH))


def top_margin(rows: int) -> int:
    """One blank row above the header when the frame has the room for it."""
    return 1 if rows >= 20 else 0


def panel_height(rows: int, header_len: int, hints: bool = True) -> int:
    """Rows available to the output panel body (borders excluded)."""
    return max(1, rows - header_len - 6 - (1 if hints else 0))


def build_frame(*, columns: int, rows: int, header: Sequence[Sequence[Span]],
                body: Sequence[str], status: Sequence[Span],
                prompt_text: str = "", hints: Sequence[Span] = (),
                painter, glyphs, width: Optional[int] = None,
                cursor: int = 0, prompt_len: int = 2) -> Tuple[List[str], Tuple[int, int]]:
    """Compose one screen.

    `cursor` is an index into the typed part of the command bar, `prompt_len` the
    width of the `> ` prefix. Returns (lines, (row, column)), both 1-based.
    """
    width = block_width(columns) if width is None else min(width, columns)
    width = min(width, columns)
    left = max(0, (columns - width) // 2)
    right = max(0, columns - left - width)
    inner = max(4, width - 4)  # "| " ... " |"

    def pad(spans: Sequence[Span], fill: str = " ", align: str = "left") -> str:
        spans = truncate_spans(spans, width)
        text = spans_plain(spans)
        room = max(0, width - len(text))
        lead = room // 2 if align == "center" else 0
        trail = room - lead
        body = fill * lead + _paint_spans(spans, painter) + fill * trail
        return " " * left + body + " " * right

    corner_tl = glyphs.corner("┌", "+")
    corner_tr = glyphs.corner("┐", "+")
    corner_bl = glyphs.corner("└", "+")
    corner_br = glyphs.corner("┘", "+")
    bar = glyphs.vert

    margin = top_margin(rows)
    lines: List[str] = [""] * margin
    for span_line in header:
        lines.append(pad(span_line, " ", "center"))

    # ---- output panel ----------------------------------------------------
    panel_rows = panel_height(rows - margin, len(header), bool(hints))
    label = " output "
    top = corner_tl + glyphs.h + label
    top += glyphs.h * max(0, width - 1 - len(top) - 1) + corner_tr
    lines.append(pad([(top, "tool", False)]))

    visible = list(body)[:panel_rows]
    while len(visible) < panel_rows:
        visible.append("")
    for row_text in visible:
        clipped = row_text[:inner]
        filler = " " * max(0, inner - len(clipped))
        lines.append(pad([(bar + " ", "tool", False), *colorize(clipped),
                          (filler + " " + bar, "tool", False)]))
    lines.append(pad([(corner_bl + glyphs.h * (width - 2) + corner_br, "tool", False)]))

    # ---- status ----------------------------------------------------------
    lines.append(pad(list(status)))

    # ---- command bar -----------------------------------------------------
    label = " command "
    bar_top = corner_tl + glyphs.h + label
    bar_top += glyphs.h * max(0, width - 1 - len(bar_top) - 1) + corner_tr
    lines.append(pad([(bar_top, "accent", False)]))
    shown = prompt_text[:max(0, inner - prompt_len)]
    prefix = prompt_text[:0] or "> "
    tail = " " * max(0, inner - prompt_len - len(shown)) + " " + bar
    lines.append(pad([(bar + " ", "accent", False), (prefix, "primary", True),
                      (shown, "", False), (tail, "accent", False)]))
    lines.append(pad([(corner_bl + glyphs.h * (width - 2) + corner_br, "accent", False)]))

    # ---- hints -----------------------------------------------------------
    if hints:
        lines.append(pad(list(hints), " ", "center"))

    cursor_row = len(lines) - (2 if hints else 1)
    while len(lines) < rows:
        lines.append(" " * columns)
    # pad on *visible* width: painted spans carry escape sequences
    padded = [line + " " * max(0, columns - visible_len(line)) for line in lines[:rows]]
    cursor_col = left + 2 + prompt_len + max(0, min(cursor, len(shown)))
    return padded, (cursor_row, cursor_col + 1)


_STATUS_ROLE_RE = re.compile(
    r"^(\[\s*(?:\+|x|!|\?)?\s*(PASS|FAIL|WARNING|NOT TESTED)\s*\])")


def colorize(text: str) -> List[Span]:
    """Give a captured output line the right colours without changing its text."""
    role_of = {"PASS": "success", "FAIL": "error", "WARNING": "warning",
               "NOT TESTED": "muted"}
    match = _STATUS_ROLE_RE.match(text)
    if match:
        head, status = match.group(1), match.group(2)
        return [(head, role_of[status], True), (text[len(head):], "", False)]
    stripped = text.strip()
    if stripped.startswith("error:"):
        return [(text, "error", False)]
    if stripped.startswith("fix:") or stripped.startswith("report written:"):
        return [(text, "accent", False)]
    if stripped.startswith("Diagnosis") or stripped.startswith("SSL Doctor commands"):
        return [(text, "primary", True)]
    if stripped.startswith("next:") or stripped.startswith("interrupted"):
        return [(text, "muted", False)]
    return [(text, "", False)]


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
        self._write(CURSOR_SHOW + ALT_SCREEN_OFF)

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
        except Exception:
            pass


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
        try:
            import termios  # noqa: F401
        except Exception:
            self._windows = True

    # -- raw mode is entered for a single keystroke only
    def _raw(self) -> None:
        if self._windows or self._fd is None:
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
        if self._saved is None or self._fd is None:
            return
        import termios
        try:
            termios.tcsetattr(self._fd, termios.TCSADRAIN, self._saved)
        except Exception:
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

    def _decode_escape(self, sequence: bytes) -> str:
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

    def _read_key_windows(self) -> str:
        import msvcrt
        char = msvcrt.getwch()
        if char in ("\x00", "\xe0"):
            code = msvcrt.getwch()
            return {"H": "up", "P": "down", "M": "right", "K": "left",
                    "G": "home", "O": "end", "I": "pageup", "Q": "pagedown",
                    }.get(code, "unknown")
        return self._decode_bytes(char.encode("utf-8", "replace"))


# -------------------------------------------------------------------- session

class TuiSession:
    """Alternate-screen session: transcript, status, command bar, renderer."""

    def __init__(self, renderer: Callable[["TuiSession"], Tuple[List[str], Tuple[int, int]]],
                 stream=None, keys: Optional[KeyReader] = None) -> None:
        self.screen = Screen(stream)
        self.transcript = Transcript()
        self.renderer = renderer
        self.keys = keys or KeyReader()
        self.status: List[Span] = []
        self.question = ""
        self.default = ""
        self.input = ""
        self.cursor = 0
        self.masked = False
        self.scroll = 0
        self.history: List[str] = []
        self.hints: List[Span] = []
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
        self.question = label
        self.default = default
        self.set_status([(f"{label}" + (f"  [{default}]" if default else ""),
                          "accent", False)])
        value = self.read_line(secret=secret)
        self.question = ""
        self.default = ""
        self.status = []
        if value is None:
            return default
        return value or default

    def read_secret(self, label: str = "password") -> str:
        return self.ask(label, "", secret=True)

    # -- the command bar -------------------------------------------------
    def read_line(self, secret: bool = False) -> Optional[str]:
        """Read one edited line. Returns None on EOF/Ctrl-D."""
        self.input = ""
        self.cursor = 0
        self.masked = secret
        history_index = len(self.history)
        draft = ""
        while True:
            self.render()
            key = self.keys.read_key()
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
                if history_index > 0:
                    if history_index == len(self.history):
                        draft = self.input
                    history_index -= 1
                    self.input = self.history[history_index]
                    self.cursor = len(self.input)
            elif key == "down":
                if history_index < len(self.history) - 1:
                    history_index += 1
                    self.input = self.history[history_index]
                elif history_index == len(self.history) - 1:
                    history_index = len(self.history)
                    self.input = draft
                self.cursor = len(self.input)
            elif key in ("pageup", "pagedown", "escape"):
                self.scroll_rows(PAGE_STEP if key == "pageup" else -PAGE_STEP)
            elif key == "ctrl-l":
                self.scroll = 0
                self.screen.enter()
            elif key == "tab":
                continue
            elif len(key) == 1 and key.isprintable():
                self.input = self.input[:self.cursor] + key + self.input[self.cursor:]
                self.cursor += 1

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
