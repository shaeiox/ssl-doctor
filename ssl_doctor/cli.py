"""Interactive command-line interface for SSL Doctor.

A persistent REPL with slash commands.  Presentation follows the Claude Code
terminal design language: semantic colour roles that degrade from TrueColor to
256 to 16 to plain, one frame per command, a rounded chat-style composer,
hot-pink frames around machine work and lavender frames around questions put
back to the operator.  Colour disables automatically when stdout is not a terminal, when
NO_COLOR is set, or when the terminal cannot render the glyphs.

Also supports one-shot batch usage:

    python3 ssldoctor.py -c "/tls example.com" -c "/report html out.html"
"""

from __future__ import annotations

import contextlib
import getpass
import json
import os
import random
import shlex
import shutil
import sys
import textwrap
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from . import APP_NAME, __version__
from . import findings as F
from . import textcells
from .analyze import diagnose
from . import certs as certmod
from . import local as localmod
from . import netchecks
from . import report as reportmod
from . import server as servermod
from . import profiles as profilesmod
from . import vault as vaultmod

_TW_ENABLED = False
_TW_CPS = 40.0
_TW_BATCH = False


def _tw_type(text: str) -> None:
    """Print text, using the typewriter effect when active."""
    global _TW_ENABLED, _TW_CPS, _TW_BATCH
    # never into the full-screen capture: the shell redraws on its own ticks
    active = (_TW_ENABLED and not _TW_BATCH and not _CAPTURE
              and bool(getattr(sys.stdout, "isatty", lambda: False)()))
    if not active:
        print(text)
        return
    cps = _TW_CPS if _TW_CPS >= 1 else 1.0
    for ch in str(text):
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(1.0 / cps)
    sys.stdout.write("\n")
    sys.stdout.flush()


# -------------------------------------------------------------------- theme
#
# Colours are named by role, never by escape code, so the whole interface can
# step down from TrueColor to 256 to 16 to plain without changing a call site.


class ColorMode:
    """Terminal colour capability, resolved once per process."""

    TRUECOLOR = "truecolor"
    ANSI256 = "ansi256"
    ANSI16 = "ansi16"
    PLAIN = "plain"


# role -> (truecolor rgb, 256-colour index, basic 16-colour SGR code)
ROLES = {
    "foreground": ((255, 255, 255), 15, 97),
    "primary": ((215, 119, 87), 173, 33),
    "shimmer": ((235, 159, 127), 216, 33),
    "tool": ((253, 93, 177), 206, 95),
    "accent": ((177, 185, 249), 147, 94),
    "success": ((78, 186, 101), 71, 32),
    "warning": ((255, 193, 7), 220, 33),
    "error": ((255, 107, 128), 204, 31),
    "muted": ((136, 136, 136), 245, 90),
    "inactive": ((153, 153, 153), 246, 90),
    "subtle": ((80, 80, 80), 239, 90),
    "surface": ((55, 55, 55), 237, 40),
}

_RESET = "\033[0m"

# layout constants from the design system
INDENT = "  "
MIN_BLOCK_WIDTH = 40
MAX_BLOCK_WIDTH = 72
DEFAULT_WIDTH = 80


def _role_sgr(role: str, mode: str) -> str:
    rgb, index, basic = ROLES[role]
    if mode == ColorMode.TRUECOLOR:
        return "38;2;%d;%d;%d" % rgb
    if mode == ColorMode.ANSI256:
        return "38;5;%d" % index
    return str(basic)


def _vt_enabled() -> bool:
    """Turn on ANSI processing for Windows consoles; False when unsupported."""
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        state = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(state)):
            return False
        return bool(kernel32.SetConsoleMode(handle, state.value | 0x0004))
    except Exception:
        return False


def resolve_color_mode(stream=None, env=None, windows: Optional[bool] = None,
                       enable_vt=None) -> str:
    """Pick one colour level, honouring NO_COLOR and SSL_DOCTOR_COLOR first."""
    env = os.environ if env is None else env
    stream = sys.stdout if stream is None else stream
    windows = (os.name == "nt") if windows is None else windows
    enable_vt = _vt_enabled if enable_vt is None else enable_vt

    if env.get("NO_COLOR") is not None:
        return ColorMode.PLAIN
    forced = (env.get("SSL_DOCTOR_COLOR") or "").strip().lower()
    if forced in ("never", "plain"):
        return ColorMode.PLAIN
    try:
        is_tty = bool(stream.isatty())
    except Exception:
        is_tty = False
    if not is_tty:  # pipes, files and captured test output stay plain
        return ColorMode.PLAIN
    if (env.get("TERM") or "").strip().lower() == "dumb":
        return ColorMode.PLAIN
    if windows and not enable_vt():
        return ColorMode.PLAIN
    colorterm = (env.get("COLORTERM") or "").strip().lower()
    if colorterm in ("truecolor", "24bit"):
        return ColorMode.TRUECOLOR
    if "256color" in (env.get("TERM") or "").lower():
        return ColorMode.ANSI256
    return ColorMode.ANSI16


class Glyphs:
    """Unicode marks with the design system's ASCII fallbacks."""

    UNICODE = {"pass": "✓", "fail": "✗", "warn": "⚠", "run": "▸",
               "bullet": "•", "sep": "·", "unknown": "?"}
    ASCII = {"pass": "+", "fail": "x", "warn": "!", "run": ">",
             "bullet": "-", "sep": "-", "unknown": "?"}

    def __init__(self, unicode_ok: bool = True, box_ok: bool = True) -> None:
        self.unicode = unicode_ok
        self.box = box_ok
        self.table = self.UNICODE if unicode_ok else self.ASCII

    def __getitem__(self, key: str) -> str:
        return self.table[key]

    @property
    def vert(self) -> str:
        return "│" if self.box else "|"

    @property
    def h(self) -> str:
        """Horizontal rule: box drawing on capable terminals, dashed ASCII else."""
        return "─" if self.box else "-"

    def corner(self, unicode_char: str, ascii_char: str) -> str:
        return unicode_char if self.box else ascii_char

    @property
    def ellipsis(self) -> str:
        return "…" if self.unicode else "..."

    @property
    def double(self) -> str:
        """Double horizontal rule: two straight lines, or `=` in ASCII."""
        return "═" if self.box else "="

    @property
    def block(self) -> str:
        """Wordmark stroke: a solid block when the encoding can carry it."""
        return "█" if self.unicode else "#"


def resolve_glyphs(mode: str, stream=None) -> Glyphs:
    """Plain mode is ASCII; a terminal gets Unicode only if it can encode it."""
    if mode == ColorMode.PLAIN:
        return Glyphs(False, False)
    stream = sys.stdout if stream is None else stream
    encoding = getattr(stream, "encoding", None)
    if not encoding:
        return Glyphs(True, True)
    try:
        "✓✗⚠▸•·│┌┐└┘─".encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return Glyphs(False, False)  # frames fall back to dashed ASCII too
    return Glyphs(True, True)


_MODE = resolve_color_mode()
_GLYPHS = resolve_glyphs(_MODE)
# While the full-screen shell captures a command's output, colour must not leak
# into the transcript: the renderer re-applies status colours when it draws.
_CAPTURE = False
# Width of the transcript while the shell is open. Non-zero means "we are being
# drawn by the shell", so result frames are sized to the column.
_CAPTURE_WIDTH = 0
# Compatibility alias: older code and third-party snippets read this.
_USE_COLOR = _MODE != ColorMode.PLAIN


def set_capture_width(width: int) -> None:
    """Tell the printers how wide the shell's transcript is (0 = not in one)."""
    global _CAPTURE_WIDTH
    _CAPTURE_WIDTH = max(0, int(width))


def set_color_mode(mode: str) -> None:
    """Re-resolve the palette (used by tests and embedding callers)."""
    global _MODE, _GLYPHS, _USE_COLOR
    _MODE = mode
    _GLYPHS = resolve_glyphs(mode)
    _USE_COLOR = mode != ColorMode.PLAIN


def _plain_output() -> bool:
    """True when output must be plain: no colour, no block frames."""
    return _CAPTURE or _MODE == ColorMode.PLAIN


def paint(text: str, role: str = "", bold: bool = False, dim: bool = False) -> str:
    """Colour one string by semantic role; no-op in plain mode."""
    if _plain_output():
        return text
    return _sgr(text, role, bold, dim)


def paint_screen(text: str, role: str = "", bold: bool = False) -> str:
    """The full-screen renderer's painter: follows the terminal only.

    `paint()` also goes plain while a command's output is being captured, so
    the transcript stays colourless; the renderer draws during that time too
    (the spinner and streamed findings redraw from another thread), and the
    banner and composer must keep their colours while it does.
    """
    if _MODE == ColorMode.PLAIN:
        return text
    return _sgr(text, role, bold, False)


def _sgr(text: str, role: str, bold: bool, dim: bool) -> str:
    if not text:
        return text
    codes = []
    if role:
        if role not in ROLES:  # a bug here must not crash a scan
            raise KeyError(f"unknown colour role: {role}")
        codes.append(_role_sgr(role, _MODE))
    if bold:
        codes.append("1")
    if dim:
        codes.append("2")
    if not codes:
        return text
    return "\033[" + ";".join(codes) + "m" + text + _RESET


def _answer_hints(label: str, default: str) -> str:
    """Key hints for a question, derived from the answers its call site takes."""
    low = label.lower()
    if "(yes/no)" in low or default.strip().lower() in ("yes", "no"):
        return "[Y]es  [N]o"
    if "1=" in low and "2=" in low:
        return "[1] password  [2] private key"
    return ""

_STATUS_ROLE = {
    F.PASS: "success", F.FAIL: "error", F.WARNING: "warning", F.NOT_TESTED: "muted",
}

_CERTAINTY_ROLE = {"confirmed": "error", "probable": "warning", "possible": "muted"}

_SCOPE_LABEL = {
    F.SCOPE_LOCAL: "local",
    F.SCOPE_REMOTE_NET: "network",
    F.SCOPE_SERVER: "server",
}


# ----------------------------------------------------------------- terminal


def terminal_width(default: int = DEFAULT_WIDTH) -> int:
    try:
        return shutil.get_terminal_size((default, 24)).columns
    except Exception:
        return default


def block_width(label: str = "") -> int:
    """Clamp the frame to the terminal, but never narrow the header label."""
    columns = terminal_width()
    width = max(MIN_BLOCK_WIDTH, min(columns - 2, MAX_BLOCK_WIDTH))
    if label:
        needed = len(INDENT) + len(label) + 6
        width = max(width, min(needed, max(columns - 2, MIN_BLOCK_WIDTH)))
    return width


# One table for the shell's completion menu; /help keeps the full usage text.
COMMANDS: List[tuple] = [
    ("/scan", "full workflow: domain, then client and server checks"),
    ("/tls", "remote TLS/HTTPS diagnostics for a host"),
    ("/cert", "inspect a certificate file or match a private key"),
    ("/server", "SSH setup, nginx config, logs and comparison"),
    ("/local", "diagnostics for this machine"),
    ("/diagnose", "correlate findings into root causes"),
    ("/findings", "list everything recorded this session"),
    ("/copy", "copy the previous response (or 'all') to the clipboard"),
    ("/servers", "remembered SSH servers (passwords are never shown)"),
    ("/report", "write an HTML, JSON or AI-ready (agent) report"),
    ("/timeout", "show or set the network timeout"),
    ("/clear", "discard recorded findings"),
    ("/version", "show the version"),
    ("/exit", "leave ssl-doctor"),
]


# commands whose argument is a remembered server's name
PROFILE_ARGUMENT_COMMANDS = ("/server connect", "/server forget-password", "/server forget")


def command_completions(prefix: str, limit: int = 3, profiles=()) -> List[tuple]:
    """Commands matching `prefix`, best match first, for the completion menu.

    After a command that takes a remembered server (`/server connect `), the
    rows are that command with each matching profile name instead.
    """
    text = (prefix or "").lstrip()
    for command in PROFILE_ARGUMENT_COMMANDS:
        if text.lower().startswith(command + " "):
            partial = text[len(command) + 1:].strip()
            if " " in partial:
                return []
            return [(f"{command} {p.name}", p.endpoint) for p in profiles
                    if p.name.startswith(partial)][:max(0, limit)]
    word = text.lower()
    if not word.startswith("/") or " " in word:     # a typed space ends the command word
        return []
    exact = [row for row in COMMANDS if row[0] == word]
    starts = [row for row in COMMANDS if row[0].startswith(word) and row[0] != word]
    inside = [row for row in COMMANDS if word.lstrip("/") and word.strip("/") in row[0]
              and row not in starts and row not in exact]
    return (exact + starts + inside)[:max(0, limit)]


def _wrap(text: str, width: int) -> List[str]:
    """Wrap without dropping characters; long tokens are broken, not elided."""
    if width <= 0:
        return [text]
    # by terminal cells, so wide characters cannot push a frame border out
    text = text.replace("\t", " ").replace("\n", " ").strip()
    return textcells.wrap(text, max(12, width)) or [""]


# --------------------------------------------------------------- indicators

SPINNER_FRAMES = ["·", "✢", "✳", "✶", "✻", "✽"]
# reverse-mirror cycle: up one way, back the other
SPINNER_CYCLE = SPINNER_FRAMES + SPINNER_FRAMES[-2:0:-1]

SPINNER_VERBS = (
    "handshaking", "chaining", "ciphering", "pinning", "tracing", "sniffing",
    "untangling", "auditing", "decoding", "percolating", "ruminating",
    "noodling",
)


_TUI_SESSION = None


def _active_tui():
    """The running full-screen session, if any (used by Spinner)."""
    return _TUI_SESSION


def set_active_tui(session) -> None:
    global _TUI_SESSION
    _TUI_SESSION = session


class Spinner:
    """Signature thinking indicator; one plain line when output is redirected."""

    def __init__(self, text: str, verb: Optional[str] = None) -> None:
        self.text = text
        self.verb = verb or random.choice(SPINNER_VERBS)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._dirty = False
        self._session = None

    def __enter__(self) -> "Spinner":
        session = _active_tui()
        if session is not None:
            # the transcript must not gain progress lines: the status line owns them
            self._session = session
            session.start_status([(f"{SPINNER_CYCLE[2]} {self.verb}{_GLYPHS.ellipsis} "
                                   f"{self.text}", "primary", True)])
            return self
        if _MODE != ColorMode.PLAIN:
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
        else:
            print(paint(f"... {self.text}", "muted"))
        return self

    def _render(self, frame: str, tone: str) -> str:
        return " ".join((
            paint(frame, tone, bold=True),
            paint(f"{self.verb}{_GLYPHS.ellipsis}", "primary"),
            paint(self.text, "muted", dim=True),
        ))

    def _run(self) -> None:
        index = 0
        while not self._stop.is_set():
            frame = SPINNER_CYCLE[index % len(SPINNER_CYCLE)]
            tone = "primary" if index % 2 == 0 else "shimmer"
            sys.stdout.write("\r" + self._render(frame, tone) + "\033[K")
            sys.stdout.flush()
            self._dirty = True
            index += 1
            time.sleep(0.12)
        self._clear()

    def _clear(self) -> None:
        if not self._dirty:
            return
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()
        self._dirty = False

    def __exit__(self, *exc) -> None:
        if self._session is not None:
            self._session.stop_status()
            self._session = None
            return
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=0.5)
            self._clear()


# ------------------------------------------------------------------- output

def _counts(items: List[F.Finding]) -> Dict[str, int]:
    return {s: sum(1 for f in items if f.status == s) for s in _STATUS_ROLE}


def _counts_segments(items: List[F.Finding]):
    c = _counts(items)
    return [
        (f"{c[F.PASS]} passed", "success"),
        (f"{c[F.FAIL]} failed", "error"),
        (f"{c[F.WARNING]} warnings", "warning"),
        (f"{c[F.NOT_TESTED]} not tested", "muted"),
    ]


def _counts_text(items: List[F.Finding], sep: str) -> str:
    return sep.join(text for text, _ in _counts_segments(items))


def _counts_line(items: List[F.Finding]) -> str:
    sep = paint(f" {_GLYPHS['sep']} ", "muted")
    return sep.join(paint(text, role, dim=True)
                    for text, role in _counts_segments(items))


def _status_glyph(status: str) -> str:
    return {
        F.PASS: _GLYPHS["pass"], F.FAIL: _GLYPHS["fail"],
        F.WARNING: _GLYPHS["warn"], F.NOT_TESTED: _GLYPHS["unknown"],
    }.get(status, _GLYPHS["sep"])


def print_finding(f: F.Finding, verbose: bool = True) -> None:
    """Print one finding in the plain, pipe-friendly format."""
    role = _STATUS_ROLE.get(f.status, "")
    scope = paint(_SCOPE_LABEL.get(f.scope, f.scope), "muted", dim=True)
    status = paint(f"{_status_glyph(f.status)} {f.status}".rjust(9), role, bold=True)
    _tw_type(f"[{status}] {f.title}  {paint(_GLYPHS['sep'], 'muted')} {scope}")
    if not verbose:
        return
    for line in f.evidence:
        _tw_type(f"          {paint(_GLYPHS['bullet'], 'muted')} {line}")
    if f.failure_kind:
        _tw_type(paint(f"          failure kind: {f.failure_kind}", dim=True))
    if f.observation:
        _tw_type(paint(f"          observation: {f.observation}", dim=True))
    if f.detail:
        _tw_type(paint(f"          {f.detail}", dim=True))
    if f.recommendation:
        _tw_type(paint(f"          fix: {f.recommendation}", "accent"))


_BLOCK_LABEL = ""


def set_block_label(label: str) -> None:
    """Label the next command block (set per executed command line)."""
    global _BLOCK_LABEL
    _BLOCK_LABEL = label


def _frame_top(label: str, width: int, role: str = "tool") -> str:
    corner = _GLYPHS.corner("┌", "+")
    head = f"{corner}{_GLYPHS.h} {label} " if label else f"{corner}{_GLYPHS.h} "
    dashes = max(1, width - len(INDENT) - len(head) - 1)
    return INDENT + paint(head + _GLYPHS.h * dashes + _GLYPHS.corner("┐", "+"), role)


def _frame_bottom(line_text: str, width: int, role: str = "tool",
                  visible_len: Optional[int] = None) -> str:
    """Close a frame; `visible_len` is the plain length when text is painted."""
    shown = len(line_text) if visible_len is None else visible_len
    corner = _GLYPHS.corner("┘", "+")
    if not shown:  # empty footer: a plain closing rule
        lead = _GLYPHS.corner("└", "+") + _GLYPHS.h
        dashes = max(1, width - len(INDENT) - len(lead) - 1)
        return INDENT + paint(lead + _GLYPHS.h * dashes + corner, role)
    lead = _GLYPHS.corner("└", "+") + _GLYPHS.h + " "
    used = len(INDENT) + len(lead) + shown + 1 + 1
    dashes = max(1, width - used)
    return (INDENT + paint(lead, role) + line_text
            + paint(" " + _GLYPHS.h * dashes + corner, role))


def _spans_text(spans) -> str:
    return "".join(text for text, _, _ in spans)


def _span_len(spans) -> int:
    return sum(textcells.width(text) for text, _, _ in spans)


def _paint_line(spans) -> str:
    return "".join(paint(text, role, bold) for text, role, bold in spans)


def _box_row(content, inner: int) -> List:
    """One interior row: gutter, left border, padded content, right border."""
    room = max(0, inner - _span_len(content))
    return [(INDENT, "", False), (_GLYPHS.vert, "tool", False), (" ", "", False),
            *content, (" " * room, "", False), (" ", "", False),
            (_GLYPHS.vert, "tool", False)]


def _box_title(label: str, inner: int) -> str:
    title = (label or "results").strip()
    room = inner - len(INDENT) - 6
    if room >= 6 and textcells.width(title) > room:
        title = (textcells.clip(title, max(4, room - len(_GLYPHS.ellipsis)))
                 + _GLYPHS.ellipsis)
    return title


def _box_counts(items: List[F.Finding], room: int) -> List:
    """Counters for the closing border, shortened until they fit `room`."""
    sep = f" {_GLYPHS['sep']} " if _GLYPHS.unicode else " - "
    segments = _counts_segments(items)
    text = sep.join(part for part, _ in segments)
    if textcells.width(text) > room:
        kept = [seg for seg in segments if not seg[0].startswith("0 ")]
        segments = kept or segments
        text = sep.join(part for part, _ in segments)
    if textcells.width(text) > room:
        return [(textcells.clip(text, max(0, room)), "muted", False)]
    spans: List = []
    for index, (part, role) in enumerate(segments):
        if index:
            spans.append((sep, "muted", False))
        spans.append((part, role, False))
    return spans


def _box_geometry(width: int):
    """(width, inner) for a result frame; every row is exactly `width` columns."""
    width = max(30, width)
    return width, max(16, width - len(INDENT) - 4)


def _box_top(label: str, width: int) -> List:
    width, inner = _box_geometry(width)
    h = _GLYPHS.h
    title = _box_title(label, inner)
    fill = max(1, width - len(INDENT) - textcells.width(f"{h} {title} ") - 2)
    return [(INDENT, "", False), (_GLYPHS.corner("╭", "+") + h + " ", "tool", False),
            (title, "primary", True),
            (" " + h * fill + _GLYPHS.corner("╮", "+"), "tool", False)]


def _box_note(text: str, width: int) -> List[List]:
    """A muted interior row, e.g. the phase a streaming frame is waiting on."""
    _, inner = _box_geometry(width)
    return [_box_row([(chunk, "muted", False)], inner)
            for chunk in _wrap(f"{_GLYPHS['run']} {text}", inner)]


def _box_finding(f: F.Finding, width: int, check_width: int,
                 verbose: bool = True) -> List[List]:
    """The interior rows of one finding: status row, evidence, detail, fix."""
    _, inner = _box_geometry(width)
    role = _STATUS_ROLE.get(f.status, "")
    glyph = _status_glyph(f.status)
    prefix = f"{glyph} {f.status:<10} {f.check:<{check_width}}"
    room = inner - len(prefix) - 2
    rows: List[List] = []
    if room >= 20:
        chunks = _wrap(f.title, room)
        rows.append(_box_row([(f"{glyph} ", role, True),
                              (f"{f.status:<10} ", role, True),
                              (f"{f.check:<{check_width}}", "muted", False),
                              (chunks[0], "", False)], inner))
        for chunk in chunks[1:]:
            rows.append(_box_row([(" " * len(prefix), "", False),
                                  (chunk, "", False)], inner))
    else:
        rows.append(_box_row([(f"{glyph} ", role, True),
                              (f.status, role, True)], inner))
        for chunk in _wrap(f"{f.check}  {f.title}", inner - 2):
            rows.append(_box_row([(chunk, "", False)], inner))
    if not verbose:
        return rows
    for line in f.evidence:
        chunks = _wrap(line, inner - 7)
        rows.append(_box_row([("  " + _GLYPHS["bullet"] + " ", "muted", False),
                              (chunks[0], "", False)], inner))
        for chunk in chunks[1:]:
            rows.append(_box_row([("    ", "", False), (chunk, "", False)], inner))
    for label, value in (("failure kind", f.failure_kind),
                         ("observation", f.observation)):
        if value:
            rows.append(_box_row([("    ", "", False),
                                  (f"{label}: {value}", "muted", False)], inner))
    if f.detail:
        for chunk in _wrap(f.detail, inner - 7):
            rows.append(_box_row([("    ", "", False), (chunk, "muted", False)], inner))
    if f.recommendation:
        for chunk in _wrap(f"fix: {f.recommendation}", inner - 7):
            rows.append(_box_row([("    ", "", False), (chunk, "accent", False)], inner))
    return rows


def _box_bottom(items: List[F.Finding], width: int) -> List:
    width, inner = _box_geometry(width)
    h = _GLYPHS.h
    footer = _box_counts(items, inner - 6)
    used = _span_len(footer)
    tail_fill = max(1, width - len(INDENT) - used - 5)
    return [(INDENT, "", False), (_GLYPHS.corner("╰", "+") + h + " ", "tool", False),
            *footer, (" " + h * tail_fill + _GLYPHS.corner("╯", "+"), "tool", False)]


# A streamed frame opens before its findings are known, so its check column
# uses the cap instead of the longest id.
STREAM_CHECK_WIDTH = 20


def _box_lines(items: List[F.Finding], width: int, label: str = "",
               verbose: bool = True) -> List[List]:
    """Draw one result frame: title, one row per check, counters in the base.

    Returns rows as spans so the line REPL can paint them and the full-screen
    shell can capture them as plain text. Every row is exactly `width` columns,
    and text wraps rather than being elided.
    """
    check_width = min(max(len(f.check) for f in items) + 2, STREAM_CHECK_WIDTH)
    rows: List[List] = [_box_top(label, width)]
    for f in items:
        rows.extend(_box_finding(f, width, check_width, verbose))
    rows.append(_box_bottom(items, width))
    return rows


def _framed() -> bool:
    """Result frames are drawn unless output is plain and not captured."""
    return not (_plain_output() and not _CAPTURE_WIDTH)


def _frame_width() -> int:
    return _CAPTURE_WIDTH or block_width(_BLOCK_LABEL)


def _print_spans(spans) -> None:
    _tw_type(_spans_text(spans) if _CAPTURE_WIDTH else _paint_line(spans))


def print_findings(items: List[F.Finding], verbose: bool = True) -> None:
    """Print a command's results: one framed block, or plain rows when piped."""
    if not items:
        return
    if not _framed():
        for f in items:
            print_finding(f, verbose)
        _tw_type(paint("\n" + _counts_text(items, " - "), "muted", dim=True))
        return
    for spans in _box_lines(items, _frame_width(), _BLOCK_LABEL, verbose):
        _print_spans(spans)


class LiveFrame:
    """A result frame that is drawn while its findings arrive.

    The top border and the phase row print on open, each finding prints as its
    check completes, and the counters close the frame -- so streaming keeps the
    same box a finished command gets. Plain output streams bare rows instead.
    """

    def __init__(self, text: str, label: Optional[str] = None) -> None:
        self.text = text
        self.label = _BLOCK_LABEL if label is None else label
        self.items: List[F.Finding] = []
        self.width = _frame_width()
        self._open = False

    def open(self) -> "LiveFrame":
        if _framed():
            _print_spans(_box_top(self.label, self.width))
            for spans in _box_note(self.text, self.width):
                _print_spans(spans)
        else:
            _tw_type(paint(f"... {self.text}", "muted", dim=True))
        self._open = True
        sys.stdout.flush()
        return self

    def add(self, f: F.Finding) -> None:
        self.items.append(f)
        if _framed():
            for spans in _box_finding(f, self.width, STREAM_CHECK_WIDTH):
                _print_spans(spans)
        else:
            print_finding(f)
        sys.stdout.flush()

    def close(self) -> None:
        if not self._open:
            return
        self._open = False
        if _framed():
            _print_spans(_box_bottom(self.items, self.width))
        elif self.items:
            _tw_type(paint("\n" + _counts_text(self.items, " - "), "muted", dim=True))


def _status_line_status(status: str) -> str:
    return paint(f"[{status}]", _STATUS_ROLE.get(status, ""), bold=True)


# ------------------------------------------------------------------- banner
#
# The wordmark is a five-row table: every stem is two characters wide, so each
# letter reads as paired straight lines. Seven glyphs and a word space are all
# the tool needs, which keeps the stdlib-only install story intact.

WORDMARK = {
    "S": ("######", "##    ", "######", "    ##", "######"),
    "L": ("##    ", "##    ", "##    ", "##    ", "######"),
    "D": ("##### ", "##  ##", "##  ##", "##  ##", "##### "),
    "O": ("######", "##  ##", "##  ##", "##  ##", "######"),
    "C": ("######", "##    ", "##    ", "##    ", "######"),
    "T": ("######", "  ##  ", "  ##  ", "  ##  ", "  ##  "),
    "R": ("######", "##  ##", "######", "##  ##", "##  ##"),
}

WORDMARK_ROWS = 5
BANNER_NAME = "SSL DOCTOR"
BANNER_TAGLINE_PARTS = ("offline ssl/tls diagnostics", "client", "server",
                        "chain", "nginx")
BANNER_NOTE = "all checks are read-only; credentials are never logged"
BANNER_CREATOR = "eleven"
BANNER_CREDIT = f"creator: {BANNER_CREATOR}"


def wordmark(text: str, stroke: str = "#") -> List[str]:
    """Render `text` as WORDMARK_ROWS rows of two-stroke letters."""
    rows = [""] * WORDMARK_ROWS
    for index, char in enumerate(text):
        if char == " ":
            for row in range(WORDMARK_ROWS):
                rows[row] += "   "
            continue
        glyph = WORDMARK.get(char)
        if glyph is None:
            continue
        for row in range(WORDMARK_ROWS):
            rows[row] += glyph[row].replace("#", stroke)
        if index != len(text) - 1 and text[index + 1] != " ":
            for row in range(WORDMARK_ROWS):
                rows[row] += " "
    return [row.rstrip() for row in rows]


def banner_tagline() -> str:
    """Description line, using the ASCII separator when glyphs are unavailable."""
    sep = f" {_GLYPHS['sep']} "
    return sep.join(BANNER_TAGLINE_PARTS)


def banner_rows(columns: int, note: bool = True) -> List[List[tuple]]:
    """The banner as rows of (text, role, bold) spans, before centring.

    One description serves both presentations: the line REPL paints and
    centres it on the terminal, the full-screen shell centres it in its column.
    The two-stroke wordmark needs its own width plus margins; below that the
    banner collapses to a compact text form. `note` adds the read-only line.
    """
    sep = _GLYPHS["sep"]
    limit = max(20, columns - 2)  # never wider than the terminal
    art = wordmark(BANNER_NAME, _GLYPHS.block)
    art_width = max(len(row) for row in art)
    if limit >= art_width + 4:
        width = min(max(art_width, len(banner_tagline())) + 4, limit)
        rule = [(_GLYPHS.double * width, "primary", False)]
        rows = [rule]
        rows.extend([(row, "primary", True)] for row in art)
        rows.append([(banner_tagline(), "muted", False)])
        rows.append([(BANNER_CREDIT, "accent", True),
                     (f"  {sep}  v{__version__}", "muted", False)])
        if note:
            rows.append([(BANNER_NOTE, "muted", False)])
        rows.append(rule)
        return rows
    width = max(20, min(limit, MAX_BLOCK_WIDTH))
    rule = [(_GLYPHS.double * width, "primary", False)]
    return [rule,
            [(BANNER_NAME, "primary", True), (f"  {sep}  v{__version__}", "muted", False)],
            [("offline ssl/tls diagnostics", "muted", False)],
            [(BANNER_CREDIT, "accent", True)],
            rule]


def banner_lines(columns: Optional[int] = None) -> List[str]:
    """Return the banner as painted lines, centred on the terminal."""
    columns = terminal_width() if columns is None else columns
    lines = []
    for spans in banner_rows(columns):
        text_len = sum(len(text) for text, _, _ in spans)
        lead = " " * max(0, (columns - text_len) // 2)
        lines.append(lead + "".join(paint(text, role, bold) for text, role, bold in spans)
                     if spans else "")
    return lines


class _Phase:
    """Collects one phase's findings for :meth:`SSLDoctorCLI._results`."""

    def __init__(self, text: str, live: bool) -> None:
        self.live = live
        self.frame = LiveFrame(text)
        self.items: List[F.Finding] = []

    def add(self, f: F.Finding, first: bool = False) -> None:
        """Record one finding; `first` orders it ahead in a finished frame
        (a live frame has already drawn its predecessors)."""
        if any(f is seen for seen in self.items):
            return
        if first:
            self.items.insert(0, f)
        else:
            self.items.append(f)
        if self.live:
            self.frame.add(f)

    def done(self, items) -> List[F.Finding]:
        """Reconcile with what the checks returned; returns them as a list."""
        found = list(items) if isinstance(items, (list, tuple)) else [items]
        for f in found:
            self.add(f)
        return found

    def close(self) -> None:
        if self.live:
            self.frame.close()
        else:
            print_findings(self.items)


class _ResponseRecorder:
    """Tees a command's stdout into a colourless record of its response.

    Uses the shell's transcript parser, so escapes are dropped and spinner
    carriage returns overwrite instead of piling up -- the record is the text
    the operator saw. Input read through getpass never passes stdout, so a
    password cannot end up in it.
    """

    def __init__(self, inner) -> None:
        from . import tui as tuimod
        self.inner = inner
        self._record = tuimod.Transcript()

    def write(self, text: str) -> int:
        self._record.feed(text)
        return self.inner.write(text)

    def flush(self) -> None:
        self.inner.flush()

    def text(self) -> str:
        self._record.flush_partial()
        return "\n".join(line.rstrip() for line in self._record.lines).strip("\n")

    def __getattr__(self, name):
        return getattr(self.inner, name)


# ------------------------------------------------------------------- CLI


def remember_enabled(env, batch: bool, interactive: bool, no_remember: bool = False) -> bool:
    """Whether this session may offer to remember servers and use saved passwords."""
    setting = (env.get("SSL_DOCTOR_REMEMBER") or "").strip().lower()
    return (interactive and not batch and not no_remember
            and setting not in ("off", "0", "no", "false"))


@dataclass
class _ConnectSettings:
    """What /server connect needs, whether typed or taken from a profile."""
    host: str
    port: int
    username: str
    auth: str
    key_path: str = ""
    tls_host: str = ""
    tls_port: int = 443
    tls_explicit: bool = False
    profile: Optional[profilesmod.Profile] = None
    resave: bool = False            # a saved password could not be used: offer to replace it

    @classmethod
    def from_profile(cls, profile) -> "_ConnectSettings":
        return cls(host=profile.host, port=profile.port, username=profile.username,
                   auth=profile.auth, key_path=os.path.expanduser(profile.key_path),
                   tls_host=profile.tls_host or profile.host, tls_port=profile.tls_port,
                   tls_explicit=bool(profile.tls_host and profile.tls_host != profile.host),
                   profile=profile)


class SSLDoctorCLI:
    def __init__(self) -> None:
        self.store = F.FindingStore()
        self.net_timeout = 8.0
        self.command_timeout = 20.0  # remote command timeout (seconds)
        self.server: Optional[servermod.ServerSession] = None
        self.remote_facts: Dict = {}
        self._diagnosis = None
        self._running = True
        self._tui = None  # set while the full-screen shell is active
        # what the previous command printed (None until one ran), and every
        # command with its output, for /copy and /copy all
        self._last_response: Optional[str] = None
        self._session_log: List[str] = []
        self.use_tui: Optional[bool] = None  # None = decide from the terminal
        self._BATCH_MODE = False
        # remembered servers: loaded on first use (injectable for tests)
        self.no_remember = False
        self._profile_store: Optional[profilesmod.ProfileStore] = None
        self._secret_vault: Optional[vaultmod.SecretVault] = None
        # typewriter state
        self._typewriter_enabled = False
        self._typewriter_cps = 40.0
        global _TW_ENABLED, _TW_CPS, _TW_BATCH
        _TW_ENABLED = False
        _TW_CPS = 40.0
        _TW_BATCH = False

    @property
    def _STREAM_OUTPUT(self) -> bool:
        is_tty = bool(getattr(sys.stdout, "isatty", lambda: False)())
        return is_tty and not getattr(self, "_BATCH_MODE", False)

    @property
    def _batch_mode(self) -> bool:
        return getattr(self, "_BATCH_MODE", False)

    @property
    def _typewriter_active(self) -> bool:
        if not getattr(self, "_typewriter_enabled", False):
            return False
        if getattr(self, "_BATCH_MODE", False):
            return False
        return bool(getattr(sys.stdout, "isatty", lambda: False)())

    # ---------------- helpers ----------------
    def out(self, text: str = "") -> None:
        _tw_type(text)

    def error(self, text: str) -> None:
        _tw_type(paint(f"error: {text}", "error"))

    def note(self, text: str) -> None:
        _tw_type(paint(text, "muted"))

    # ---- frames -------------------------------------------------------
    def _composer_edge(self, top: bool) -> str:
        """Top or bottom border of the line REPL's composer, painted.

        The same rounded box the full-screen shell draws; only the input row
        has no right border, since the terminal echoes what is typed.
        """
        from . import tui as tuimod
        inner = block_width() - len(INDENT)
        if top:
            spans = tuimod.composer_border(
                [(APP_NAME.lower().replace(" ", "-"), "primary", True)],
                [(self.status_text(), "muted", False)], inner,
                (_GLYPHS.corner("╭", "+"), _GLYPHS.corner("╮", "+")),
                _GLYPHS.h, "primary")
        else:
            sep = f" {_GLYPHS['sep']} " if _GLYPHS.unicode else " - "
            spans = tuimod.composer_border(
                [(sep.join(("/help", "Ctrl-D quit")), "muted", False)],
                [(self._send_hint(), "muted", False)], inner,
                (_GLYPHS.corner("╰", "+"), _GLYPHS.corner("╯", "+")),
                _GLYPHS.h, "primary")
        return INDENT + "".join(paint(text, role, bold) for text, role, bold in spans)

    def status_text(self) -> str:
        """Plain one-liner: what is in scope, what was found, what is open."""
        target = ""
        if self.remote_facts.get("host"):
            target = f"{self.remote_facts['host']}:{self.remote_facts.get('port', 443)}"
        elif self.server and self.server.connected:
            cfg = self.server.cfg
            target = f"{cfg.tls_host or cfg.host}:{cfg.tls_port}"
        parts = [target] if target else []
        items = self.store.all()
        counts = _counts(items)
        if items:
            parts.append(f"{len(items)} findings")
            if counts[F.FAIL]:
                parts.append(f"{counts[F.FAIL]} fail")
        parts.append(f"timeout {self.net_timeout:g}s")
        parts.append("ssh " + ("on" if (self.server and self.server.connected) else "off"))
        separator = f" {_GLYPHS['sep']} " if _GLYPHS.unicode else " - "
        return separator.join(parts)

    def _question_frame(self, label: str, hints: str, default: str) -> str:
        """Lavender frame for a question that is waiting on the operator."""
        width = block_width(label)
        bar = _GLYPHS.vert
        body = paint(hints, "foreground") if hints else ""
        if default:
            body += paint(f"   default: {default}", "muted", dim=True)
        self.out(_frame_top(label, width, "accent"))
        if body:
            self.out(f"{INDENT}{paint(bar, 'accent')}  {body}")
        return f"{INDENT}{paint(bar, 'accent')}  {paint(_GLYPHS['run'], 'accent', bold=True)} "

    def prompt(self, label: str, default: str = "") -> str:
        if self._tui is not None:
            return self._tui.ask(label, default)
        if _MODE == ColorMode.PLAIN:
            suffix = f" [{default}]" if default else ""
            try:
                val = input(f"{label}{suffix}: ").strip()
            except EOFError:
                return default
            return val or default
        cursor = self._question_frame(label, _answer_hints(label, default), default)
        width = block_width(label)
        try:
            val = input(cursor).strip()
        except EOFError:
            print()
            val = ""
        self.out(_frame_bottom("", width, "accent"))
        return val or default

    def _meta(self) -> Dict:
        tgt = self.remote_facts
        target = ""
        if tgt.get("host"):
            target = f"{tgt['host']}:{tgt.get('port', 443)}"
        return {"target": target,
                "network_timeout": self.net_timeout,
                "command_timeout": self.command_timeout,
                "ssh_connected": bool(self.server and self.server.connected)}

    # ---------------- command dispatch ----------------
    def execute(self, line: str) -> bool:
        """Execute one command line. Returns False when the session should end."""
        line = line.strip()
        if not line:
            return True
        if not line.startswith("/"):
            if line.lower() in ("help", "?"):
                line = "/help"
            else:
                self.error("commands start with '/'. Try /help")
                return True
        try:
            args = shlex.split(line[1:])
        except ValueError as exc:
            self.error(str(exc))
            return True
        if not args:
            return True
        cmd, rest = args[0].lower(), args[1:]
        set_block_label(line)
        handler = getattr(self, f"cmd_{cmd}", None)
        if handler is None:
            self.error(f"unknown command /{cmd}. Try /help")
            return True
        # /copy is not a response of its own: repeating it copies the same text
        recorder = None if cmd == "copy" else _ResponseRecorder(sys.stdout)
        if recorder is not None:
            sys.stdout = recorder
        try:
            handler(rest)
        except KeyboardInterrupt:
            self.note("\ninterrupted")
        except Exception as exc:  # never crash the session on a check bug
            self.error(f"{type(exc).__name__}: {exc}")
        finally:
            if recorder is not None:
                sys.stdout = recorder.inner
                self._last_response = recorder.text()
                self._session_log.append(f"ssl-doctor> {line}")
                if self._last_response:
                    self._session_log.append(self._last_response)
        return self._running

    # ---------------- individual commands ----------------
    def cmd_help(self, args: List[str]) -> None:
        rows = [
            ("/scan [target]", "full workflow: identify domain -> client-side -> (SSH) server-side -> diagnosis"),
            ("/scan [target] --client-only", "only client-side: network path + this machine"),
            ("/scan [target] --server-only", "only server-side: SSH + nginx SSL config + presented-cert comparison"),
            ("/scan [target] --with-server", "combined run without the SSH yes/no prompt"),
            ("/tls <host> [port] [--sni name]", "remote TLS/HTTPS diagnostics (default port 443; URLs ok)"),
            ("/local", "diagnostics for this machine (Windows-aware)"),
            ("/cert inspect <file> [hostname]", "parse a PEM/DER certificate or chain file"),
            ("/cert match <cert> <key>", "verify a private key belongs to a certificate"),
            ("/server connect [name]", "SSH setup for authorized server-side checks (name: a remembered server)"),
            ("/servers", "list remembered servers; passwords live only in the OS credential vault"),
            ("/server forget <name>|--all", "forget a remembered server and its saved password"),
            ("/server forget-password <name>", "delete only the saved password"),
            ("/server status", "show SSH session state"),
            ("/server overview", "remote OS / web-server identification"),
            ("/server nginx [domain[:port]]", "examine nginx SSL config: vhost match, protocols, ciphers, cert/key"),
            ("/server cert <file> [key]", "inspect cert (and key pairing) on the server"),
            ("/server config", "scan readable web-server TLS/vhost configuration"),
            ("/server logs", "recent TLS-related service log entries (if readable)"),
            ("/server compare", "configured certificate vs certificate served on the network"),
            ("/server disconnect", "close the SSH session"),
            ("/diagnose", "correlate all findings into prioritized root causes"),
            ("/findings", "list everything recorded this session"),
            ("/copy [all]", "copy the previous command's response (all: the whole session)"),
            ("/report [html|json|both] [path]", "write a report (default: html)"),
            ("/report agent [dir]", "AI-ready agent-report.md + agent-report.json of the latest scan"),
            ("/timeout [seconds]", "show/set network timeout (default 8s)"),
            ("/clear", "discard recorded findings"),
            ("/version", "show version"),
            ("/typewriter [on|off|speed <n>]", "toggle typewriter output (tty only)"),
            ("/exit", "leave ssl-doctor"),
            ("--no-remember", "start option: never remember servers or use saved passwords "
                              "(also SSL_DOCTOR_REMEMBER=off)"),
        ]
        self.out(paint(f"{APP_NAME} commands:", "primary", bold=True))
        for c, d in rows:
            self.out(f"  {paint(f'{c:<44}', 'primary')} {paint(d, 'muted')}")

    def cmd_version(self, args: List[str]) -> None:
        self.out(f"{APP_NAME} v{__version__}")

    def cmd_exit(self, args: List[str]) -> None:
        if self.server:
            self.server.disconnect()
        self._running = False

    cmd_quit = cmd_exit           # type: ignore[assignment]

    def cmd_clear(self, args: List[str]) -> None:
        self.store.clear()
        self._diagnosis = None
        self.note("findings cleared")

    def cmd_timeout(self, args: List[str]) -> None:
        if not args:
            self.out(f"network timeout: {self.net_timeout}s · remote command timeout: "
                     f"{self.command_timeout}s  (usage: /timeout <net_s> [cmd_s])")
            return
        try:
            self.net_timeout = float(args[0])
            if len(args) > 1:
                self.command_timeout = float(args[1])
            self.out(f"timeouts set: network {self.net_timeout}s, "
                     f"remote commands {self.command_timeout}s")
        except ValueError:
            self.error("usage: /timeout <net_s> [cmd_s]")

    def cmd_typewriter(self, args: List[str]) -> None:
        global _TW_ENABLED, _TW_CPS, _TW_BATCH
        sub = args[0].lower() if args else "status"
        if sub in ("on", "off", "status"):
            if sub == "on":
                if not (sys.stdout.isatty() if hasattr(sys.stdout, "isatty") else False):
                    self.error("typewriter mode requires an interactive terminal")
                    return
                self._typewriter_enabled = True
            elif sub == "off":
                self._typewriter_enabled = False
            _TW_ENABLED = self._typewriter_enabled
            _TW_CPS = self._typewriter_cps
            _TW_BATCH = self._BATCH_MODE
            self.out(f"typewriter: {'on' if self._typewriter_enabled else 'off'} "
                     f"· speed {self._typewriter_cps:g} cps "
                     f"· active {self._typewriter_active}")
            return
        if sub == "speed":
            if len(args) < 2:
                self.error("usage: /typewriter speed <chars-per-second>")
                return
            try:
                cps = float(args[1])
            except ValueError:
                self.error("speed must be a number")
                return
            if cps < 1:
                self.error("speed must be >= 1")
                return
            self._typewriter_cps = cps
            _TW_ENABLED = self._typewriter_enabled
            _TW_CPS = cps
            _TW_BATCH = self._BATCH_MODE
            self.out(f"typewriter speed set to {cps:g} cps")
            return
        self.error("usage: /typewriter [on|off|speed <cps>]")

    def cmd_copy(self, args: List[str]) -> None:
        """`/copy`: the previous response; `/copy all`: the whole session."""
        if args and args[0].lower() != "all":
            self.error("usage: /copy [all]")
            return
        if args:
            what = "session transcript"
            text = ("\n".join(self._tui.transcript.lines).strip("\n")
                    if self._tui is not None else "\n".join(self._session_log))
        else:
            what = "previous response"
            text = self._last_response
            if text is None:
                self.note("nothing to copy yet - run a command first, then /copy")
                return
        if not text:
            self.note(f"nothing to copy - the {what} is empty")
            return
        self.note(self.copy_text(text))

    def copy_text(self, text: str) -> str:
        """Put `text` on the clipboard; returns the confirmation line."""
        from . import clipboard
        return clipboard.describe(clipboard.copy(text))

    def cmd_findings(self, args: List[str]) -> None:
        scope = args[0] if args else ""
        items = self.store.by_scope(scope) if scope else self.store.all()
        if not items:
            self.note("no findings recorded yet - run /scan or /tls first")
            return
        print_findings(items)

    # ---------------- /cert ----------------
    def cmd_cert(self, args: List[str]) -> None:
        if not args or args[0] == "inspect":
            rest = args[1:] if args and args[0] == "inspect" else args
            if not rest:
                self.error("usage: /cert inspect <file> [hostname]")
                return
            path = os.path.expanduser(rest[0])
            hostname = rest[1] if len(rest) > 1 else ""
            with self._results(f"inspecting {os.path.basename(path)}") as phase:
                items = phase.done(certmod.inspect_cert_file(path, hostname,
                                                             emit=phase.add))
            self.store.extend(items)
            return
        if args[0] == "match":
            if len(args) < 3:
                self.error("usage: /cert match <cert-file> <key-file>")
                return
            cpath, kpath = (os.path.expanduser(a) for a in args[1:3])
            self.note("key material is never displayed; only digests are compared")
            with self._results("comparing public keys") as phase:
                items = phase.done(certmod.match_cert_key(cpath, kpath,
                                                          emit=phase.add))
            self.store.extend(items)
            return
        self.error("usage: /cert inspect <file> [hostname] | /cert match <cert> <key>")

    # ---------------- /tls ----------------
    def _sni_arg(self, args: List[str]) -> Optional[str]:
        if "--sni" in args:
            i = args.index("--sni")
            if i + 1 < len(args):
                return args[i + 1]
        return None

    @contextlib.contextmanager
    def _results(self, text: str):
        """Run one check phase; its findings always land in one result frame.

        Streaming (an interactive terminal outside batch mode) opens the frame
        first and adds each finding as its check completes; otherwise the
        spinner runs and the finished frame is drawn at the end.  Yields the
        phase: pass `phase.add` as `emit` and hand the returned findings to
        `phase.done()` so one a check returned without emitting is not lost.
        """
        phase = _Phase(text, live=self._STREAM_OUTPUT)
        try:
            if phase.live:
                phase.frame.open()
                # the shell's status line owns progress (and keeps redrawing);
                # in the line REPL the frame's phase row says what is running
                with (Spinner(text) if _active_tui() is not None
                      else contextlib.nullcontext()):
                    yield phase
            else:
                with Spinner(text):
                    yield phase
        finally:
            phase.close()

    def _gather_remote(self, host: str, port: int, sni: Optional[str],
                      profile: bool = True) -> List[F.Finding]:
        with self._results(f"running remote TLS diagnostics against "
                           f"{host}:{port}") as phase:
            items, facts = netchecks.run_remote_diagnostics(
                host, port, sni=sni, timeout=self.net_timeout, emit=phase.add)
            phase.done(items)
            if profile and facts.get("cert"):
                prof = netchecks.domain_profile(
                    host, port, facts.get("ips", []), facts)
                items.insert(0, prof)
                phase.add(prof, first=True)
        self.store.extend(items)
        self.remote_facts = facts
        self._diagnosis = None
        return items

    def cmd_tls(self, args: List[str]) -> None:
        positional = [a for a in args if not a.startswith("--")]
        if not positional:
            self.error("usage: /tls <host|host:port|https://url> [--sni name]")
            return
        target = positional[0]
        if len(positional) > 1 and positional[1].isdigit():
            target = f"{positional[0]}:{positional[1]}"
        host, port, _scheme, err = netchecks.parse_target(target)
        if err:
            self.error(err)
            return
        self._gather_remote(host, port, self._sni_arg(args))
        self.out(paint("next: /diagnose or /report html", "muted", dim=True))

    cmd_remote = cmd_tls           # type: ignore[assignment]

    # ---------------- /local ----------------
    def cmd_local(self, args: List[str]) -> None:
        cert_path = args[0] if args else None
        with self._results("collecting local system information") as phase:
            items = phase.done(localmod.run_local_for_remote(
                self.remote_facts, cert_path, emit=phase.add))
        self.store.extend(items)

    # ---------------- /scan (guided) ----------------
    def cmd_scan(self, args: List[str]) -> None:
        pos = [a for a in args if not a.startswith("--")]
        target = pos[0] if pos else self.prompt("target hostname or host:port")
        host, port, _scheme, err = netchecks.parse_target(target)
        if err:
            self.error(err)
            return
        sni = self._sni_arg(args)
        mode = "combined"
        with_server = "--with-server" in args
        if "--server-only" in args:
            mode = "server"
        elif "--client-only" in args:
            mode = "client"

        if mode == "combined" and not with_server:
            ans = self.prompt("run authorized server-side checks too (SSH)? (yes/no)",
                              "no")
            with_server = ans.lower() in ("yes", "y")
        steps_total = {"client": 3, "server": 2}.get(
            mode, 4 if with_server else 3)
        step = 0

        def head(title: str) -> None:
            nonlocal step
            step += 1
            self.out(paint(f"\n{_GLYPHS['run']} Step {step}/{steps_total}: {title}",
                           "primary", bold=True))

        if mode in ("client", "combined"):
            head(f"domain identification + network checks for {host}:{port}")
            self._gather_remote(host, port, sni)
            head("client machine checks (this system)")
            self.cmd_local([])

        if mode == "server":
            head(f"server-side checks for {host}:{port} (SSH)")
            self._scan_server_side(host, port, sni)
        elif mode == "combined" and with_server:
            head("server-side checks (nginx SSL config, via SSH)")
            self._scan_server_side(host, port, sni)
        elif mode == "combined":
            self.note("server-side checks skipped; run later with /server connect or "
                      "/scan <target> --server-only")

        head("diagnosis")
        self.cmd_diagnose([])

    def _scan_server_side(self, host: str, port: int, sni: Optional[str]) -> None:
        """Authorized server-side sweep: nginx SSL config + presented-cert compare."""
        if not self.remote_facts.get("cert"):
            # presented cert is needed to compare 'configured vs served'
            with Spinner(f"measuring the public endpoint {host}:{port}"):
                dns_f, ips = netchecks.check_dns(host, self.net_timeout)
                hs_f, hs_facts = netchecks.check_tls_basic(
                    host, port, sni or (None if netchecks._is_ip(host) else host),
                    self.net_timeout)
            extras = [dns_f, hs_f,
                      netchecks.domain_profile(host, port, ips,
                                               {**hs_facts, "ips": ips})]
            self.store.extend(extras)
            self.remote_facts.update(hs_facts)
            print_findings(extras)
        if not (self.server and self.server.connected):
            match = self._profiles().match_domain(host) if not self._batch_mode else None
            if match is not None and self.prompt(
                    f"Use remembered server {match.name} ({match.endpoint})? (yes/no)",
                    "yes").lower() in ("yes", "y"):
                self._server_connect(profile=match)
            else:
                self._server_connect(offer_recent=match is None)
        if not (self.server and self.server.connected):
            return
        srv = self.server
        domain = srv.cfg.tls_host or host
        with self._results("reading server identity (read-only)") as phase:
            items = phase.done(srv.overview(emit=phase.add)
                               + srv.webserver_detection(emit=phase.add))
        self.store.extend(items)

        with self._results(f"examining nginx SSL configuration for "
                           f"'{domain}:{port}'") as phase:
            items = phase.done(srv.nginx_scan(domain, port, emit=phase.add))
        self.store.extend(items)

        presented = ""
        cert = self.remote_facts.get("cert")
        if cert:
            presented = cert.sha256
        with self._results("comparing configured and presented certificates, "
                           "scanning TLS service logs (read-only)") as phase:
            items = phase.done([srv.compare_configured_vs_presented(
                presented, emit=phase.add)] + srv.log_scan(emit=phase.add))
        self.store.extend(items)

    # ---------------- /server ----------------
    def cmd_server(self, args: List[str]) -> None:
        sub = args[0].lower() if args else "status"
        if sub == "connect":
            self._server_connect(args[1] if len(args) > 1 else "")
            return
        if sub in ("forget", "forget-password"):
            self._server_forget(args[1:], password_only=sub == "forget-password")
            return
        if sub == "disconnect":
            if self.server:
                self.server.disconnect()
                self.server = None
                self.out("SSH session closed")
            else:
                self.note("not connected")
            return
        if sub == "status":
            if self.server and self.server.connected:
                c = self.server.cfg
                self.out(f"connected: {c.username}@{c.host}:{c.port} "
                         f"(TLS target {c.tls_host or c.host}:{c.tls_port})")
            else:
                self.note("no active SSH session - /server connect")
            return

        if not (self.server and self.server.connected):
            self.error("not connected - run /server connect first")
            return
        srv = self.server
        if sub == "overview":
            with self._results("querying server") as phase:
                items = phase.done(srv.overview(emit=phase.add)
                                   + srv.webserver_detection(emit=phase.add))
        elif sub == "nginx":
            domain, port = srv.cfg.tls_host, srv.cfg.tls_port
            if len(args) > 1:
                domain, port, _scheme, err = netchecks.parse_target(args[1])
                if err:
                    self.error(err)
                    return
                if ":" not in args[1].split("//")[-1]:
                    port = srv.cfg.tls_port      # bare domain: session's TLS port
            with self._results(f"examining nginx SSL configuration for "
                               f"'{domain}:{port}'") as phase:
                items = phase.done(srv.nginx_scan(domain, port, emit=phase.add))
        elif sub == "cert":
            if len(args) < 2:
                self.error("usage: /server cert <remote-cert-path> [remote-key-path]")
                return
            cert_path = args[1]
            key_path = args[2] if len(args) > 2 else ""
            self.note("key material stays on the server; only digests are compared")
            paths = [cert_path] + ([key_path] if key_path else [])
            with self._results(f"inspecting {cert_path} on the server") as phase:
                items = phase.done(srv.scan_cert(cert_path, key_path, emit=phase.add)
                                   + srv.file_permissions(paths))
        elif sub == "config":
            with self._results("reading TLS/vhost configuration (read-only)") as phase:
                items = phase.done(srv.tls_config_scan(emit=phase.add))
        elif sub == "logs":
            with self._results("scanning service logs (read-only)") as phase:
                items = phase.done(srv.log_scan(emit=phase.add))
        elif sub == "compare":
            presented = ""
            cert = self.remote_facts.get("cert")
            if cert:
                presented = cert.sha256
            with self._results("comparing configured and presented "
                               "certificates") as phase:
                items = phase.done([srv.compare_configured_vs_presented(
                    presented, emit=phase.add)])
        else:
            self.error("usage: /server connect|status|overview|nginx [domain]|cert|"
                       "config|logs|compare|disconnect")
            return
        self.store.extend(items)

    # ---------------- remembered servers ----------------
    def _interactive_session(self) -> bool:
        if self._tui is not None:
            return True
        try:
            return sys.stdin.isatty() and sys.stdout.isatty()
        except Exception:
            return False

    def _remembering(self) -> bool:
        return remember_enabled(os.environ, batch=self._batch_mode,
                                interactive=self._interactive_session(),
                                no_remember=self.no_remember)

    def _profiles(self) -> profilesmod.ProfileStore:
        if self._profile_store is None:
            self._profile_store = profilesmod.ProfileStore(warn=self.note).load()
            if self._remembering():
                for name in self._profile_store.expire(self._vault()):
                    self.note(f"saved password for {name} expired after "
                              f"{vaultmod.EXPIRY_DAYS} days unused and was deleted")
        return self._profile_store

    def _vault(self) -> vaultmod.SecretVault:
        if self._secret_vault is None:
            self._secret_vault = vaultmod.open_vault(enabled=self._remembering())
        return self._secret_vault

    def _completer(self):
        """The shell's completion callback, with remembered servers as arguments."""
        def complete(prefix: str) -> List[tuple]:
            try:
                profiles = self._profiles().all()
            except Exception:
                profiles = []
            return command_completions(prefix, profiles=profiles)
        complete.completes_arguments = True       # type: ignore[attr-defined]
        return complete

    def cmd_servers(self, args: List[str]) -> None:
        store = self._profiles()
        rows = store.all()
        if not rows:
            self.note("No servers are remembered yet. After a successful /server connect "
                      "you are asked whether to remember it.")
            return
        vault_name = self._vault().name
        self.out(paint("Remembered servers", "primary", bold=True))
        self.out("  " + paint(f"{'NAME':<16} {'ENDPOINT':<36} {'AUTH':<9} "
                              f"{'PASSWORD':<10} LAST USED", "muted"))
        for p in rows:
            saved = "saved" if p.password_saved else "-"
            used = p.last_used[:10]
            self.out(f"  {p.name:<16} {p.endpoint:<36} {p.auth:<9} {saved:<10} {used}")
        if any(p.password_saved for p in rows):
            self.note(f"saved passwords are kept in {vault_name}, never in a file")
        if any(p.auth == "password" for p in rows):
            self.note("for password servers a key login (with ssh-agent) is the stronger "
                      "choice")
        sep = f" {_GLYPHS['sep']} " if _GLYPHS.unicode else " - "
        self.out(paint(f"connect: /server connect <name>{sep}forget: /server forget <name>",
                       "muted", dim=True))

    def _server_forget(self, args: List[str], password_only: bool) -> None:
        store = self._profiles()
        command = "/server forget-password" if password_only else "/server forget"
        if not args:
            self.error(f"usage: {command} <name>" + ("" if password_only else "|--all"))
            return
        if args[0] == "--all" and not password_only:
            everything = store.all()
            if not everything:
                self.note("no servers are remembered")
                return
            answer = self.prompt(f"Forget all {len(everything)} remembered servers and their "
                                 f"saved passwords? (yes/no)", "no").lower()
            if answer not in ("yes", "y"):
                self.note("nothing was forgotten")
                return
            for profile in everything:
                self._delete_saved_password(profile)
                store.forget(profile.name)
            self.note(f"forgot {len(everything)} remembered servers")
            return
        profile = store.get(args[0])
        if profile is None:
            close = store.closest(args[0])
            hint = f"; did you mean {', '.join(close)}?" if close else ""
            self.error(f"no remembered server named {args[0]!r}{hint}")
            return
        self._delete_saved_password(profile)
        if password_only:
            profile.password_saved = False
            store.save(profile)
            self.note(f"saved password for {profile.name} deleted; the server stays "
                      "remembered")
        else:
            store.forget(profile.name)
            self.note(f"forgot {profile.name} and any saved password")

    def _delete_saved_password(self, profile) -> None:
        # always, even when the profile says no password: a crash can orphan one
        try:
            self._vault().delete(vaultmod.target_for(profile))
        except vaultmod.VaultError as exc:
            self.note(f"could not delete the saved password for {profile.name}: {exc}")

    # ---------------- /server connect ----------------
    def _server_connect(self, name: str = "",
                        profile: Optional[profilesmod.Profile] = None,
                        offer_recent: bool = True) -> None:
        """settings -> host key -> secret -> session -> outcome (ADR-001).

        The password is asked for, or read from the vault, only once the host
        key is trusted, so no secret is ever collected for a refused host.
        """
        settings = self._connect_settings(name, profile, offer_recent)
        if settings is None:
            return
        key = self._verify_host_key(settings)
        if key is None:
            return
        fingerprints = servermod.sha256_fingerprints(key.fingerprints)
        password, source = "", ""
        if settings.auth == "password":
            password, source = self._saved_password(settings, fingerprints)
            if not password:
                password = self._ask_password()
                if password is None:
                    return
        connected, auth_failed = self._open_session(settings, password)
        if not connected and auth_failed and source:
            self._forget_password(settings.profile, "the server rejected the saved password")
            password = self._ask_password()
            if password is None:
                return
            source = ""
            connected, _ = self._open_session(settings, password)
        if connected:
            self._after_connect(settings, fingerprints, password, source)

    def _connect_settings(self, name: str, profile,
                          offer_recent: bool = True) -> Optional["_ConnectSettings"]:
        store = self._profiles()
        if name:
            profile = store.get(name)
            if profile is None:
                close = store.closest(name)
                hint = f"; did you mean {', '.join(close)}?" if close else ""
                self.error(f"no remembered server named {name!r}{hint} (/servers lists them)")
                return None
        elif profile is None and offer_recent and store.all() and not self._batch_mode:
            profile = self._pick_recent(store)
            if profile is False:
                return None
        if profile is not None:
            if profile.auth == "key" and not os.path.exists(os.path.expanduser(profile.key_path)):
                self.error(f"key not found: {profile.key_path}")
                return None
            self.out(paint(f"connecting to remembered server {profile.name} "
                           f"({profile.endpoint})", "primary", bold=True))
            return _ConnectSettings.from_profile(profile)
        return self._ask_settings(store)

    def _pick_recent(self, store):
        recent = store.recent(5)
        choices = "  ".join(f"{i}={p.name}" for i, p in enumerate(recent, 1))
        self.out(paint("Remembered servers:", "primary", bold=True))
        for i, p in enumerate(recent, 1):
            self.out(f"  {i}  {p.name:<16} {p.endpoint}")
        answer = self.prompt(f"server: {choices}  n=new server", "1").strip().lower()
        if answer in ("n", "new"):
            return None
        if answer.isdigit() and 1 <= int(answer) <= len(recent):
            return recent[int(answer) - 1]
        chosen = store.get(answer)
        if chosen is None:
            self.error(f"no remembered server {answer!r}")
            return False
        return chosen

    def _ask_settings(self, store) -> Optional["_ConnectSettings"]:
        self.out(paint("SSH connection setup (credentials are never displayed "
                       "or written to disk):", "primary", bold=True))
        host = self.prompt("SSH hostname or IP")
        if not host:
            self.error("hostname required")
            return None
        known = store.for_host(host)
        ssh_port_s = self.prompt("SSH port", str(known.port) if known else "22")
        if not ssh_port_s.isdigit():
            self.error("invalid port")
            return None
        user = self.prompt("SSH username", known.username if known else getpass.getuser())
        auth = ""
        default_auth = "1" if known and known.auth == "password" else "2"
        while auth not in ("1", "2"):
            auth = self.prompt("auth method: 1=password  2=private key", default_auth)
        key_path, method = "", "password" if auth == "1" else "key"
        if method == "key":
            default_key = known.key_path if known and known.key_path else "~/.ssh/id_rsa"
            key_path = os.path.expanduser(self.prompt("private key path", default_key))
            if not os.path.exists(key_path):
                self.error(f"key not found: {key_path}")
                return None
        default_tls = known.tls_host if known and known.tls_host != known.host else ""
        tls_host = self.prompt("TLS target hostname (blank = SSH host)", default_tls)
        tls_port_s = self.prompt("TLS target port", str(known.tls_port) if known else "443")
        tls_port = int(tls_port_s) if tls_port_s.isdigit() else 443
        settings = _ConnectSettings(host=host, port=int(ssh_port_s), username=user,
                                    auth=method, key_path=key_path,
                                    tls_host=tls_host or host, tls_port=tls_port,
                                    tls_explicit=bool(tls_host))
        if known and (known.port, known.username, known.auth) == \
                (settings.port, settings.username, settings.auth):
            settings.profile = known
        return settings

    def _verify_host_key(self, settings) -> Optional[servermod.HostKeyInfo]:
        host, port, user = settings.host, settings.port, settings.username
        timeout = self.net_timeout
        with Spinner(f"verifying host key of {host}"):
            key = servermod.host_key_status(host, port, timeout, user)
        if key.status == "unreachable":
            self.error(f"cannot reach the SSH service / host key: {key.detail}")
            self.store.add(F.Finding(
                "ssh.hostkey", "SSH host key verification", F.FAIL, F.SCOPE_SERVER,
                [key.detail], target=f"{host}:{port}"))
            return None
        if key.status == "changed":
            self.error("HOST KEY CHANGED - possible MITM. Refusing to connect.")
            for fp in key.fingerprints:
                self.out("  " + paint(fp, "error"))
            self.note("Verify with the server admin out-of-band, then remove the stale "
                      "entry from ~/.ssl-doctor/known_hosts before retrying.")
            self.store.add(F.Finding(
                "ssh.hostkey", "SSH host key verification", F.FAIL, F.SCOPE_SERVER,
                [key.detail, *key.fingerprints], target=f"{host}:{port}"))
            return None
        if key.status == "unknown":
            self.out(paint("The host key is not in the ssl-doctor trust store:", "warning"))
            for fp in key.fingerprints:
                self.out("  " + fp)
            ans = self.prompt("Trust this key and save it for future sessions? (yes/no)",
                              "no").lower()
            if ans not in ("yes", "y"):
                self.note("connection aborted before authentication")
                return None
            ok, msg = servermod.store_host_key(host, port, timeout, user)
            if not ok:
                self.error(msg)
                return None
            self.note(msg)
        return key

    def _saved_password(self, settings, fingerprints) -> tuple:
        """(password, vault name) when the vault releases one for this key."""
        profile = settings.profile
        if profile is None or not profile.password_saved:
            return "", ""
        store = self._vault()
        ok, reason = store.available()
        if not ok:
            self.note(f"saved password not available ({reason}); asking instead")
            return "", ""
        if profile.hostkey_fingerprints and not (set(fingerprints)
                                                 & set(profile.hostkey_fingerprints)):
            settings.resave = True
            self.note("the server's host key differs from the one the password was saved "
                      "with, so the saved password is not used")
            return "", ""
        try:
            secret = store.get(vaultmod.target_for(profile), fingerprints)
        except vaultmod.VaultError as exc:
            self.note(f"saved password not available ({exc}); asking instead")
            return "", ""
        if not secret:
            settings.resave = True
            self.note(f"no saved password found in {store.name}; asking instead")
            return "", ""
        self.note(f"password from {store.name}")
        return secret, store.name

    def _ask_password(self) -> Optional[str]:
        try:
            if self._tui is not None:
                password = self._tui.read_secret("SSH password (hidden)")
            else:
                password = getpass.getpass("SSH password (hidden): ")
        except EOFError:
            self.error("cannot read password in this terminal")
            return None
        if not password:
            self.error("empty password")
            return None
        return password

    def _open_session(self, settings, password: str) -> tuple:
        """(connected, authentication failed)."""
        cfg = servermod.SSHConfig(
            host=settings.host, port=settings.port, username=settings.username,
            auth=settings.auth, key_path=settings.key_path,
            connect_timeout=self.net_timeout, command_timeout=self.command_timeout,
            tls_host=settings.tls_host, tls_port=settings.tls_port)
        if self.server:
            self.server.disconnect()
        self.server = servermod.ServerSession(cfg, password=password)
        with Spinner(f"connecting to {settings.username}@{settings.host}"):
            items = self.server.connect()
        self.store.extend(items)
        print_findings(items)
        auth_failed = any(f.check == "ssh.auth" and f.status == F.FAIL for f in items)
        return bool(self.server.connected), auth_failed

    def _forget_password(self, profile, why: str) -> None:
        try:
            self._vault().delete(vaultmod.target_for(profile))
        except vaultmod.VaultError as exc:
            self.note(f"could not delete the saved password: {exc}")
        profile.password_saved = False
        self._profiles().save(profile)
        self.note(f"{why}; it was removed from {self._vault().name}")

    def _after_connect(self, settings, fingerprints, password: str, source: str) -> None:
        if settings.tls_explicit and settings.tls_host != settings.host:
            self.note(f"TLS target recorded as {settings.tls_host}:{settings.tls_port} "
                      f"(differs from SSH endpoint)")
        profile = settings.profile
        if self._remembering():
            if profile is None:
                self._offer_remember(settings, fingerprints, password)
            else:
                profile.last_used = profilesmod.now_iso()
                if (not source and password and settings.resave
                        and self._vault().available()[0]):
                    answer = self.prompt(f"Save this password for {profile.name} in "
                                         f"{self._vault().name}? (yes/no)", "no").lower()
                    if answer in ("yes", "y"):
                        self._store_password(profile, password, fingerprints)
                self._profiles().save(profile)
        self.out(paint("next: /server overview, /server cert <path> [key], "
                       "/server compare", "muted", dim=True))

    def _offer_remember(self, settings, fingerprints, password: str) -> None:
        store = self._profiles()
        ok, reason = self._vault().available()
        can_save = settings.auth == "password" and ok and bool(fingerprints)
        if settings.auth == "password" and not ok:
            self.note(f"passwords cannot be saved here: {reason}")
        options = "[P]rofile only  " + ("[S]ave password too  " if can_save else "") + "[N]o"
        answer = self.prompt(f"Remember this server? {options}", "p").strip().lower()
        if answer not in ("p", "profile", "s", "save") or (answer[0] == "s" and not can_save):
            if answer not in ("n", "no"):
                self.note("not remembered")
            return
        profile = profilesmod.Profile(
            name=profilesmod.default_name(settings.host, {p.name for p in store.all()}),
            host=settings.host, port=settings.port, username=settings.username,
            auth=settings.auth, key_path=settings.key_path, tls_host=settings.tls_host,
            tls_port=settings.tls_port, hostkey_fingerprints=fingerprints[:8])
        if answer[0] == "s":
            self._store_password(profile, password, fingerprints)
        store.save(profile)
        self.note(f"remembered as {profile.name} - next time: /server connect {profile.name}")

    def _store_password(self, profile, password: str, fingerprints) -> None:
        try:
            self._vault().put(vaultmod.target_for(profile), password, fingerprints)
        except vaultmod.VaultError as exc:
            self.note(f"password not saved: {exc}")
            profile.password_saved = False
            return
        profile.password_saved = True
        profile.hostkey_fingerprints = list(fingerprints)[:8]
        self.note(f"password saved in {self._vault().name}")

    # ---------------- /diagnose ----------------
    def cmd_diagnose(self, args: List[str]) -> None:
        items = self.store.all()
        if not items:
            self.note("nothing to diagnose yet - run /scan, /tls, /local or /server "
                      "checks first")
            return
        ctx = {"cert": self.remote_facts.get("cert")}
        self._diagnosis = diagnose(items, ctx)
        overall = self._diagnosis.overall
        self.out(paint("Diagnosis", "primary", bold=True) + "  " +
                 paint(overall, "success" if overall == F.PASS else
                       "error" if overall == F.FAIL else "warning", bold=True))
        if not self._diagnosis.causes:
            self.out("  no confirmed or probable root causes identified")
        for i, c in enumerate(self._diagnosis.causes, 1):
            mark = _CERTAINTY_ROLE.get(c.certainty, "muted")
            self.out(f"{INDENT}{i}. [{paint(c.certainty.upper(), mark, bold=True)}"
                     f" {paint(_GLYPHS['sep'], 'muted')} {c.origin}] {c.summary}")
            for e in c.evidence[:4]:
                self.out(paint(f"       evidence: {e}", dim=True))
            for lim in c.limitations:
                self.out(paint(f"       limit: {lim}", dim=True))
            if c.recommendation:
                self.out(paint(f"       fix: {c.recommendation}", "accent"))
        for u in self._diagnosis.unresolved:
            self.out(f"{INDENT}[{paint('UNRESOLVED', 'warning', bold=True)}"
                     f" {paint(_GLYPHS['sep'], 'muted')} {u.check}] {u.observed}")
            self.out(paint(f"       conclusion: {u.conclusion}", dim=True))
            for unc in u.uncertainty:
                self.out(paint(f"       uncertain: {unc}", dim=True))
            if u.recommendation:
                self.out(paint(f"       next: {u.recommendation}", "accent"))
        for n in self._diagnosis.notes:
            self.out(paint(f"  note: {n}", "muted", dim=True))
        self.note("\ngenerate a report with /report html")

    # ---------------- /report ----------------
    def _report_inputs(self, items: List[F.Finding]):
        """(diagnosis, meta, secrets, facts) shared by every report format."""
        diag = self._diagnosis
        if diag is None:
            diag = diagnose(items, {"cert": self.remote_facts.get("cert")})
            self._diagnosis = diag
        meta = self._meta()
        secrets = self.server.known_secrets() if self.server else []
        # Also emitted when no certificate was captured: the facts block carries
        # the handshake address and failure classification that explain why.
        facts = netchecks.export_facts(self.remote_facts) \
            if self.remote_facts.get("host") else None
        return diag, meta, secrets, facts

    def _agent_payload(self, items: List[F.Finding]) -> Dict:
        """The redacted findings document an agent report is made from.

        Built exactly like `/report json` (same diagnosis, facts, secrets and
        redaction); only `meta` gains the scan and environment context.
        """
        diag, meta, secrets, facts = self._report_inputs(items)
        meta = reportmod.agent_meta(meta, self.remote_facts, items)
        return reportmod.build_payload(items, diag, meta, secrets, facts)

    def _report_agent(self, directory: str) -> None:
        """`/report agent [dir]`: export the latest completed scan for an AI model.

        A completed `/tls` or `/scan` leaves `remote_facts` behind; `/clear`
        empties the store. Both documents are built in memory before anything
        is written, and the writer leaves either both files or neither.
        """
        items = self.store.all()
        if not (items and self.remote_facts.get("host")):
            self.error("no completed scan in this session - run /scan <target> or "
                       "/tls <target> first, then /report agent")
            return
        try:
            payload = self._agent_payload(items)
            markdown = reportmod.agent_markdown(payload)
            json_text = json.dumps(payload, ensure_ascii=False, indent=2,
                                   default=str) + "\n"
        except (TypeError, ValueError, KeyError) as exc:
            self.error(f"could not serialise the agent report: {type(exc).__name__}: {exc}")
            return
        directory = directory or f"ssl-doctor-agent-report-{time.strftime('%Y%m%d-%H%M%S')}"
        try:
            paths = reportmod.write_agent_report(directory, markdown, json_text)
        except OSError as exc:
            where = exc.filename or directory
            self.error(f"could not write the agent report: {where}: {exc.strerror or exc}")
            return
        counts = payload["summary"]
        overall = (payload.get("diagnosis") or {}).get("overall", "?")
        self.out(f"agent report written: {paint(os.path.abspath(paths[0]), 'accent')}")
        self.out(f"                      {paint(os.path.abspath(paths[1]), 'accent')}")
        self.note(f"{self.remote_facts['host']}:{self.remote_facts.get('port', 443)} "
                  f"{_GLYPHS['sep']} overall {overall} {_GLYPHS['sep']} "
                  f"{counts[F.PASS]} pass, {counts[F.FAIL]} fail, "
                  f"{counts[F.WARNING]} warning, {counts[F.NOT_TESTED]} not tested "
                  f"{_GLYPHS['sep']} give agent-report.md to the AI model of your choice")

    def cmd_report(self, args: List[str]) -> None:
        fmt = "html"
        path = ""
        for a in args:
            if a in ("html", "json", "both", "agent"):
                fmt = a
            else:
                path = a
        if fmt == "agent":
            self._report_agent(path)
            return
        items = self.store.all()
        if not items:
            self.note("no findings yet - run some checks first")
            return
        diag, meta, secrets, facts = self._report_inputs(items)
        ts = time.strftime("%Y%m%d-%H%M%S")
        written = []
        if fmt in ("json", "both"):
            p = path if path.lower().endswith(".json") else \
                (path + ".json" if path else f"ssl-doctor-report-{ts}.json")
            reportmod.write_json(p, items, diag, meta, secrets, facts)
            written.append(p)
        if fmt in ("html", "both"):
            p = path if (path and path.lower().endswith(".html")) else \
                (path + ".html" if path else f"ssl-doctor-report-{ts}.html")
            reportmod.write_html(p, items, diag, meta, secrets, facts)
            written.append(p)
        for p in written:
            self.out(f"report written: {paint(os.path.abspath(p), 'accent')}")

    # ---------------- full-screen shell ----------------
    def _capture_width(self, session) -> int:
        """Width of the transcript inside the shell's column (0 if unknown)."""
        from . import tui as tuimod
        try:
            columns, _ = session.size()
        except Exception:
            return 0
        # breathing room on the right of the frame
        return max(0, tuimod.block_width(columns) - tuimod.GUTTER * 2 - tuimod.FRAME_MARGIN)

    def _tui_header(self, width: int, rows: int) -> List[List]:
        """The centred banner: the full wordmark when the screen has the room.

        The full form takes nine rows, so short screens keep the compact one
        and leave the rows to the transcript.
        """
        # build_frame centres it and adds the room below
        return banner_rows(width if rows >= 24 else min(width, 40), note=False)

    def _composer_state(self, session) -> str:
        if getattr(session, "question", ""):
            return "ask"
        return "busy" if getattr(session, "status", None) else "ready"

    def _tui_hints(self, session, state: str, inner: int) -> List:
        """Key hints for the composer's bottom border, fitted by dropping the
        least important ones rather than clipping a word."""
        if state == "busy":
            return []
        arrows = "↑↓" if _GLYPHS.unicode else "up/down"
        if state == "ask":
            hint = _answer_hints(session.question, getattr(session, "default", ""))
            parts = [hint] if hint else ["Enter accepts the default"]
        elif getattr(session, "menu", None):
            parts = ["Tab complete", f"{arrows} select", "Esc close"]
        else:
            parts = ["Tab complete", f"{arrows} history", "drag or Ctrl-Y copies",
                     "PgUp scroll", "/help", "Ctrl-D quit"]
        sep = f" {_GLYPHS['sep']} " if _GLYPHS.unicode else " - "
        room = max(10, inner - 4 - len(self._send_hint()) - 4)
        while len(sep.join(parts)) > room and len(parts) > 1:
            parts.pop(-2 if len(parts) > 2 else -1)
        return [(sep.join(parts), "muted", False)]

    @staticmethod
    def _send_hint() -> str:
        return "⏎ send" if _GLYPHS.unicode else "Enter send"

    def _composer_placeholder(self, session, state: str) -> str:
        if state == "busy":
            return "running " + ("—" if _GLYPHS.unicode else "-") + \
                " Ctrl-C to interrupt"
        if state == "ask":
            if getattr(session, "masked", False):
                return "input is hidden"
            default = getattr(session, "default", "")
            return f"type an answer, or Enter for {default}" if default \
                else "type an answer"
        return "Type a command, e.g. /scan example.com"

    def _tui_menu(self, session, inner: int) -> List[List]:
        """The three-row completion list, drawn on top of the command bar."""
        if not getattr(session, "menu", None):
            return []
        name_width = min(max(len(name) for name, _ in session.menu), 12)
        rows: List[List] = []
        for index, (name, description) in enumerate(session.menu[:3]):
            chosen = index == getattr(session, "menu_index", 0)
            marker = _GLYPHS["run"] if chosen else " "
            room = max(8, inner - name_width - 4)
            if len(description) > room:
                description = description[:max(4, room - len(_GLYPHS.ellipsis))] + _GLYPHS.ellipsis
            rows.append([(marker + " ", "primary" if chosen else "muted", chosen),
                         (f"{name:<{name_width}}", "primary", chosen),
                         ("  ", "", False),
                         (description, "" if chosen else "muted", False)])
        return rows

    def _tui_frame(self, session):
        """Compose the frame; called by the shell on every redraw."""
        from . import tui as tuimod
        columns, rows = session.size()
        width = tuimod.block_width(columns)
        header = self._tui_header(width, rows)
        inner = max(4, width - tuimod.GUTTER * 2)
        menu = self._tui_menu(session, inner)
        state = self._composer_state(session)
        limit = tuimod.content_height(rows, len(header), len(menu))
        # left-aligned log: only real lines, so the composer follows the output
        window = getattr(session.transcript, "window", None)
        if window is not None:
            start, body = window(inner, limit, session.scroll)
        else:   # a stand-in transcript without a window (tests)
            start, body = 0, session.transcript.tail(inner, limit, session.scroll, fill=False)
        body = list(body)
        if session.scroll and body:
            body[0] = f".. {session.scroll} lines back (PgDn or wheel down to return)"
        # the label says what the composer is for; a question or a running
        # check replaces it, a copy confirmation shows once, and the session
        # summary sits on the right
        notice = getattr(session, "notice", None)
        if state != "ready":
            label = session.status
        elif notice:
            label = notice
        else:
            label = [(APP_NAME.lower().replace(" ", "-"), "primary", True)]
        layout = getattr(session, "layout", None)
        if layout is not None:
            layout.clear()
            layout["start"] = start
        highlight = (session.highlight(start, len(body), inner)
                     if hasattr(session, "highlight") else None)
        return tuimod.build_frame(
            columns=columns, rows=rows, header=header, body=body,
            status=[(self.status_text(), "muted", False)],
            prompt_text=session.display_text(), painter=paint_screen, glyphs=_GLYPHS,
            cursor=session.cursor, menu=menu, label=label, state=state,
            placeholder=self._composer_placeholder(session, state),
            hints=self._tui_hints(session, state, inner),
            send=[] if state == "busy" else [(self._send_hint(), "muted", False)],
            layout=layout, highlight=highlight)

    def _tui_run(self, session, line: str) -> None:
        """Execute one command with its output captured into the transcript."""
        global _CAPTURE
        # result frames are drawn to the transcript, not to the terminal
        set_capture_width(self._capture_width(session))
        session.transcript.append(f"ssl-doctor> {line}")
        captured = session.capture()
        saved = sys.stdout
        _CAPTURE = True
        try:
            sys.stdout = captured
            self.execute(line)
        finally:
            sys.stdout = saved
            _CAPTURE = False
        session.transcript.flush_partial()
        # blank line between commands so each command's output reads as a block
        if session.transcript.lines and session.transcript.lines[-1].strip():
            session.transcript.append("")
        session.render()

    def _repl_tui(self) -> int:
        from . import tui as tuimod
        session = tuimod.TuiSession(renderer=self._tui_frame,
                                    completer=self._completer(),
                                    on_copy=self.copy_text,
                                    last_response=lambda: self._last_response)
        set_capture_width(self._capture_width(session))
        self._tui = session
        set_active_tui(session)
        try:
            with session:
                session.transcript.append(
                    paint(f"Welcome. {APP_NAME} is read-only; credentials are "
                          f"never logged.", "muted"))
                session.transcript.append("")
                while self._running:
                    try:
                        line = session.read_line()
                    except KeyboardInterrupt:
                        # Ctrl-C at the command bar ends the session, exactly as in
                        # the line-oriented REPL; the shell restores the terminal.
                        break
                    if line is None:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    if line.lower() in ("/exit", "/quit", "exit", "quit"):
                        self.cmd_exit([])
                        break
                    session.scroll = 0
                    self._tui_run(session, line)
                    if not self._running:
                        break
        finally:
            set_active_tui(None)
            set_capture_width(0)
            self._tui = None
            if self.server:
                self.server.disconnect()
        self.note("bye")
        return 0

    # ---------------- REPL ----------------
    def banner(self) -> None:
        for line in banner_lines():
            self.out(line)
        hint = "Type /help for the command list."
        # the call to action sits under the centred banner, centred with it
        self.out(" " * max(0, (terminal_width() - len(hint)) // 2)
                 + paint(hint, "muted", dim=True))
        self.out("")

    def repl(self) -> int:
        from . import tui as tuimod
        if self.use_tui is None:
            self.use_tui = tuimod.enabled()
        if self.use_tui:
            try:
                return self._repl_tui()
            except Exception as exc:  # never strand the terminal
                self.note(f"full-screen mode unavailable: {type(exc).__name__}: {exc}")
                self.use_tui = False
        self.banner()
        framed = _MODE != ColorMode.PLAIN
        while self._running:
            if framed:
                self.out(self._composer_edge(top=True))
                mark = "❯ " if _GLYPHS.unicode else "> "
                prompt_text = (INDENT + paint(_GLYPHS.vert, "primary") + " "
                               + paint(mark, "primary", bold=True))
            else:
                prompt_text = "ssl-doctor> "
            try:
                line = input(prompt_text)
            except (EOFError, KeyboardInterrupt):
                if framed:
                    # nothing echoed a newline: close the box below the prompt
                    self.out("")
                    self.out(self._composer_edge(top=False))
                self.out("")
                break
            if framed:
                # close the composer before any output; the leading CR keeps
                # the frame tidy when the terminal never echoed a newline
                self.out("\r" + self._composer_edge(top=False))
            if line.strip().lower() in ("/exit", "/quit", "exit", "quit"):
                self.cmd_exit([])
                break
            self.execute(line)
        if self.server:
            self.server.disconnect()
        self.note("bye")
        return 0


# ------------------------------------------------------------------- main

def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if servermod.askpass_reply():          # started by ssh as its password helper
        return 0
    if argv[:1] == ["agent"]:
        from . import agent
        try:
            return agent.main(argv[1:])
        except agent.AgentError as exc:
            print(paint(f"error: {exc}", "error"))
            return 1
    cli = SSLDoctorCLI()

    batch: List[str] = []
    i = 0
    while i < len(argv):
        if argv[i] == "-c" and i + 1 < len(argv):
            batch.append(argv[i + 1])
            i += 2
        elif argv[i] == "--timeout" and i + 1 < len(argv):
            try:
                cli.net_timeout = float(argv[i + 1])
            except ValueError:
                pass
            i += 2
        elif argv[i] in ("--no-tui", "--plain"):
            cli.use_tui = False
            i += 1
        elif argv[i] == "--no-remember":
            cli.no_remember = True
            i += 1
        elif argv[i] == "--typewriter":
            cli._typewriter_enabled = True
            global _TW_ENABLED
            _TW_ENABLED = True
            i += 1
        elif argv[i] == "--typewriter-speed" and i + 1 < len(argv):
            try:
                cli._typewriter_cps = float(argv[i + 1])
                global _TW_CPS
                _TW_CPS = cli._typewriter_cps
            except ValueError:
                pass
            i += 2
        elif argv[i] in ("-h", "--help"):
            cli.banner()
            cli.cmd_help([])
            return 0
        elif argv[i].startswith("/"):
            batch.append(" ".join(argv[i:]))
            break
        else:
            i += 1

    if batch:
        cli._BATCH_MODE = True
        global _TW_BATCH
        _TW_BATCH = True
        cli.banner()
        for line in batch:
            print(paint(f"ssl-doctor> {line}", "primary", bold=True))
            if not cli.execute(line):
                break
        diag = cli._diagnosis
        if diag is None and len(cli.store):
            try:
                diag = diagnose(cli.store.all(), {})
            except Exception:
                diag = None
        return 1 if (diag and diag.overall == "FAIL") else 0
    return cli.repl()


if __name__ == "__main__":
    raise SystemExit(main())
