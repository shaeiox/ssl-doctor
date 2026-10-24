"""Interactive command-line interface for SSL Doctor.

A persistent REPL with slash commands.  Presentation follows the Claude Code
terminal design language: semantic colour roles that degrade from TrueColor to
256 to 16 to plain, one frame per command, dashed ASCII input, hot-pink frames
around machine work and lavender frames around questions put back to the
operator.  Colour disables automatically when stdout is not a terminal, when
NO_COLOR is set, or when the terminal cannot render the glyphs.

Also supports one-shot batch usage:

    python3 ssldoctor.py -c "/tls example.com" -c "/report html out.html"
"""

from __future__ import annotations

import getpass
import os
import random
import shlex
import shutil
import sys
import textwrap
import threading
import time
from typing import Dict, List, Optional

from . import APP_NAME, __version__
from . import findings as F
from .analyze import diagnose
from . import certs as certmod
from . import local as localmod
from . import netchecks
from . import report as reportmod
from . import server as servermod

_TW_ENABLED = False
_TW_CPS = 40.0
_TW_BATCH = False


def _tw_type(text: str) -> None:
    """Print text, using the typewriter effect when active."""
    global _TW_ENABLED, _TW_CPS, _TW_BATCH
    active = (_TW_ENABLED and not _TW_BATCH
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
# Compatibility alias: older code and third-party snippets read this.
_USE_COLOR = _MODE != ColorMode.PLAIN


def set_color_mode(mode: str) -> None:
    """Re-resolve the palette (used by tests and embedding callers)."""
    global _MODE, _GLYPHS, _USE_COLOR
    _MODE = mode
    _GLYPHS = resolve_glyphs(mode)
    _USE_COLOR = mode != ColorMode.PLAIN


def paint(text: str, role: str = "", bold: bool = False, dim: bool = False) -> str:
    """Colour one string by semantic role; no-op in plain mode."""
    if _MODE == ColorMode.PLAIN or not text:
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


def _wrap(text: str, width: int) -> List[str]:
    """Wrap without dropping characters; long tokens are broken, not elided."""
    if width <= 0:
        return [text]
    lines = textwrap.wrap(text, width=max(12, width), break_long_words=True,
                          break_on_hyphens=False) or [""]
    return lines


def dashed_rule(width: int) -> str:
    """Signature input rule: hyphens and pipes, never Unicode box drawing."""
    width = max(MIN_BLOCK_WIDTH, width)
    return " ".join("-" for _ in range(max(1, (width + 1) // 2)))


# --------------------------------------------------------------- indicators

SPINNER_FRAMES = ["·", "✢", "✳", "✶", "✻", "✽"]
# reverse-mirror cycle: up one way, back the other
SPINNER_CYCLE = SPINNER_FRAMES + SPINNER_FRAMES[-2:0:-1]

SPINNER_VERBS = (
    "handshaking", "chaining", "ciphering", "pinning", "tracing", "sniffing",
    "untangling", "auditing", "decoding", "percolating", "ruminating",
    "noodling",
)


class Spinner:
    """Signature thinking indicator; one plain line when output is redirected."""

    def __init__(self, text: str, verb: Optional[str] = None) -> None:
        self.text = text
        self.verb = verb or random.choice(SPINNER_VERBS)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._dirty = False

    def __enter__(self) -> "Spinner":
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


def _print_row(f: F.Finding, verbose: bool, width: int, check_width: int) -> None:
    role = _STATUS_ROLE.get(f.status, "")
    bar = paint(_GLYPHS.vert, "tool")
    glyph = paint(_status_glyph(f.status), role, bold=True)
    status = paint(f"{f.status:<10}", role, bold=True)
    check = paint(f"{f.check:<{check_width}}", "muted")
    prefix = f"{_status_glyph(f.status)} {f.status:<10} {f.check:<{check_width}}"
    head = f"{INDENT}{bar} {glyph} {status} {check}"
    available = width - len(INDENT) - 2 - len(prefix)
    if available >= 20:
        title_lines = _wrap(f.title, available)
        _tw_type(head + title_lines[0])
        pad = " " * (len(INDENT) + 2 + len(prefix))
        for extra in title_lines[1:]:
            _tw_type(pad + extra)
    else:
        # narrow terminal: the title drops below the status row instead of
        # wrapping one word per line next to it
        _tw_type(f"{INDENT}{bar} {glyph} {status} {paint(f.check, 'muted')}")
        title_indent = f"{INDENT}{bar}   "
        for chunk in _wrap(f.title, width - len(INDENT) - 5):
            _tw_type(title_indent + chunk)
    if not verbose:
        return

    sub = f"{INDENT}{bar}   "
    body_width = width - len(INDENT) - 4
    for line in f.evidence:
        chunks = _wrap(line, body_width - 2)
        _tw_type(f"{sub}{paint(_GLYPHS['bullet'], 'muted')} {chunks[0]}")
        for chunk in chunks[1:]:
            _tw_type(f"{sub}  {chunk}")
    if f.detail:
        for chunk in _wrap(f.detail, body_width):
            _tw_type(sub + paint(chunk, dim=True))
    if f.recommendation:
        chunks = _wrap(f"fix: {f.recommendation}", body_width)
        _tw_type(sub + paint(chunks[0], "accent"))
        for chunk in chunks[1:]:
            _tw_type(f"{sub}{paint(chunk, 'accent')}")


def print_findings(items: List[F.Finding], verbose: bool = True) -> None:
    """Print a command's findings: framed rows on a terminal, plain otherwise."""
    if not items:
        return
    if _MODE == ColorMode.PLAIN:
        for f in items:
            print_finding(f, verbose)
        _tw_type(paint("\n" + _counts_text(items, " - "), "muted", dim=True))
        return

    width = block_width(_BLOCK_LABEL)
    check_width = min(max(len(f.check) for f in items) + 2, 24)
    _tw_type(_frame_top(_BLOCK_LABEL, width))
    for f in items:
        _print_row(f, verbose, width, check_width)
    _tw_type(_frame_bottom(_counts_line(items), width,
                        visible_len=len(_counts_text(items, " · "))))


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


def _banner_credit() -> str:
    return f"{BANNER_CREDIT}  {_GLYPHS['sep']}  v{__version__}"


def banner_lines(columns: Optional[int] = None) -> List[str]:
    """Return the banner as painted lines, sized for the terminal."""
    columns = terminal_width() if columns is None else columns
    limit = max(20, columns - 2)  # never wider than the terminal
    art = wordmark(BANNER_NAME, _GLYPHS.block)
    art_width = max(len(row) for row in art)
    # the full wordmark needs its own width plus margins; below that, compact
    if limit >= art_width + 4:
        content = max(art_width, len(banner_tagline()), len(BANNER_NOTE),
                      len(_banner_credit()))
        width = min(content + 4, limit)
        lines = [paint(_GLYPHS.double * width, "primary")]
        for row in art:
            lines.append(INDENT + paint(row, "primary", bold=True))
        lines.append("")
        lines.append(INDENT + paint(banner_tagline(), "muted"))
        lines.append(INDENT + paint(_banner_credit(), "accent", bold=True))
        lines.append(INDENT + paint(BANNER_NOTE, "muted", dim=True))
        lines.append(paint(_GLYPHS.double * width, "primary"))
        return lines

    width = max(20, min(limit, MAX_BLOCK_WIDTH))
    lines = [paint(_GLYPHS.double * width, "primary"),
             INDENT + paint(BANNER_NAME, "primary", bold=True)
             + paint(f"  ·  v{__version__}", "muted"),
             INDENT + paint("offline ssl/tls diagnostics", "muted"),
             INDENT + paint(BANNER_CREDIT, "accent", bold=True),
             paint(_GLYPHS.double * width, "primary")]
    return lines


# ------------------------------------------------------------------- CLI


class SSLDoctorCLI:
    def __init__(self) -> None:
        self.store = F.FindingStore()
        self.net_timeout = 8.0
        self.cmd_timeout = 20.0
        self.server: Optional[servermod.ServerSession] = None
        self.remote_facts: Dict = {}
        self._diagnosis = None
        self._running = True
        self._BATCH_MODE = False
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
    def _rule(self) -> str:
        return paint(dashed_rule(block_width()), "muted")

    def status_line(self) -> str:
        """One muted line: what is in scope, what was found, what is open."""
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
        return paint(" · ".join(parts), "muted", dim=True)

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
                "command_timeout": self.cmd_timeout,
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
        try:
            handler(rest)
        except KeyboardInterrupt:
            self.note("\ninterrupted")
        except Exception as exc:  # never crash the session on a check bug
            self.error(f"{type(exc).__name__}: {exc}")
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
            ("/server connect", "interactive SSH setup for authorized server-side checks"),
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
            ("/report [html|json|both] [path]", "write a report (default: html)"),
            ("/timeout [seconds]", "show/set network timeout (default 8s)"),
            ("/clear", "discard recorded findings"),
            ("/version", "show version"),
            ("/typewriter [on|off|speed <n>]", "toggle typewriter output (tty only)"),
            ("/exit", "leave ssl-doctor"),
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
                     f"{self.cmd_timeout}s  (usage: /timeout <net_s> [cmd_s])")
            return
        try:
            self.net_timeout = float(args[0])
            if len(args) > 1:
                self.cmd_timeout = float(args[1])
            self.out(f"timeouts set: network {self.net_timeout}s, "
                     f"remote commands {self.cmd_timeout}s")
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
            items = self._run_phase(f"inspecting {os.path.basename(path)}",
                                    certmod.inspect_cert_file, path, hostname)
            self.store.extend(items)
            return
        if args[0] == "match":
            if len(args) < 3:
                self.error("usage: /cert match <cert-file> <key-file>")
                return
            cpath, kpath = (os.path.expanduser(a) for a in args[1:3])
            self.note("key material is never displayed; only digests are compared")
            items = self._run_phase("comparing public keys",
                                    certmod.match_cert_key, cpath, kpath)
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

    def _emit_finding(self, f: F.Finding) -> None:
        print_finding(f)

    def _run_phase(self, text: str, fn, *args, **kwargs):
        if self._STREAM_OUTPUT:
            self.out(paint(f"... {text}", "muted", dim=True))
            sys.stdout.flush()
            emit = self._emit_finding
            try:
                result = fn(*args, emit=emit, **kwargs)
            except TypeError:
                result = fn(*args, **kwargs)
                self._emit_result(result)
            return result
        with Spinner(text):
            result = fn(*args, **kwargs)
        self._print_result(result)
        return result

    def _emit_result(self, result) -> None:
        if result is None:
            return
        if isinstance(result, tuple):
            result = result[0]
        if isinstance(result, list):
            for f in result:
                self._emit_finding(f)
        else:
            self._emit_finding(result)

    def _print_result(self, result) -> None:
        if result is None:
            return
        if isinstance(result, tuple):
            result = result[0]
        if isinstance(result, list):
            print_findings(result)
        else:
            print_finding(result)

    def _gather_remote(self, host: str, port: int, sni: Optional[str],
                      profile: bool = True) -> List[F.Finding]:
        text = f"running remote TLS diagnostics against {host}:{port}"
        result = self._run_phase(text, netchecks.run_remote_diagnostics,
                                 host, port, sni=sni, timeout=self.net_timeout)
        items, facts = result
        if profile and facts.get("cert"):
            prof = netchecks.domain_profile(
                host, port, facts.get("ips", []), facts)
            items.insert(0, prof)
            if self._STREAM_OUTPUT:
                self._emit_finding(prof)
            else:
                print_finding(prof)
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
        items = self._run_phase("collecting local system information",
                                localmod.run_local_for_remote, self.remote_facts, cert_path)
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
            self._server_connect()
        if not (self.server and self.server.connected):
            return
        srv = self.server
        domain = srv.cfg.tls_host or host
        if self._STREAM_OUTPUT:
            self.out(paint("... reading server identity (read-only)", "muted", dim=True))
            sys.stdout.flush()
            items = srv.overview(emit=self._emit_finding) + srv.webserver_detection(emit=self._emit_finding)
        else:
            with Spinner("reading server identity (read-only)"):
                items = srv.overview() + srv.webserver_detection()
            print_findings(items)
        self.store.extend(items)

        if self._STREAM_OUTPUT:
            self.out(paint(f"... examining nginx SSL configuration for '{domain}:{port}'", "muted", dim=True))
            sys.stdout.flush()
            items = srv.nginx_scan(domain, port, emit=self._emit_finding)
        else:
            with Spinner(f"examining nginx SSL configuration for '{domain}:{port}'"):
                items = srv.nginx_scan(domain, port)
            print_findings(items)
        self.store.extend(items)

        presented = ""
        cert = self.remote_facts.get("cert")
        if cert:
            presented = cert.sha256
        cmp_f = srv.compare_configured_vs_presented(
            presented, emit=self._emit_finding if self._STREAM_OUTPUT else None)
        if not self._STREAM_OUTPUT:
            print_finding(cmp_f)
        items = [cmp_f]

        if self._STREAM_OUTPUT:
            self.out(paint("... scanning TLS service logs (read-only)", "muted", dim=True))
            sys.stdout.flush()
            log_items = srv.log_scan(emit=self._emit_finding)
        else:
            with Spinner("scanning TLS service logs (read-only)"):
                log_items = srv.log_scan()
            print_findings(log_items)
        items = items + log_items
        self.store.extend(items)

    # ---------------- /server ----------------
    def cmd_server(self, args: List[str]) -> None:
        sub = args[0].lower() if args else "status"
        if sub == "connect":
            self._server_connect()
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
            if self._STREAM_OUTPUT:
                self.out(paint("... querying server", "muted", dim=True))
                sys.stdout.flush()
                items = srv.overview(emit=self._emit_finding) + srv.webserver_detection(emit=self._emit_finding)
            else:
                with Spinner("querying server"):
                    items = srv.overview() + srv.webserver_detection()
        elif sub == "nginx":
            domain, port = srv.cfg.tls_host, srv.cfg.tls_port
            if len(args) > 1:
                domain, port, _scheme, err = netchecks.parse_target(args[1])
                if err:
                    self.error(err)
                    return
                if ":" not in args[1].split("//")[-1]:
                    port = srv.cfg.tls_port      # bare domain: session's TLS port
            if self._STREAM_OUTPUT:
                self.out(paint(f"... examining nginx SSL configuration for '{domain}:{port}'", "muted", dim=True))
                sys.stdout.flush()
                items = srv.nginx_scan(domain, port, emit=self._emit_finding)
            else:
                with Spinner(f"examining nginx SSL configuration for '{domain}:{port}'"):
                    items = srv.nginx_scan(domain, port)
        elif sub == "cert":
            if len(args) < 2:
                self.error("usage: /server cert <remote-cert-path> [remote-key-path]")
                return
            cert_path = args[1]
            key_path = args[2] if len(args) > 2 else ""
            self.note("key material stays on the server; only digests are compared")
            if self._STREAM_OUTPUT:
                self.out(paint(f"... inspecting {cert_path} on the server", "muted", dim=True))
                sys.stdout.flush()
                items = srv.scan_cert(cert_path, key_path, emit=self._emit_finding)
                paths = [cert_path] + ([key_path] if key_path else [])
                perm_items = srv.file_permissions(paths)
                for f in perm_items:
                    self._emit_finding(f)
                items = items + perm_items
            else:
                with Spinner(f"inspecting {cert_path} on the server"):
                    items = srv.scan_cert(cert_path, key_path)
                    paths = [cert_path] + ([key_path] if key_path else [])
                    items += srv.file_permissions(paths)
        elif sub == "config":
            if self._STREAM_OUTPUT:
                self.out(paint("... reading TLS/vhost configuration (read-only)", "muted", dim=True))
                sys.stdout.flush()
                items = srv.tls_config_scan(emit=self._emit_finding)
            else:
                with Spinner("reading TLS/vhost configuration (read-only)"):
                    items = srv.tls_config_scan()
        elif sub == "logs":
            if self._STREAM_OUTPUT:
                self.out(paint("... scanning service logs (read-only)", "muted", dim=True))
                sys.stdout.flush()
                items = srv.log_scan(emit=self._emit_finding)
            else:
                with Spinner("scanning service logs (read-only)"):
                    items = srv.log_scan()
        elif sub == "compare":
            presented = ""
            cert = self.remote_facts.get("cert")
            if cert:
                presented = cert.sha256
            cmp_f = srv.compare_configured_vs_presented(
                presented, emit=self._emit_finding if self._STREAM_OUTPUT else None)
            if not self._STREAM_OUTPUT:
                print_finding(cmp_f)
            items = [cmp_f]
        else:
            self.error("usage: /server connect|status|overview|nginx [domain]|cert|"
                       "config|logs|compare|disconnect")
            return
        self.store.extend(items)
        if not self._STREAM_OUTPUT:
            print_findings(items)

    def _server_connect(self) -> None:
        self.out(paint("SSH connection setup (credentials are never displayed "
                       "or written to disk):", "primary", bold=True))
        host = self.prompt("SSH hostname or IP")
        if not host:
            self.error("hostname required")
            return
        ssh_port_s = self.prompt("SSH port", "22")
        if not ssh_port_s.isdigit():
            self.error("invalid port")
            return
        user = self.prompt("SSH username", getpass.getuser())
        auth = ""
        while auth not in ("1", "2"):
            auth = self.prompt("auth method: 1=password  2=private key", "2")
        password, key_path, method = "", "", "key"
        if auth == "1":
            method = "password"
            try:
                password = getpass.getpass("SSH password (hidden): ")
            except EOFError:
                self.error("cannot read password in this terminal")
                return
            if not password:
                self.error("empty password")
                return
        else:
            key_path = os.path.expanduser(self.prompt("private key path",
                                                      "~/.ssh/id_rsa"))
            if not os.path.exists(key_path):
                self.error(f"key not found: {key_path}")
                return
        tls_host = self.prompt("TLS target hostname (blank = SSH host)", "")
        tls_port_s = self.prompt("TLS target port", "443")
        tls_port = int(tls_port_s) if tls_port_s.isdigit() else 443

        timeout = self.net_timeout
        with Spinner(f"verifying host key of {host}"):
            key = servermod.host_key_status(host, int(ssh_port_s), timeout)
        if key.status == "unreachable":
            self.error(f"cannot reach the SSH service / host key: {key.detail}")
            self.store.add(F.Finding(
                "ssh.hostkey", "SSH host key verification", F.FAIL, F.SCOPE_SERVER,
                [key.detail], target=f"{host}:{ssh_port_s}"))
            return
        if key.status == "changed":
            self.error("HOST KEY CHANGED - possible MITM. Refusing to connect.")
            for fp in key.fingerprints:
                self.out("  " + paint(fp, "error"))
            self.note("Verify with the server admin out-of-band, then remove the stale "
                      "entry from ~/.ssl-doctor/known_hosts before retrying.")
            self.store.add(F.Finding(
                "ssh.hostkey", "SSH host key verification", F.FAIL, F.SCOPE_SERVER,
                [key.detail, *key.fingerprints], target=f"{host}:{ssh_port_s}"))
            return
        if key.status == "unknown":
            self.out(paint("The host key is not in the ssl-doctor trust store:", "warning"))
            for fp in key.fingerprints:
                self.out("  " + fp)
            ans = self.prompt("Trust this key and save it for future sessions? (yes/no)",
                              "no").lower()
            if ans not in ("yes", "y"):
                self.note("connection aborted before authentication")
                return
            ok, msg = servermod.store_host_key(host, int(ssh_port_s), timeout)
            if not ok:
                self.error(msg)
                return
            self.note(msg)

        cfg = servermod.SSHConfig(
            host=host, port=int(ssh_port_s), username=user, auth=method,
            key_path=key_path, connect_timeout=timeout,
            command_timeout=self.cmd_timeout,
            tls_host=tls_host or host, tls_port=tls_port)
        if self.server:
            self.server.disconnect()
        self.server = servermod.ServerSession(cfg, password=password)
        with Spinner(f"connecting to {user}@{host}"):
            items = self.server.connect()
        self.store.extend(items)
        print_findings(items)
        if self.server.connected:
            if tls_host and tls_host != host:
                self.note(f"TLS target recorded as {tls_host}:{tls_port} (differs from "
                          f"SSH endpoint)")
            self.out(paint("next: /server overview, /server cert <path> [key], "
                           "/server compare", "muted", dim=True))

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
    def cmd_report(self, args: List[str]) -> None:
        fmt = "html"
        path = ""
        for a in args:
            if a in ("html", "json", "both"):
                fmt = a
            else:
                path = a
        items = self.store.all()
        if not items:
            self.note("no findings yet - run some checks first")
            return
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

    # ---------------- REPL ----------------
    def banner(self) -> None:
        for line in banner_lines():
            self.out(line)
        self.out(paint("Type /help for the command list.", "muted", dim=True))
        self.out("")

    def repl(self) -> int:
        self.banner()
        framed = _MODE != ColorMode.PLAIN
        while self._running:
            if framed:
                self.out(self.status_line())
                self.out(self._rule())
                prompt_text = paint("| > ", "primary", bold=True)
            else:
                prompt_text = "ssl-doctor> "
            try:
                line = input(prompt_text)
            except (EOFError, KeyboardInterrupt):
                if framed:
                    self.out("\r" + self._rule())
                self.out("")
                break
            if framed:
                # close the input box before any output; the leading CR keeps
                # the frame tidy when the terminal never echoed a newline
                self.out("\r" + self._rule())
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
