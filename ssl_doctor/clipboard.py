"""Clipboard delivery for text copied out of an interactive session.

Routes, all standard library only, tried so that a copy works on a stock
Windows or Linux desktop without installing anything:

* the operating system's clipboard, natively: the Win32 clipboard API on
  Windows, and on X11 (including XWayland) a small helper process that owns the
  CLIPBOARD selection and serves it -- the model `xclip` uses;
* a local clipboard tool when no native route applies or it failed
  (`wl-copy`, `xclip`, `xsel`, `pbcopy`, `clip.exe`), run from a fixed argument
  list without a shell;
* the terminal clipboard escape (OSC 52), which reaches the clipboard of the
  machine the terminal runs on -- the route for SSH sessions. Many terminals
  ignore it silently (VTE-based ones such as GNOME Terminal and xfce4-terminal
  do), so on its own it is never reported as a copy.

The copied text is never logged or echoed: confirmations carry only counts and
the routes used.
"""

from __future__ import annotations

import base64
import ctypes
import ctypes.util
import os
import platform as platform_mod
import shutil
import subprocess
import sys
import time
import warnings
from dataclasses import dataclass, field
from typing import Callable, List, Mapping, Optional, Sequence, Tuple

# Many terminals cap OSC 52 payloads; above this the escape is not sent.
OSC52_LIMIT = 100_000      # base64 characters
TOOL_TIMEOUT = 2.0         # seconds; a tool waiting on a missing display must not hang
TERMINAL_ROUTE = "terminal clipboard"
X11_ROUTE = "X11 clipboard"
WINDOWS_ROUTE = "Windows clipboard"
HELPER_READY_TIMEOUT = 2.0   # seconds the X11 helper may take to own the selection


@dataclass
class CopyResult:
    lines: int
    chars: int
    routes: List[str] = field(default_factory=list)     # routes that accepted the text
    failures: List[str] = field(default_factory=list)   # "<route>: <reason>"
    skipped: List[str] = field(default_factory=list)    # "<route>: <reason>"

    @property
    def confirmed(self) -> bool:
        """True when a local tool took the text; the escape alone is unconfirmed."""
        return any(route != TERMINAL_ROUTE for route in self.routes)


def osc52(text: str, env: Mapping[str, str]) -> str:
    """The clipboard escape for `text`, wrapped for tmux when inside it."""
    payload = base64.b64encode(text.encode("utf-8")).decode("ascii")
    sequence = f"\033]52;c;{payload}\a"
    if env.get("TMUX"):
        # tmux forwards an escape to the outer terminal only inside DCS passthrough
        sequence = "\033Ptmux;" + sequence.replace("\033", "\033\033") + "\033\\"
    return sequence


def _is_wsl(release: str) -> bool:
    return "microsoft" in release.lower()


def local_tool(env: Mapping[str, str], which: Callable[[str], Optional[str]] = shutil.which,
               platform: str = sys.platform,
               release: Optional[str] = None) -> Optional[List[str]]:
    """The first usable clipboard tool's argv for this machine, or None."""
    release = platform_mod.release() if release is None else release
    candidates: List[List[str]] = []
    if env.get("WAYLAND_DISPLAY"):
        candidates.append(["wl-copy"])
    if env.get("DISPLAY"):
        candidates += [["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]
    if platform == "darwin":
        candidates.append(["pbcopy"])
    if platform == "win32" or _is_wsl(release):
        candidates.append(["clip.exe"])
    for argv in candidates:
        if which(argv[0]):
            return argv
    return None


def _tool_input(argv: Sequence[str], text: str) -> bytes:
    # clip.exe reads the console code page unless the input carries a BOM
    if os.path.basename(argv[0]).lower() == "clip.exe":
        return b"\xff\xfe" + text.encode("utf-16-le")
    return text.encode("utf-8")


def copy(text: str, stream=None, env: Optional[Mapping[str, str]] = None,
         run: Callable = subprocess.run,
         which: Callable[[str], Optional[str]] = shutil.which,
         platform: str = sys.platform, release: Optional[str] = None,
         native: Optional[Sequence[Tuple[str, Callable[[str], Optional[str]]]]] = None
         ) -> CopyResult:
    """Send `text` to the clipboard routes available here; never raises.

    The OS clipboard is tried natively first; a clipboard tool only when no
    native route took the text; the terminal escape whenever a terminal is
    attached (it is what reaches a remote user's clipboard).

    `stream` is the real terminal (default: the process's original stdout, not
    a capture stream that would record the escape as transcript text).
    """
    env = os.environ if env is None else env
    stream = sys.__stdout__ if stream is None else stream
    result = CopyResult(lines=(text.count("\n") + 1) if text else 0, chars=len(text))

    try:
        is_tty = bool(stream.isatty())
    except Exception:
        is_tty = False
    if not is_tty:
        result.skipped.append(f"{TERMINAL_ROUTE}: output is not a terminal")
    else:
        sequence = osc52(text, env)
        if len(sequence) > OSC52_LIMIT:
            result.skipped.append(f"{TERMINAL_ROUTE}: text too large for the escape")
        else:
            try:
                stream.write(sequence)
                stream.flush()
                result.routes.append(TERMINAL_ROUTE)
            except Exception as exc:          # a closed terminal must not end the session
                result.failures.append(f"{TERMINAL_ROUTE}: {type(exc).__name__}")

    for name, route in (native_routes(env, platform) if native is None else native):
        try:
            error = route(text)
        except Exception as exc:                  # a broken library must not end the session
            error = f"{type(exc).__name__}: {exc}"
        if error is None:
            result.routes.append(name)
            return result
        result.failures.append(f"{name}: {error}")

    argv = local_tool(env, which, platform, release)
    if argv:
        name = os.path.basename(argv[0])
        try:
            done = run(argv, input=_tool_input(argv, text), shell=False,
                       timeout=TOOL_TIMEOUT, capture_output=True)
            if done.returncode == 0:
                result.routes.append(name)
            else:
                result.failures.append(f"{name}: exit status {done.returncode}")
        except subprocess.TimeoutExpired:
            result.failures.append(f"{name}: timed out")
        except OSError as exc:
            result.failures.append(f"{name}: {exc.strerror or type(exc).__name__}")
    return result


# ---------------------------------------------------------------- Windows

def windows_copy(text: str, user32=None, kernel32=None) -> Optional[str]:
    """Put `text` on the Windows clipboard; returns an error, or None on success.

    The clipboard keeps its own copy, so nothing has to outlive this call.
    Line ends become CRLF, which is what Windows applications paste.
    """
    if user32 is None or kernel32 is None:
        from ctypes import wintypes
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        user32.OpenClipboard.argtypes = [wintypes.HWND]
        user32.OpenClipboard.restype = wintypes.BOOL
        user32.EmptyClipboard.restype = wintypes.BOOL
        user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
        user32.SetClipboardData.restype = wintypes.HANDLE
        user32.CloseClipboard.restype = wintypes.BOOL
        kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
        kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
        kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
        kernel32.GlobalLock.restype = wintypes.LPVOID
        kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
        kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
    data = text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-16-le") + b"\0\0"
    for _ in range(10):                      # another program may hold it briefly
        if user32.OpenClipboard(None):
            break
        time.sleep(0.02)
    else:
        return "the clipboard is in use by another program"
    try:
        if not user32.EmptyClipboard():
            return "could not empty the clipboard"
        handle = kernel32.GlobalAlloc(0x0002, len(data))          # GMEM_MOVEABLE
        if not handle:
            return "out of memory"
        pointer = kernel32.GlobalLock(handle)
        if not pointer:
            kernel32.GlobalFree(handle)
            return "out of memory"
        ctypes.memmove(pointer, data, len(data))
        kernel32.GlobalUnlock(handle)
        if not user32.SetClipboardData(13, handle):               # CF_UNICODETEXT
            kernel32.GlobalFree(handle)                           # still ours on failure
            return "the clipboard refused the text"
        return None
    finally:
        user32.CloseClipboard()


# ------------------------------------------------------------------- X11

class _XSelectionRequestEvent(ctypes.Structure):
    _fields_ = [("type", ctypes.c_int), ("serial", ctypes.c_ulong),
                ("send_event", ctypes.c_int), ("display", ctypes.c_void_p),
                ("owner", ctypes.c_ulong), ("requestor", ctypes.c_ulong),
                ("selection", ctypes.c_ulong), ("target", ctypes.c_ulong),
                ("property", ctypes.c_ulong), ("time", ctypes.c_ulong)]


class _XSelectionEvent(ctypes.Structure):
    _fields_ = [("type", ctypes.c_int), ("serial", ctypes.c_ulong),
                ("send_event", ctypes.c_int), ("display", ctypes.c_void_p),
                ("requestor", ctypes.c_ulong), ("selection", ctypes.c_ulong),
                ("target", ctypes.c_ulong), ("property", ctypes.c_ulong),
                ("time", ctypes.c_ulong)]


_SELECTION_CLEAR, _SELECTION_REQUEST, _SELECTION_NOTIFY = 29, 30, 31


def _libx11():
    name = ctypes.util.find_library("X11")
    if not name:
        return None
    try:
        x = ctypes.CDLL(name)
    except OSError:
        return None
    x.XOpenDisplay.argtypes = [ctypes.c_char_p]
    x.XOpenDisplay.restype = ctypes.c_void_p
    x.XInternAtom.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
    x.XInternAtom.restype = ctypes.c_ulong
    x.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
    x.XDefaultRootWindow.restype = ctypes.c_ulong
    x.XCreateSimpleWindow.argtypes = [ctypes.c_void_p, ctypes.c_ulong] + [ctypes.c_int] * 2 \
        + [ctypes.c_uint] * 3 + [ctypes.c_ulong] * 2
    x.XCreateSimpleWindow.restype = ctypes.c_ulong
    x.XSetSelectionOwner.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong,
                                     ctypes.c_ulong]
    x.XGetSelectionOwner.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    x.XGetSelectionOwner.restype = ctypes.c_ulong
    x.XNextEvent.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    x.XChangeProperty.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong,
                                  ctypes.c_ulong, ctypes.c_int, ctypes.c_int,
                                  ctypes.c_void_p, ctypes.c_int]
    x.XSendEvent.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int, ctypes.c_long,
                             ctypes.c_void_p]
    x.XFlush.argtypes = [ctypes.c_void_p]
    x.XExtendedMaxRequestSize.argtypes = [ctypes.c_void_p]
    x.XExtendedMaxRequestSize.restype = ctypes.c_long
    x.XMaxRequestSize.argtypes = [ctypes.c_void_p]
    x.XMaxRequestSize.restype = ctypes.c_long
    return x


def _x11_serve(data: bytes, ready_fd: int) -> None:
    """Own CLIPBOARD and answer requests for it until another client takes it.

    Runs in the detached helper; reports `ok` or `error:<reason>` on `ready_fd`
    once ownership is (or is not) established. Uses only ctypes and `os`.
    """
    def ready(message: str) -> None:
        try:
            os.write(ready_fd, message.encode("utf-8", "replace") + b"\n")
            os.close(ready_fd)
        except OSError:
            pass

    x = _libx11()
    dpy = x.XOpenDisplay(None) if x else None
    if not dpy:
        ready("error:cannot open the X display")
        return
    # one ChangeProperty request must hold the whole text (no INCR transfer)
    limit = (x.XExtendedMaxRequestSize(dpy) or x.XMaxRequestSize(dpy)) * 4 - 64
    if len(data) > limit:
        ready("error:text too large for the X clipboard")
        return
    atom = lambda name: x.XInternAtom(dpy, name, 0)          # noqa: E731
    clipboard, targets, utf8 = atom(b"CLIPBOARD"), atom(b"TARGETS"), atom(b"UTF8_STRING")
    plain, text_atom, atom_type = atom(b"STRING"), atom(b"TEXT"), atom(b"ATOM")
    window = x.XCreateSimpleWindow(dpy, x.XDefaultRootWindow(dpy), 0, 0, 1, 1, 0, 0, 0)
    x.XSetSelectionOwner(dpy, clipboard, window, 0)
    if x.XGetSelectionOwner(dpy, clipboard) != window:
        ready("error:the X server did not hand over the clipboard")
        return
    ready("ok")
    offered = (ctypes.c_ulong * 4)(targets, utf8, plain, text_atom)
    buffer = ctypes.create_string_buffer(data, len(data))
    event = (ctypes.c_long * 24)()
    while True:
        x.XNextEvent(dpy, ctypes.byref(event))
        kind = ctypes.cast(event, ctypes.POINTER(ctypes.c_int))[0]
        if kind == _SELECTION_CLEAR:
            return                                          # someone else copied
        if kind != _SELECTION_REQUEST:
            continue
        request = ctypes.cast(event, ctypes.POINTER(_XSelectionRequestEvent)).contents
        answer = request.property or request.target         # obsolete clients: property 0
        if request.target == targets:
            x.XChangeProperty(dpy, request.requestor, answer, atom_type, 32, 0,
                              offered, len(offered))
        elif request.target in (utf8, plain, text_atom):
            x.XChangeProperty(dpy, request.requestor, answer,
                              utf8 if request.target == text_atom else request.target,
                              8, 0, buffer, len(data))
        else:
            answer = 0                                      # refuse unknown targets
        notify = _XSelectionEvent(type=_SELECTION_NOTIFY, serial=0, send_event=1,
                                  display=dpy, requestor=request.requestor,
                                  selection=request.selection, target=request.target,
                                  property=answer, time=request.time)
        x.XSendEvent(dpy, request.requestor, 0, 0, ctypes.byref(notify))
        x.XFlush(dpy)


def x11_copy(text: str, timeout: float = HELPER_READY_TIMEOUT) -> Optional[str]:
    """Hand `text` to a detached helper that owns the X11 CLIPBOARD.

    X11 keeps no clipboard of its own: the owner must stay alive to paste from,
    so a double-forked helper (detached from the terminal, stdio on /dev/null)
    serves it until another program copies -- desktop clipboard managers take
    it over when they keep history. Returns an error, or None once the helper
    owns the selection. A fork, not a new interpreter, so frozen builds work.
    """
    if not hasattr(os, "fork"):
        return "not available on this platform"
    if _libx11() is None:
        return "libX11 is not installed"
    data = text.encode("utf-8")
    read_fd, write_fd = os.pipe()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)   # fork with live threads
        pid = os.fork()
    if pid == 0:                                              # first child
        try:
            os.close(read_fd)
            os.setsid()
            if os.fork() == 0:                                # the helper
                null = os.open(os.devnull, os.O_RDWR)
                for fd in (0, 1, 2):
                    os.dup2(null, fd)
                os.closerange(3, write_fd)
                os.closerange(write_fd + 1, 256)
                _x11_serve(data, write_fd)
        finally:
            os._exit(0)
    os.close(write_fd)
    try:
        os.waitpid(pid, 0)                                    # the first child exits at once
        import select
        reply = b""
        deadline = time.monotonic() + timeout
        while not reply.endswith(b"\n"):
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([read_fd], [], [], left)[0]:
                return "the clipboard helper did not respond"
            chunk = os.read(read_fd, 512)
            if not chunk:
                return "the clipboard helper stopped"
            reply += chunk
    finally:
        os.close(read_fd)
    message = reply.decode("utf-8", "replace").strip()
    return None if message == "ok" else message.partition(":")[2] or message


def native_routes(env: Mapping[str, str], platform: str = sys.platform
                  ) -> List[Tuple[str, Callable[[str], Optional[str]]]]:
    """The operating-system clipboards reachable from here, best first."""
    if platform == "win32":
        return [(WINDOWS_ROUTE, windows_copy)]
    if env.get("DISPLAY"):
        return [(X11_ROUTE, x11_copy)]
    return []


# Shown whenever no route is confirmed: the terminal's own selection always works
# (most terminals let Shift bypass an application's mouse capture).
SHIFT_DRAG_HINT = "Shift+drag selects with the terminal itself"


def describe(result: CopyResult) -> str:
    """One-line confirmation: counts and routes, never the copied text.

    Only a route that took the text (the OS clipboard or a tool) is a copy; the
    terminal escape alone is reported as unconfirmed, with what to do instead.
    """
    size = f"{result.lines} line{'s' if result.lines != 1 else ''} · {result.chars} chars"
    problems = result.failures + [s for s in result.skipped
                                  if not s.startswith(f"{TERMINAL_ROUTE}: output is not")]
    if result.confirmed:
        text = f"copied {size} · {' + '.join(result.routes)}"
        return text + (f" ({'; '.join(problems)})" if problems else "")
    if result.routes:
        text = (f"copy not confirmed: {size} sent only to the {TERMINAL_ROUTE} (OSC 52), "
                f"which many terminals ignore - {SHIFT_DRAG_HINT}")
        return text + (f" ({'; '.join(problems)})" if problems else "")
    reasons = result.failures + result.skipped
    return (f"copy failed: no clipboard reachable for {size} - {SHIFT_DRAG_HINT}"
            + (f" ({'; '.join(reasons)})" if reasons else ""))
