"""Which interactive presentation a terminal can carry, and why.

The full-screen shell draws on the terminal's alternate screen, which has no
scrollback of its own: the transcript scrolls only through the shell (wheel,
PageUp/PageDown). That works wherever the shell gets keys and, for the wheel,
mouse events -- POSIX terminals, Windows Terminal, VS Code, ConEmu, and the
classic Windows console or winpty once the key reader sets the right console
mode (see `tui.console_read_mode`). Where it cannot work -- output that is not
a terminal, `TERM=dumb`, a Windows console that does not process VT sequences --
the line REPL is used instead, so the terminal's own scrollback and wheel do.

`detect()` is pure (environment and capabilities are passed in) so every row of
that table is tested without the terminal it describes.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping

_OFF = ("0", "false", "no", "off", "plain")


@dataclass(frozen=True)
class TerminalProfile:
    host: str            # a readable name for the terminal, for messages and reports
    fullscreen: bool     # alternate-screen shell (else the line REPL)
    mouse: bool          # the shell captures wheel/drag (else the terminal keeps them)
    reason: str = ""     # why the full-screen shell or the mouse is off

    @property
    def description(self) -> str:
        mode = "full-screen shell" if self.fullscreen else "line mode"
        mouse = (", mouse wheel and selection" if self.mouse else ", scroll with PgUp/PgDn") \
            if self.fullscreen else ", the terminal's own scrollback"
        return f"{self.host}: {mode}{mouse}"


def host_name(env: Mapping[str, str], windows: bool) -> str:
    if env.get("WT_SESSION"):
        return "Windows Terminal"
    if env.get("TERM_PROGRAM") == "vscode":
        return "VS Code terminal"
    if env.get("ConEmuPID") or env.get("ConEmuANSI"):
        return "ConEmu"
    if windows and (env.get("MSYSTEM") or env.get("TERM_PROGRAM") == "mintty"):
        return "mintty (Git Bash / MSYS2)"
    if windows:
        return "Windows console (conhost)"
    return env.get("TERM_PROGRAM") or env.get("TERM") or "terminal"


def detect(env: Mapping[str, str], windows: bool, stdin_tty: bool, stdout_tty: bool,
           keys_ok: bool, vt_ok: bool) -> TerminalProfile:
    """The presentation this terminal gets. The first reason that applies wins."""
    host = host_name(env, windows)

    def line(reason: str) -> TerminalProfile:
        return TerminalProfile(host, False, False, reason)

    if (env.get("SSL_DOCTOR_TUI") or "").strip().lower() in _OFF:
        return line("the full-screen shell is turned off (SSL_DOCTOR_TUI / --no-tui)")
    if not (stdin_tty and stdout_tty):
        return line("input or output is not a terminal (pipe, file, or a terminal "
                    "such as mintty without winpty)")
    if (env.get("TERM") or "").strip().lower() == "dumb":
        return line("TERM=dumb")
    if not keys_ok:
        return line("key input cannot be read one key at a time here")
    if windows and not vt_ok:
        return line("this console cannot process VT sequences (legacy console mode or an "
                    "old Windows build), so its own scrollback is used")
    if (env.get("SSL_DOCTOR_MOUSE") or "").strip().lower() in _OFF:
        return TerminalProfile(host, True, False,
                               "mouse capture is turned off (SSL_DOCTOR_MOUSE)")
    return TerminalProfile(host, True, True)


def vt_output_available() -> bool:
    """Turn on VT processing for a Windows console; False when unsupported."""
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        state = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(state)):
            return False
        return bool(kernel32.SetConsoleMode(handle, state.value | 0x0004))
    except Exception:  # noqa: BLE001 - any failure means: no VT output
        return False
