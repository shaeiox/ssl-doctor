# Design

## Context

- `tui.py` enables `MOUSE_ON = ?1000h ?1006h` only inside `TuiSession.read_line()`
  and decodes SGR reports in `KeyReader._decode_escape`, mapping buttons 64/65 to
  wheel keys; every other report becomes `"unknown"`. Mode 1000 also reports
  button presses, which is why the terminal's own selection stops working inside
  the composer.
- `build_frame()` is pure: it receives the transcript's visible rows (`body`) and
  places them after the header, top margin and a blank row. The renderer
  (`SSLDoctorCLI._tui_frame`) knows the header length; nothing records which
  screen row shows which transcript row.
- The transcript is colourless text (`Transcript.lines`), so copying needs no
  ANSI stripping. Masked input is never written to it (`TuiSession.display_text`).
- The line REPL prints straight to `sys.stdout`; nothing records a command's
  output. The shell records it via `CaptureStream` but not per command.

## Goals / Non-Goals

**Goals:** select-to-copy over the transcript, `/copy` / `/copy all` in both
presentations, `Ctrl-Y`, stdlib-only clipboard delivery that works over SSH.

**Non-Goals:** selecting the banner or composer; word/line selection by double or
triple click; auto-scrolling while dragging past the top; copying with frame
borders removed; mouse selection in the line REPL (the terminal owns it).

## Decisions

1. **Button-event tracking `?1002h` + SGR `?1006h`** instead of `?1000h`.
   1002 adds motion-while-pressed reports, needed for drag; any-motion `?1003h`
   would flood redraws with hover events. Decode SGR `ESC[<b;x;yM|m`: b=0 press,
   b=32 drag (motion bit + left), `m` final = release, 64/65 wheel as today.
   The reader returns structured mouse events instead of string keys so
   `read_line()` can route them; wheel handling is unchanged.
2. **Selection model in screen coordinates, resolved through a layout map.**
   `build_frame()` additionally returns (or records on the session) the screen
   row of the first body row and the gutter column, so the renderer's last frame
   maps `(x, y)` → `(transcript row, column)`. Anchor + head are stored as
   transcript row/column, so a redraw (spinner, resize) keeps the selection on the
   same text. Rejected: re-deriving rows from the painted lines — they contain
   escape codes and padding.
3. **Highlight as reverse video** (`SGR 7`) over the selected span, applied by
   `build_frame()` after colouring a body row. It reads in every colour mode,
   including 16-colour, and needs no new role.
4. **Copy what is shown, trimmed.** Each selected row is copied as displayed with
   trailing spaces removed, rows joined by `\n`. Frame borders stay; stripping
   them is a different feature and would make `/copy` and selection disagree.
5. **Per-command response recording.** `execute()` delimits a command, so it
   tees `sys.stdout` for the duration of the handler through `tui.Transcript`
   (which already drops escapes and applies spinner carriage returns) — one
   mechanism for the shell and the line REPL alike. *Implemented this way
   instead of the originally planned transcript slicing for the shell: the
   result is the same text, with one code path.* `/copy` itself is not
   recorded, so repeated `/copy` keeps copying the same response; `/copy all`
   uses the shell's transcript as shown, or the recorded command log in the
   line REPL. Input read through `getpass` never passes stdout.
6. **Clipboard helper `ssl_doctor/clipboard.py`.** `copy(text) -> CopyResult`
   writes OSC 52 (`ESC ] 52 ; c ; <base64> BEL`, wrapped in a DCS passthrough when
   `TMUX` is set) to the real terminal, then tries the first available local tool
   from a fixed argv list — `wl-copy` (Wayland), `xclip -selection clipboard` /
   `xsel -b` (X11 with `DISPLAY`), `pbcopy` (macOS), `clip.exe` (Windows/WSL) — via
   `subprocess.run(argv, input=..., shell=False, timeout=2)`. The result names the
   routes; the composer/`note()` prints `copied 3 lines · 212 chars · terminal
   clipboard + wl-copy`. Rejected: `pyperclip`/`tkinter` (dependency or display
   requirement; nothing works over SSH).
6a. **Amended after field testing — native OS clipboards first.** On Linux Mint
   22.3 with xfce4-terminal (VTE 0.76) and no clipboard tool installed, nothing
   copied: VTE ignores OSC 52 and no tool existed. Decision 6 assumed one of the
   two routes would be present on a desktop; that is false. Route order is now:
   the Win32 clipboard API (ctypes) on Windows, or on X11/XWayland a double-forked
   helper that owns CLIPBOARD via libX11 (ctypes) and serves TARGETS/UTF8_STRING/
   STRING/TEXT until SelectionClear; then the local tools; OSC 52 whenever a
   terminal is attached. A fork, not a new interpreter, because release builds
   are PyInstaller executables. The Windows key reader enables
   ENABLE_VIRTUAL_TERMINAL_INPUT per key and reads escape sequences whole, without
   which no mouse report reached the shell on Windows.
7. **OSC 52 size cap** of 100 kB of base64; larger copies go to the local tool
   only and the confirmation says the terminal route was skipped.
8. **`Ctrl-Y`** (`\x19`) decoded as `"ctrl-y"`; `read_line()` calls the same copy
   function as `/copy` and re-renders without touching `input`/`history`.

## Risks / Trade-offs

- [Terminals ignore OSC 52 silently (some disable it by default)] → the
  confirmation never claims more than "sent to the terminal clipboard"; README
  lists how to enable it (tmux `set-clipboard on`, etc.); Shift+drag native
  selection remains available.
- [Capturing presses removes native click-to-select inside the composer] → that
  is already true today with `?1000h`; Shift+drag still bypasses capture in
  common terminals and is documented.
- [Clipboard tool hangs (no X server)] → 2 s timeout, failure reported, session
  continues; tools are only tried when their environment marker is present.
- [Selection drifts when new output arrives during selection] → selection is only
  possible while the composer reads, when no output is arriving; anchors are
  stored in transcript coordinates, so scrolling keeps them on the same text.

## Open Questions

- Whether to add word selection by double-click later; it does not change the
  drag behaviour or the tasks below.
