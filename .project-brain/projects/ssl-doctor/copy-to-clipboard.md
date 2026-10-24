---
project: ssl-doctor
topic: copy-to-clipboard
tags: [tui, mouse, clipboard, osc52]
status: done
trust: ai-inferred
last_done: 2026-10-24
version: 2
---

**What:** (OpenSpec `add-copy-to-clipboard`) drag-to-copy over the full-screen transcript,
`/copy`, `/copy all`, `Ctrl-Y`.

**How:** `ssl_doctor/clipboard.py`: OSC 52 to `sys.__stdout__` (tmux passthrough, 100 kB cap,
only to a tty) + first local tool by environment (`wl-copy`, `xclip`, `xsel`, `pbcopy`,
`clip.exe`), `shell=False`, 2 s timeout; `describe()` never echoes text and never calls an
escape-only copy "copied". Mouse: `?1002h`+`?1006h` only inside `read_line()`;
`KeyReader._decode_mouse` → `tui.MouseEvent`. `build_frame(layout=, highlight=)` reports where
the transcript is drawn and reverse-videos the selection; `TuiSession.selection` is in wrapped
transcript coordinates. Responses are recorded by an stdout tee in `execute()`
(`_ResponseRecorder`, via `tui.Transcript`), skipping `/copy`.

**v2 (field bug):** xfce4-terminal/VTE ignores OSC 52 and the machine had no xclip → nothing
copied. Now native first: `clipboard.windows_copy` (Win32 API) and `clipboard.x11_copy`
(double-forked libX11 CLIPBOARD owner, `_x11_serve`; fork because builds are PyInstaller), then
tools, OSC 52 always on a tty. Escape-only copies say "copy not confirmed" + Shift+drag hint.
Windows `KeyReader` turns on ENABLE_VIRTUAL_TERMINAL_INPUT per key and reads ESC sequences whole.
Verify with `SSL_DOCTOR_TEST_X11=1` (replaces the real clipboard). Tests must pass `native=[]`.

**Gotcha:** tests that call `_tui_run()` directly must `set_capture_width(0)` afterwards, or
later plain-mode tests draw frames.

**Tests:** `tests/test_clipboard.py` (14), `tests/test_copy.py` (11), `tests/test_selection.py` (17).
