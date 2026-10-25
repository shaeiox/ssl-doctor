"""Measure, cut and wrap text in terminal cells rather than code points.

A frame's right border is only straight if every row is the same number of
*cells* wide. CJK and most emoji take two cells, combining marks and joiners
take none, so ``len()`` is the wrong ruler for an IDN host, a certificate
subject or a server's error text. Stdlib only (``unicodedata``). East Asian
"ambiguous" characters -- box drawing among them -- count as one cell, which is
what terminals do outside CJK legacy locales.
"""

from __future__ import annotations

import re
import unicodedata
from functools import lru_cache
from typing import List

_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF}
_TOKENS = re.compile(r"\S+|\s+")


@lru_cache(maxsize=4096)
def char_width(char: str) -> int:
    code = ord(char)
    if code < 0x20 or 0x7F <= code < 0xA0:
        return 0
    if code in _ZERO_WIDTH or 0xFE00 <= code <= 0xFE0F or 0xE0100 <= code <= 0xE01EF:
        return 0                                  # joiners and variation selectors
    if unicodedata.combining(char) or unicodedata.category(char) in ("Mn", "Me"):
        return 0
    return 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1


def width(text: str) -> int:
    if text.isascii():
        return sum(1 for c in text if " " <= c < "\x7f")
    return sum(char_width(c) for c in text)


def clip(text: str, cells: int) -> str:
    """The longest prefix of `text` that fits in `cells`; never half a glyph."""
    if cells <= 0:
        return ""
    if text.isascii() and text.isprintable():
        return text[:cells]
    used = 0
    for index, char in enumerate(text):
        used += char_width(char)
        if used > cells:
            return text[:index]
    return text


def slice(text: str, start: int, end: int) -> str:  # noqa: A001 - mirrors str slicing
    """The characters drawn in columns [start, end)."""
    out, column = [], 0
    for char in text:
        cell = char_width(char)
        if column >= end:
            break
        if column >= start:
            out.append(char)
        column += cell
    return "".join(out)


def pad(text: str, cells: int) -> str:
    """`text` clipped or space-filled to exactly `cells` columns."""
    text = clip(text, cells)
    return text + " " * (cells - width(text))


def wrap(text: str, cells: int, initial: str = "", subsequent: str = "") -> List[str]:
    """Word-wrap to `cells` columns, keeping inner runs of spaces.

    Breaks fall on spaces (the space at a break is dropped); a word wider than
    the room is broken by cells, so no character is ever elided.
    """
    rows: List[str] = []
    line, used = initial, width(initial)
    for token in _TOKENS.findall(text):
        size = width(token)
        if token.isspace():
            if used + size <= cells:
                line, used = line + token, used + size
            elif line.strip():
                rows.append(line.rstrip())
                line, used = subsequent, width(subsequent)
            continue
        if used + size > cells and line.strip():
            rows.append(line.rstrip())
            line, used = subsequent, width(subsequent)
        while used + size > cells:                 # a word longer than a row
            room = max(1, cells - used)
            head = clip(token, room) or token[0]
            rows.append(line + head)
            token = token[len(head):]
            size = width(token)
            line, used = subsequent, width(subsequent)
        line, used = line + token, used + size
    if line.strip() or not rows:
        rows.append(line.rstrip() if rows else line)
    return rows
