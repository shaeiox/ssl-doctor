"""Regenerate the application icons from the artwork (run on any OS).

    python packaging/make_icons.py <artwork.png>

Writes packaging/icons/:
    ssl-doctor.png    1024 px master with transparent corners
    ssl-doctor.ico    Windows executables (16-256 px)
    ssl-doctor.icns   macOS executables

The artwork is a rounded square on a dark backdrop. It is cropped to the
square and its corners are made transparent, so the icon does not show as a
dark box on a taskbar or desktop. The generated files are committed, so
packaging/build.py needs no image library; this script needs Pillow.
"""

from __future__ import annotations

import os
import sys

from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
ICONS = os.path.join(HERE, "icons")

# The rounded square in the 1254 px artwork, and its corner radius.
SQUARE = (91, 89, 1163, 1161)
RADIUS = 0.19                      # of the square's side
MASTER = 1024
ICO_SIZES = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]


def master(path: str) -> Image.Image:
    art = Image.open(path).convert("RGB")
    scale = art.width / 1254       # the box was measured on the 1254 px artwork
    box = tuple(round(v * scale) for v in SQUARE)
    square = art.crop(box).resize((MASTER, MASTER), Image.LANCZOS).convert("RGBA")
    # draw the mask 4x larger and scale down, so the curved edge is anti-aliased
    big = MASTER * 4
    mask = Image.new("L", (big, big), 0)
    inset = 4 * 4                  # stay inside the backdrop's own soft edge
    ImageDraw.Draw(mask).rounded_rectangle((inset, inset, big - inset, big - inset),
                                           radius=round(big * RADIUS), fill=255)
    square.putalpha(mask.resize((MASTER, MASTER), Image.LANCZOS))
    return square


def main(argv) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    os.makedirs(ICONS, exist_ok=True)
    icon = master(argv[1])
    icon.save(os.path.join(ICONS, "ssl-doctor.png"), optimize=True)
    icon.save(os.path.join(ICONS, "ssl-doctor.ico"), sizes=ICO_SIZES)
    # 512 px is the largest size a Finder icon needs; the 1024 px retina copy adds ~0.3 MB
    icon.resize((512, 512), Image.LANCZOS).save(os.path.join(ICONS, "ssl-doctor.icns"))
    for name in sorted(os.listdir(ICONS)):
        print(f"  {os.path.join(ICONS, name)}  {os.path.getsize(os.path.join(ICONS, name))} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
