"""Builds icon.png / icon.ico from logo_source.png (the knight emblem).

The source is small, not square, and sits on a textured gradient. The emblem
is lifted out with a soft luminance mask (so the gradient doesn't show as a
seam), brightened a little so it stays legible at tray size, and centered on a
flat padded tile with rounded corners.
"""
from pathlib import Path

from PIL import Image, ImageDraw, ImageEnhance, ImageFilter

HERE = Path(__file__).parent
SOURCE = HERE / "logo_source.png"
SIZE = 256
BACKGROUND = (22, 27, 34)
EMBLEM_LOW, EMBLEM_HIGH = 44, 64  # luminance ramp from background to emblem
BRIGHTEN = 1.35
PADDING = 0.12                    # fraction of the tile left empty around the emblem
CORNER_RADIUS = 0.18              # fraction of the tile size


def build(size: int = SIZE) -> Image.Image:
    src = Image.open(SOURCE).convert("RGB")
    span = EMBLEM_HIGH - EMBLEM_LOW
    alpha = src.convert("L").point(
        lambda v: 0 if v <= EMBLEM_LOW else 255 if v >= EMBLEM_HIGH
        else int((v - EMBLEM_LOW) * 255 / span)
    )
    bbox = alpha.point(lambda v: 255 if v > 128 else 0).getbbox()
    emblem = ImageEnhance.Brightness(src).enhance(BRIGHTEN).crop(bbox)
    emblem_alpha = alpha.crop(bbox)

    side = int(max(emblem.size) / (1 - 2 * PADDING))
    scale = size / side
    emblem = emblem.resize((round(emblem.width * scale), round(emblem.height * scale)), Image.LANCZOS)
    emblem_alpha = emblem_alpha.resize(emblem.size, Image.LANCZOS)

    tile = Image.new("RGB", (size, size), BACKGROUND)
    tile.paste(emblem, ((size - emblem.width) // 2, (size - emblem.height) // 2), emblem_alpha)
    tile = tile.filter(ImageFilter.UnsharpMask(1.2, 60, 2))

    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        (0, 0, size - 1, size - 1), radius=int(size * CORNER_RADIUS), fill=255
    )
    icon = tile.convert("RGBA")
    icon.putalpha(mask)
    return icon


def build_emblem(height: int = 256) -> Image.Image:
    """Just the knight on a transparent background, for placing on app surfaces."""
    src = Image.open(SOURCE).convert("RGB")
    span = EMBLEM_HIGH - EMBLEM_LOW
    alpha = src.convert("L").point(
        lambda v: 0 if v <= EMBLEM_LOW else 255 if v >= EMBLEM_HIGH
        else int((v - EMBLEM_LOW) * 255 / span)
    )
    bbox = alpha.point(lambda v: 255 if v > 128 else 0).getbbox()
    emblem = ImageEnhance.Brightness(src).enhance(BRIGHTEN).crop(bbox).convert("RGBA")
    emblem.putalpha(alpha.crop(bbox))
    width = round(emblem.width * height / emblem.height)
    return emblem.resize((width, height), Image.LANCZOS)


if __name__ == "__main__":
    build_emblem().save(HERE / "emblem.png")
    icon = build()
    icon.save(HERE / "icon.png")
    icon.save(HERE / "icon.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48),
                                         (64, 64), (128, 128), (256, 256)])
    print(f"Wrote {HERE / 'icon.png'} and {HERE / 'icon.ico'}")
