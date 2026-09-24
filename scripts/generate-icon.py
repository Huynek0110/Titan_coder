from pathlib import Path
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "assets"
OUT.mkdir(exist_ok=True)
size = 512
image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
draw = ImageDraw.Draw(image)
# Rounded dark tile.
draw.rounded_rectangle((18, 18, 494, 494), radius=112, fill=(11, 14, 20, 255), outline=(66, 78, 102, 255), width=8)
# Soft accent glow rings.
draw.ellipse((72, 70, 440, 438), outline=(39, 116, 108, 90), width=8)
draw.arc((112, 104, 400, 392), 205, 515, fill=(67, 221, 190, 255), width=18)
# Terminal prompt.
draw.line((145, 205, 218, 272, 145, 339), fill=(222, 235, 240, 255), width=28, joint="curve")
draw.line((255, 340, 370, 340), fill=(222, 235, 240, 255), width=28)
# Local node spark.
cx, cy = 361, 151
for angle in range(0, 360, 45):
    import math
    rad = math.radians(angle)
    x1, y1 = cx + math.cos(rad) * 18, cy + math.sin(rad) * 18
    x2, y2 = cx + math.cos(rad) * 42, cy + math.sin(rad) * 42
    draw.line((x1, y1, x2, y2), fill=(98, 240, 205, 255), width=10)
draw.ellipse((cx - 12, cy - 12, cx + 12, cy + 12), fill=(183, 255, 235, 255))
image.save(OUT / "icon.png")
image.save(OUT / "icon.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print(OUT / "icon.png")
print(OUT / "icon.ico")
