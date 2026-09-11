"""Render each stage of demo/terminal_walkthrough.md as a terminal-style PNG.

Produces one image per stage in demo/screenshots/, ready to drop into a slide
deck or a PDF. The colouring mirrors what the demo actually prints: alerts red,
blocks yellow, clean scores green, banners in their phase colour.

    python demo/render_screenshots.py

Only needs Pillow, which arrives with matplotlib (eval/requirements.txt).
"""

import os
import re
import sys

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(HERE, "terminal_walkthrough.md")
OUT_DIR = os.path.join(HERE, "screenshots")

# --- Terminal theme. Dark, high contrast, readable when a PDF shrinks it. ---
BG = (18, 18, 26)
FG = (222, 222, 226)
DIM = (128, 128, 138)
RED = (255, 107, 96)
GRN = (110, 219, 148)
YEL = (240, 200, 90)
CYN = (110, 190, 240)
MAG = (208, 150, 240)

FONT_SIZE = 17
PAD = 28
TITLE_H = 46
LINE_GAP = 5


def pick_font(bold=False):
    for name in (("consolab.ttf", "consola.ttf") if bold else ("consola.ttf",)):
        path = os.path.join(r"C:\Windows\Fonts", name)
        if os.path.exists(path):
            return ImageFont.truetype(path, FONT_SIZE)
    for path in ("/System/Library/Fonts/Menlo.ttc",
                 "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"):
        if os.path.exists(path):
            return ImageFont.truetype(path, FONT_SIZE)
    return ImageFont.load_default()


def colour_for(line):
    """Match the colours the demo script itself prints."""
    s = line.strip()
    if "[ALERT" in line or s.startswith("signals:") or s.startswith("why:"):
        return RED
    if "[BLOCK" in line:
        return YEL
    if "all clean" in line or "model_loaded=true" in line or s.startswith("PHASE 1"):
        return GRN
    if s.startswith("====") or s.startswith("PHASE 2"):
        return MAG if "EXTRACTION DETECTOR" in line or "RESULT" in line else CYN
    if "collecting" in line or s.startswith("...") or s.startswith("> "):
        return DIM
    if s.startswith("$ "):
        return CYN
    if "ATTACK" in line:
        return RED
    if re.search(r"\bbenign\b", line):
        return GRN
    if "precision" in line or "recall" in line:
        return YEL
    return FG


def render(title, lines, path, font, title_font):
    width_chars = max([len(l) for l in lines] + [len(title)])
    ascent, descent = font.getmetrics()
    line_h = ascent + descent + LINE_GAP
    char_w = font.getlength("M")
    w = int(PAD * 2 + char_w * (width_chars + 1))
    h = int(PAD * 2 + TITLE_H + line_h * len(lines))

    img = Image.new("RGB", (w, h), BG)
    d = ImageDraw.Draw(img)

    # Window chrome: three dots and the stage title, so it reads as a terminal.
    for i, c in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
        d.ellipse([PAD + i * 20, PAD - 4, PAD + i * 20 + 11, PAD + 7], fill=c)
    d.text((PAD + 74, PAD - 7), title, font=title_font, fill=DIM)
    d.line([(PAD, PAD + 24), (w - PAD, PAD + 24)], fill=(44, 44, 56), width=1)

    y = PAD + TITLE_H
    for line in lines:
        d.text((PAD, y), line, font=font, fill=colour_for(line))
        y += line_h

    img.save(path)
    return w, h


def slug(text):
    s = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return re.sub(r"_+", "_", s)[:48]


def main():
    if not os.path.exists(SRC):
        print("Missing %s" % SRC)
        return 2
    md = open(SRC, encoding="utf-8").read()
    os.makedirs(OUT_DIR, exist_ok=True)

    font, title_font = pick_font(), pick_font(bold=True)
    stages = re.findall(r"^## (STAGE [^\n]+)\n(.*?)(?=^## |\Z)", md,
                        re.S | re.M)
    if not stages:
        print("No '## STAGE' sections found.")
        return 2

    made = 0
    for heading, body in stages:
        blocks = re.findall(r"^```\n(.*?)^```", body, re.S | re.M)
        # The last fenced block in a stage is the terminal output; earlier ones
        # are the reproduce-with commands.
        if not blocks:
            continue
        lines = blocks[-1].rstrip("\n").split("\n")
        num = heading.split(":")[0].replace("STAGE ", "").strip()
        name = heading.split(":", 1)[1].strip() if ":" in heading else heading
        out = os.path.join(OUT_DIR, "stage_%s_%s.png" % (num.lower(), slug(name)))
        w, h = render(heading, lines, out, font, title_font)
        print("  %-46s %dx%d" % (os.path.basename(out), w, h))
        made += 1

    print("\nwrote %d screenshots to %s" % (made, OUT_DIR))
    return 0


if __name__ == "__main__":
    sys.exit(main())
