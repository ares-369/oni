"""Rebuild docs/demo.gif from a real `oniops demo` run.

Usage (needs Pillow and the DejaVu Sans Mono font):
    python scripts/make_demo_gif.py [docs/demo.gif]

It runs `oniops demo`, records every output line, and draws the lines as terminal
frames. The text is exactly what the run printed. The run itself takes about two
seconds, so playback adds pauses between sections to make it readable.
"""
import re
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

COLS, ROWS, FS = 112, 30, 15
FONT_DIR = "/usr/share/fonts/truetype/dejavu/"
BG, FG, DIM = (22, 24, 29), (215, 218, 224), (110, 116, 128)
GREEN, YELLOW, BLUE, RED = (110, 200, 120), (225, 190, 90), (90, 180, 220), (235, 105, 95)
COLOURS = {"VERIFIED": GREEN, "UNCONFIRMED": YELLOW, "FIXED": BLUE, "HIGH": RED, "MEDIUM": YELLOW,
           "AUTH-ENFORCED": BLUE, "FALSE-POSITIVE-FILTERED": BLUE}
TOKENS = re.compile("(" + "|".join(sorted(COLOURS, key=len, reverse=True)) + ")")
# Hold the frame after a line ending with this text (milliseconds).
PAUSES = {"as terms acceptance here.": 1800, "deterministic probes and validators only.": 1200,
          "(10 routes).": 1000, "without readOnly protection": 4000, "HTTP 403": 3000,
          "never FIXED.": 3500, "issues on real systems.": 5000}


def record_demo() -> list[str]:
    run = subprocess.run([sys.executable, "-m", "oniops", "demo"], capture_output=True, text=True, check=True)
    return run.stdout.splitlines()


class Terminal:
    def __init__(self) -> None:
        self.font = ImageFont.truetype(FONT_DIR + "DejaVuSansMono.ttf", FS)
        self.bold = ImageFont.truetype(FONT_DIR + "DejaVuSansMono-Bold.ttf", FS)
        self.cw = self.font.getbbox("M")[2]
        self.lh = FS + 5
        self.pad, self.bar = 16, 30
        self.w = self.pad * 2 + self.cw * COLS
        self.h = self.bar + self.pad * 2 + self.lh * ROWS

    def _line(self, d, y, text, prompt):
        x = self.pad
        if prompt:
            d.text((x, y), "$ ", font=self.bold, fill=GREEN)
            d.text((x + self.cw * 2, y), text, font=self.bold, fill=FG)
            return
        if text.startswith("[DEMO]"):
            d.text((x, y), "[DEMO]", font=self.font, fill=DIM)
            x, text = x + self.cw * 6, text[6:]
        pos = 0
        for m in TOKENS.finditer(text):
            seg = text[pos:m.start()]
            d.text((x, y), seg, font=self.font, fill=FG)
            x += self.cw * len(seg)
            d.text((x, y), m.group(1), font=self.bold, fill=COLOURS[m.group(1)])
            x += self.cw * len(m.group(1))
            pos = m.end()
        d.text((x, y), text[pos:], font=self.font, fill=FG)

    def frame(self, buf, cursor=False):
        im = Image.new("RGB", (self.w, self.h), BG)
        d = ImageDraw.Draw(im)
        d.rectangle([0, 0, self.w, self.bar], fill=(34, 37, 44))
        for i, c in enumerate([RED, YELLOW, GREEN]):
            d.ellipse([12 + i * 20, 10, 24 + i * 20, 22], fill=c)
        d.text((self.w // 2 - self.cw * 6, 7), "oniops demo", font=self.font, fill=DIM)
        view = buf[-ROWS:]
        for i, (text, prompt) in enumerate(view):
            self._line(d, self.bar + self.pad + i * self.lh, text[:COLS - (2 if prompt else 0)], prompt)
        if cursor:
            y = self.bar + self.pad + (len(view) - 1) * self.lh
            x = self.pad + self.cw * (2 + len(view[-1][0]))
            d.rectangle([x, y + 2, x + self.cw - 2, y + self.lh - 3], fill=FG)
        return im


def build(lines: list[str], out: str) -> None:
    term = Terminal()
    frames, durs = [], []
    buf = [("", True)]
    frames.append(term.frame(buf, cursor=True))
    durs.append(600)
    cmd = "oniops demo"
    for i in range(1, len(cmd) + 1):
        buf[-1] = (cmd[:i], True)
        frames.append(term.frame(buf, cursor=True))
        durs.append(70)
    frames.append(term.frame(buf))
    durs.append(500)
    for line in lines:
        buf.append((line, False))
        frames.append(term.frame(buf))
        durs.append(next((ms for end, ms in PAUSES.items() if line.rstrip().endswith(end)), 140))
    palette = frames[-20].quantize(colors=32, method=Image.Quantize.MEDIANCUT)
    small = [f.quantize(palette=palette, dither=Image.Dither.NONE) for f in frames]
    small[0].save(out, save_all=True, append_images=small[1:], duration=durs, loop=0, optimize=True, disposal=1)
    print(f"wrote {out}: {len(frames)} frames, {sum(durs) / 1000:.0f}s")


if __name__ == "__main__":
    build(record_demo(), sys.argv[1] if len(sys.argv) > 1 else "docs/demo.gif")
