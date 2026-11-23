import argparse
import json
import math
import os
import pathlib
import shutil
import sys
import tempfile

import numpy as np
from PIL import Image
from playwright.sync_api import sync_playwright

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import design  # noqa: E402
from design import LOST, TAGLINE  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
ASSETS = ROOT / "assets"
TMP = pathlib.Path(tempfile.mkdtemp(prefix="lscore-brand-"))
OUT = str(TMP)
FPS, LOOP = 12.5, 7.2
N = int(round(LOOP * FPS))                       # 90 frames of 80 ms
EARN = [0 if i in LOST else 1 for i in range(100)]
LEN_T = len(TAGLINE)
OUT0, OUT1, IN0, HOLD1 = 2.8, 3.4, 3.6, 5.1      # seconds: rewind starts / ends, redraw starts, idle resumes


def cl(x): return max(0.0, min(1.0, x))
def e_out(x): x = cl(x); return 1 - (1 - x) ** 3
def e_in(x): x = cl(x); return x ** 3
def e_io(x): x = cl(x); return 4 * x ** 3 if x < .5 else 1 - (-2 * x + 2) ** 3 / 2
def e_back(x, s=1.7): x = cl(x); return 1 + (s + 1) * (x - 1) ** 3 + s * (x - 1) ** 2


def dial_progress(t):
    if t < OUT0: return 1.0
    if t < OUT1: return 1 - e_io((t - OUT0) / 0.6)
    if t < IN0: return 0.0
    if t < 4.8: return e_out((t - IN0) / 1.2)
    return 1.0


def word_p(t, k):
    if t < OUT1:                                  # erase, last letter first
        return 1 - e_in((t - (OUT0 + (5 - k) * 0.05)) / 0.30)
    return e_io((t - (3.75 + k * 0.12)) / 0.45)   # draw, first letter first


def pulse(t): return 1 + 0.14 * math.sin(2 * math.pi * (t + LOOP - HOLD1) / 1.8)


def core_scale(t):
    if t < OUT0: return pulse(t)
    if t < OUT0 + 0.2: return (1 - e_in((t - OUT0) / 0.2)) * pulse(OUT0)
    if t < 4.56: return 0.0
    if t < HOLD1: return e_back((t - 4.56) / 0.34)
    return 1 + cl((t - HOLD1) / 0.4) * 0.14 * math.sin(2 * math.pi * (t - HOLD1) / 1.8)


def tag_n(t):
    if t < OUT0: return LEN_T
    if t < OUT0 + 0.45: return int(round(LEN_T * (1 - e_in((t - OUT0) / 0.45))))
    if t < 4.30: return 0
    if t < HOLD1: return int(round(LEN_T * cl((t - 4.30) / 0.8)))
    return LEN_T


def blink(t): return (round(t, 6) % 0.8) < 0.52


def state(t, comet=True):
    s = dial_progress(t)
    head = s * 100
    lit = [1 if (EARN[i] and i < head) else 0 for i in range(100)]
    ext = [0.0] * 100
    if 0.002 < s < 0.998:                          # flare on the sweeping edge
        for k, v in enumerate((8, 5, 2.5, 1)):
            j = (int(math.floor(head)) - k) if t >= IN0 else (int(math.ceil(head)) + k)
            if 0 <= j < 100: ext[j] = v
    hold = t < OUT0 or t >= HOLD1
    if hold and comet:                             # idle: a radar-like comet circles the dial every 3.6 s
        c = (((t + (LOOP if t < OUT0 else 0)) - HOLD1) / 3.6) % 1.0
        hc = c * 100
        for i in range(100):
            d = (hc - i) % 100
            if d < 6.5: ext[i] = max(ext[i], 7 * (1 - d / 6.5) ** 1.4)
    return {"lit": lit, "ext": ext, "num": sum(lit),
            "word": {c_: word_p(t, k) for k, c_ in enumerate("lscore")},
            "core": core_scale(t), "tag": tag_n(t),
            "cur": True if (OUT0 <= t < HOLD1) else blink(t)}


def render_all(states, scale=2):
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=os.environ.get("CHROMIUM_PATH") or None)   # NixOS: point CHROMIUM_PATH at a system chromium
        pg = b.new_page(viewport={"width": design.W, "height": design.H}, device_scale_factor=scale)
        html = TMP / "final.html"
        html.write_text(design.make_html())
        pg.goto(html.as_uri())
        pg.wait_for_timeout(300)
        pg.evaluate("document.fonts.ready")
        for i, st in enumerate(states):
            pg.evaluate(f"apply({json.dumps(st)})")
            pg.screenshot(path=f"{OUT}/f{i:03d}.png", omit_background=True)
        b.close()


def gif_frames(paths, thr=0.55, ncol=255):
    arrs = [np.asarray(Image.open(p).convert("RGBA")) for p in paths]
    rng = np.random.RandomState(1)
    samples = []
    for a in arrs:
        px = a[a[..., 3] >= thr * 255][:, :3]
        if len(px):
            samples.append(px[rng.choice(len(px), min(len(px), 6000), replace=False)])
    pool = np.concatenate(samples)
    side = int(math.ceil(math.sqrt(len(pool))))
    pad = np.zeros((side * side, 3), "uint8")
    pad[:len(pool)] = pool
    pad[len(pool):] = pool[0]
    pal = Image.fromarray(pad.reshape(side, side, 3), "RGB").quantize(colors=ncol, method=Image.MEDIANCUT, dither=Image.NONE)
    palette = pal.getpalette()[:ncol * 3]
    TI = ncol
    out = []
    for a in arrs:
        q = np.asarray(Image.fromarray(a[..., :3], "RGB").quantize(palette=pal, dither=Image.NONE)).copy()
        q[a[..., 3] < thr * 255] = TI
        pimg = Image.fromarray(q, "P")
        pimg.putpalette(palette + [0, 0, 0] * (256 - ncol))
        out.append(pimg)
    return out, TI


def render_static(path, scale=2):
    """Final pose, no comet, full 8-bit alpha."""
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=os.environ.get("CHROMIUM_PATH") or None)
        pg = b.new_page(viewport={"width": design.W, "height": design.H}, device_scale_factor=scale)
        html = TMP / "static.html"
        html.write_text(design.make_html())
        pg.goto(html.as_uri())
        pg.wait_for_timeout(300)
        pg.evaluate("document.fonts.ready")
        pg.evaluate(f"apply({json.dumps(design.final_state())})")
        pg.screenshot(path=str(path), omit_background=True)
        b.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Regenerate the lscore banner. Requires playwright and Chromium.")
    ap.add_argument("--out", default=str(ASSETS), help="output folder (default: assets/)")
    args = ap.parse_args()
    outdir = pathlib.Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    try:
        ts = [i / FPS for i in range(N)]
        states = [state(t) for t in ts]
        # Frame 0 must be the full pose.
        assert states[0]["num"] == design.SCORE and states[0]["tag"] == LEN_T and all(v == 1 for v in states[0]["word"].values())
        render_all(states, 2)
        paths = [f"{OUT}/f{i:03d}.png" for i in range(N)]
        gp, TI = gif_frames(paths, 0.55)
        gp[0].save(outdir / "lscore-banner.gif", save_all=True, append_images=gp[1:], duration=int(round(1000 / FPS)), loop=0,
                   disposal=2, transparency=TI, optimize=False)
        render_static(outdir / "lscore-banner.png")
        print("wrote", outdir / "lscore-banner.gif", os.path.getsize(outdir / "lscore-banner.gif"), "bytes;", outdir / "lscore-banner.png")
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
