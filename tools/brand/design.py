"""Builds the HTML/SVG page for the lscore banner; Chromium renders each frame."""
import importlib.util
import math
import pathlib

W, H = 840, 280
ACCENTS = ["#DF8F1F", "#E5527C", "#1FA8B4", "#3E7BDB", "#8B6AE6"]   # amber, rose, teal, blue, violet
INK_A, INK_B = "#4C6BEA", "#8F63E6"
DIM, SLATE, SLATE_TXT = "#9AA5B5", "#8390A3", "#7D8A9E"

_ROOT = pathlib.Path(__file__).resolve().parents[2]


def _weights():
    """Category weights from lscore.py (CAT_ORDER / CAT_WEIGHT); the dial zones mirror the scoring model."""
    try:
        spec = importlib.util.spec_from_file_location("lscore", _ROOT / "lscore.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return [mod.CAT_WEIGHT[c] for c in mod.CAT_ORDER]
    except Exception:                                     # standalone fallback: the v0.3.0 weights
        return [25, 30, 15, 20, 10]


ZONES = _weights()                              # Speed, Security, Privacy, Storage, Battery & Heat -> ticks per zone
POINTS_LOST = [1, 2, 2, 0, 1]                   # sample report drawn in the banner (points lost per zone) -> score 94
assert sum(ZONES) == 100 and len(ZONES) <= len(ACCENTS) and len(ZONES) == len(POINTS_LOST), "dial needs 100 ticks and one accent per zone"
SCORE = 100 - sum(POINTS_LOST)


def _lost():
    out, start = set(), 0
    for size, lost in zip(ZONES, POINTS_LOST):
        out |= set(range(start + size - lost, start + size))      # the points lost sit at the end of their zone
        start += size
    return out


LOST = _lost()
TAGLINE = "Linux health score in one command."


def word_paths():
    """Monoline lettering for 'lscore', in px at 1x."""
    r, rr = 37.0, 18.5                                    # round letters / half of the 's'
    s_cx = 47.5
    c_cx = 130.0
    o_cx = 232.0
    r_x = 302.0
    e_cx = 406.0
    k30, k42 = math.cos(math.radians(30)), math.sin(math.radians(30))
    s_start = (s_cx + rr * k30, -55.5 - rr * k42)         # top bowl, -30 deg
    s_mid = (s_cx, -37.0)
    s_end = (s_cx - rr * k30, -18.5 + rr * k42)           # bottom bowl, 150 deg
    c42 = (c_cx + r * math.cos(math.radians(42)), -37 + r * math.sin(math.radians(42)))
    e40 = (e_cx + r * math.cos(math.radians(40)), -37 + r * math.sin(math.radians(40)))
    p = {
        "l": "M0,-116 L0,0",
        "s": f"M{s_start[0]:.2f},{s_start[1]:.2f} A{rr} {rr} 0 1 0 {s_mid[0]:.2f},{s_mid[1]:.2f} A{rr} {rr} 0 1 1 {s_end[0]:.2f},{s_end[1]:.2f}",
        "c": f"M{c42[0]:.2f},{-37 - (c42[1] + 37):.2f} A{r} {r} 0 1 0 {c42[0]:.2f},{c42[1]:.2f}",
        "o": f"M{o_cx},-74 A{r} {r} 0 1 1 {o_cx - 0.01},-74",
        "r1": f"M{r_x},0 L{r_x},-74",
        "r2": f"M{r_x},-40 A34 34 0 0 1 {r_x + 34},-74",
        "e": f"M{e_cx - r},-37 L{e_cx + r},-37 A{r} {r} 0 1 0 {e40[0]:.2f},{e40[1]:.2f}",
    }
    return p, {"o_cx": o_cx, "right": e_cx + r}


def make_html(cx=164, word_x=320, base_y=179, major=False):
    paths, m = word_paths()
    left_edge = word_x - 7.5
    ink_x2 = word_x + m["right"] + 7.5
    tag_x = left_edge - 1.2                               # optical alignment with the stem of the 'l'
    core_cx = word_x + m["o_cx"]
    html = f"""<!doctype html><html><head><meta charset="utf-8"><style>
html,body{{margin:0;padding:0;background:transparent}} svg{{display:block}}
.num{{font-family:'Inter Display','Inter',sans-serif;font-weight:800;font-size:68px;letter-spacing:-2px;text-anchor:middle;font-variant-numeric:tabular-nums}}
.lab{{font-family:'Inter',sans-serif;font-weight:600;font-size:11.5px;letter-spacing:3.6px;text-anchor:middle}}
.tag{{font-family:'Inter',sans-serif;font-weight:500;font-size:21px;letter-spacing:.1px;white-space:pre}}
</style></head><body>
<svg id="s" xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">
<defs><linearGradient id="ink" gradientUnits="userSpaceOnUse" x1="{left_edge}" y1="0" x2="{ink_x2}" y2="0"><stop offset="0" stop-color="{INK_A}"/><stop offset="1" stop-color="{INK_B}"/></linearGradient></defs>
<g id="ticks"></g>
<text id="num" class="num" x="{cx}" y="163" fill="url(#ink)">{SCORE}</text>
<text id="lab" class="lab" x="{cx}" y="188" fill="{SLATE}">SCORE</text>
<g id="word" transform="translate({word_x},{base_y})" fill="none" stroke="url(#ink)" stroke-width="15" stroke-linecap="round" stroke-linejoin="round">
""" + "\n".join(f'<path id="p_{k}" d="{v}"/>' for k, v in paths.items()) + f"""
</g>
<circle id="core" cx="{core_cx}" cy="{base_y - 37}" r="9.5" fill="{ACCENTS[0]}"/>
<text id="tag" class="tag" x="{tag_x}" y="{base_y + 42}" fill="{SLATE_TXT}" xml:space="preserve"></text>
<rect id="cur" x="0" y="{base_y + 24}" width="11" height="22" rx="2" fill="{ACCENTS[0]}"/>
</svg>
<script>
const CX={cx}, CY=140, RIN=86, ROUT=104, ZONES={ZONES}, ZCOL={ACCENTS}, DIM="{DIM}", MAJOR={'true' if major else 'false'};
const GAP=7, PITCH=(360-ZONES.length*GAP)/100, NS="http://www.w3.org/2000/svg", TAGX={tag_x}, FULL={TAGLINE!r};
const ticks=[], tg=document.getElementById('ticks'); let z=0, acc=0;
for(let i=0;i<100;i++){{ while(i>=acc+ZONES[z]){{acc+=ZONES[z];z++;}}
  const a=(-90+GAP/2+i*PITCH+z*GAP+PITCH/2)*Math.PI/180, l=document.createElementNS(NS,'line');
  l.setAttribute('stroke-width','3.6'); l.setAttribute('stroke-linecap','round'); tg.appendChild(l); ticks.push({{l,a,z}}); }}
const PATHS={{l:['p_l'],s:['p_s'],c:['p_c'],o:['p_o'],r:['p_r1','p_r2'],e:['p_e']}}, LEN={{}};
for(const k in PATHS) LEN[k]=PATHS[k].map(id=>document.getElementById(id).getTotalLength());
const num=document.getElementById('num'), core=document.getElementById('core'), tag=document.getElementById('tag'), cur=document.getElementById('cur');
function drawTicks(lit,ext){{ for(let i=0;i<100;i++){{ const t=ticks[i], c=Math.cos(t.a), s=Math.sin(t.a), r2=ROUT+(ext?ext[i]:0), r1=RIN-((MAJOR&&i%10==0)?5:0);
  t.l.setAttribute('x1',CX+r1*c); t.l.setAttribute('y1',CY+r1*s); t.l.setAttribute('x2',CX+r2*c); t.l.setAttribute('y2',CY+r2*s); t.l.setAttribute('stroke',lit[i]?ZCOL[t.z]:DIM); }} }}
function setGroup(k,p){{ const ids=PATHS[k], lens=LEN[k], total=lens.reduce((a,b)=>a+b,0); let remain=p*total;
  ids.forEach((id,i)=>{{ const el=document.getElementById(id), L=lens[i], seg=Math.max(0,Math.min(L,remain)); remain-=L;
    if(seg<=0.01){{el.style.visibility='hidden';}} else {{ el.style.visibility='visible';
      if(seg>=L-0.01){{el.style.strokeDasharray='none';el.style.strokeDashoffset='0';}} else {{el.style.strokeDasharray=L+' '+(L+60);el.style.strokeDashoffset=(L-seg);}} }} }}); }}
function apply(st){{ drawTicks(st.lit,st.ext); num.textContent=String(st.num);
  for(const k in PATHS) setGroup(k,st.word[k]);
  if(st.core<=0.02){{core.style.visibility='hidden';}} else {{core.style.visibility='visible';core.setAttribute('r',9.5*st.core);}}
  tag.textContent=st.tag>0?FULL.slice(0,st.tag):'\\u200b';
  const w=st.tag>0?tag.getComputedTextLength():0; cur.setAttribute('x',TAGX+w+4); cur.style.visibility=st.cur?'visible':'hidden'; }}
</script></body></html>"""
    return html


def final_state():
    lit = [0 if i in LOST else 1 for i in range(100)]
    word = {"l": 1, "s": 1, "c": 1, "o": 1, "r": 1, "e": 1}
    return {"lit": lit, "ext": [0] * 100, "num": sum(lit), "word": word,
            "core": 1, "tag": len(TAGLINE), "cur": True}
