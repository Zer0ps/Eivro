#!/usr/bin/env python3
"""Build the bundled outline emoji font. Runtime requires no downloads/shaping.

Inputs: Google Fonts ofl/notoemoji/NotoEmoji[wght].ttf and Unicode 16 emoji-test.txt.
Build-only dependencies: fonttools, uharfbuzz. Preserve assets/NotoEmoji.LICENSE.
HarfBuzz resolves flags/ZWJ/skin tones once, into private cmap aliases for egui.
"""
import hashlib
import json
from pathlib import Path
import sys
import uharfbuzz as hb
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

root = Path(__file__).resolve().parent.parent
source, sequences = map(Path, sys.argv[1:3])
font = instantiateVariableFont(TTFont(source), {"wght": 400}, inplace=True)
hbfont = hb.Font(hb.Face(source.read_bytes()))
hbfont.set_variations({"wght": 400})
mapping = {}
for line in sequences.read_text().splitlines():
    line = line.split("#")[0].strip()
    if not line or ";" not in line:
        continue
    points, status = line.split(";")
    if status.strip() == "component":
        continue
    text = "".join(chr(int(cp, 16)) for cp in points.split())
    buf = hb.Buffer()
    buf.add_str(text)
    buf.guess_segment_properties()
    hb.shape(hbfont, buf)
    visible = [g.codepoint for g, p in zip(buf.glyph_infos, buf.glyph_positions) if p.x_advance]
    if len(visible) != 1 or visible[0] == 0:
        continue
    alias = 0xE000 + len(mapping)
    assert alias <= 0xF8FF
    name = font.getGlyphName(visible[0])
    for cmap in font['cmap'].tables:
        if cmap.isUnicode() and cmap.format in (4, 12):
            cmap.cmap[alias] = name
    mapping[text] = chr(alias)
for record in font['name'].names:
    if record.nameID in (1, 3, 4, 6, 16):
        record.string = ("VelumEmoji" if record.nameID == 6 else "Velum Emoji").encode(record.getEncoding())
font.save(root / 'assets/VelumEmoji.ttf')
(root / 'assets/emoji-map.json').write_text(json.dumps(mapping, ensure_ascii=False, separators=(',', ':')))
(root / 'assets/emoji-sources.json').write_text(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (source,sequences)},indent=2)+'\n')
print(f'Built {len(mapping)} emoji sequences, including flags and joined glyphs.')
