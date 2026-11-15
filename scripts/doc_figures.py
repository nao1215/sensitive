#!/usr/bin/env python3
"""Render measured benchmark data as deterministic, white-background SVG."""
import argparse
import html
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class SVG:
    def __init__(self, width, height, title, description):
        self.parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img">',
                      f'<title>{html.escape(title)}</title><desc>{html.escape(description)}</desc>',
                      '<rect width="100%" height="100%" fill="white"/>',
                      '<g font-family="Arial, sans-serif" font-size="15" fill="#172033">']

    def text(self, x, y, value, size=15, color='#172033', anchor='start'):
        self.parts.append(f'<text x="{x}" y="{y}" font-size="{size}" fill="{color}" text-anchor="{anchor}">{html.escape(str(value))}</text>')

    def line(self, x1, y1, x2, y2, color='#e1e5ec'):
        self.parts.append(f'<path d="M{x1},{y1} L{x2},{y2}" stroke="{color}"/>')

    def dot(self, x, y, color):
        self.parts.append(f'<circle cx="{x:.2f}" cy="{y}" r="4" fill="{color}"/>')

    def bar(self, x, y, width, height, color):
        self.parts.append(f'<rect x="{x}" y="{y}" width="{width:.2f}" height="{height}" rx="2" fill="{color}"/>')

    def render(self):
        return '\n'.join(self.parts + ['</g></svg>', ''])


def benchmark_chart(snapshot):
    data = snapshot['benchmarks']
    names = sorted(n.removeprefix('BenchmarkPublishedScanner/').removesuffix('/dirty')
                   for n in data if n.startswith('BenchmarkPublishedScanner/') and n.endswith('/dirty'))
    svg = SVG(960, 300 + 25 * len(names), 'Scanner throughput and slog time',
              'Dots show clean and sensitive input throughput on a logarithmic scale. Bars show time per slog event. All values are medians from the recorded raw samples.')
    svg.text(24, 32, 'Scanner throughput · MB/s · log scale · higher is faster', 21)
    svg.text(24, 57, f"{snapshot['date']} · {snapshot['go_version']} · {snapshot['os']}/{snapshot['arch']} · one CPU thread", 14)
    svg.dot(365, 81, '#1877b8'); svg.text(378, 86, 'Clean text')
    svg.dot(535, 81, '#b34b19'); svg.text(548, 86, 'Sensitive text')
    svg.text(815, 86, 'Clean / sensitive', 14, anchor='middle')
    bottom = 112 + 25 * (len(names)-1)
    values = [data['BenchmarkPublishedScanner/'+n+'/'+s]['MB/s'] for n in names for s in ['clean', 'dirty']]
    low, high = math.floor(math.log10(min(values))), math.ceil(math.log10(max(values)))
    x = lambda v: 205 + 470 * (math.log10(v)-low)/(high-low)
    for exponent in range(low, high+1):
        pos=x(10**exponent); svg.line(pos, 99, pos, bottom+12)
        svg.text(round(pos,2), bottom+32, f'{10**exponent:g}', 12, anchor='middle')
    for i, name in enumerate(names):
        y=112+25*i; svg.text(24, y+5, name)
        a,b=[data['BenchmarkPublishedScanner/'+name+'/'+s]['MB/s'] for s in ['clean','dirty']]
        svg.dot(x(a),y-2,'#1877b8');svg.dot(x(b),y+3,'#b34b19')
        svg.text(920,y+5,f'{a:,.2f} / {b:,.2f}',14,anchor='end')
    top=bottom+68
    svg.text(24,top,'slog · µs per event · lower is faster',21)
    series=[('Plain · clean','plain-clean'),('Masked · clean','masked-clean'),('Plain · sensitive','plain-dirty'),('Masked · sensitive','masked-dirty')]
    maximum=max(data['BenchmarkPublishedSlog/'+n]['ns/op']/1000 for _,n in series)
    for i,(label,name) in enumerate(series):
        value=data['BenchmarkPublishedSlog/'+name]['ns/op']/1000;y=top+22+i*23
        svg.text(24,y+13,label,14);svg.bar(205,y,470*value/maximum,15,'#b34b19' if name.startswith('masked') else '#1877b8')
        svg.text(700,y+13,f'{value:.2f} µs',14)
    return svg.render()


def artifacts():
    yield ROOT/'doc/images/benchmarks.svg', benchmark_chart(json.loads((ROOT/'doc/benchmarks.json').read_text(encoding='utf-8')))


def generate(check=False):
    for path, expected in artifacts():
        if check:
            if not path.exists() or path.read_text(encoding='utf-8') != expected:
                raise ValueError(f'{path.relative_to(ROOT)} is stale; run make doc-figures')
        else:
            path.write_text(expected,encoding='utf-8')


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--check',action='store_true')
    generate(parser.parse_args().check)
