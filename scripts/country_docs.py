"""Render country evaluation tables from measured JSON, without rescanning held data."""
import argparse
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]


def render_accuracy(rows):
    table='| Kind | Threshold | Dev TP / FP / FN | Dev P / R | Held TP / FP / FN | Held P / R | Exposed bytes dev / held |\n|---|---:|---:|---|---:|---|---:|\n'
    lookup={(r['set'],r['kind'],r['threshold']):r for r in rows}
    for kind in sorted({r['kind'] for r in rows}):
        for threshold in (0,.5,.7):
            dev=lookup['development',kind,threshold];held=lookup['held',kind,threshold]
            cells=[kind,str(threshold)]
            for r in (dev,held):cells.extend([f"{r['tp']} / {r['fp']} / {r['fn']}",f"{r['precision']} / {r['recall']}"])
            cells.append(f"{dev['residual_bytes']} / {held['residual_bytes']}")
            table+='| '+' | '.join(cells)+' |\n'
    return table


def render_logs(kinds,manifest,summary):
    table='| Kind | Dev findings | Dev sampled FP / sample | Dev estimated FP / GB | Held findings | Held sampled FP / sample | Held estimated FP / GB |\n|---|---:|---|---:|---:|---|---:|\n'
    for kind in sorted(kinds):
        cells=[kind]
        for split in ('development','held'):
            names={d['name'] for d in manifest['datasets'] if d['split']==split}
            size=sum(d['bytes'] for d in manifest['datasets'] if d['split']==split)
            count=samples=sample_fp=0;estimated=0.0
            for d in summary['datasets']:
                if d['dataset'] not in names:continue
                n=d['counts']['all'].get(kind,0);count+=n
                s=d['strata'].get(kind,{'sample_count':0,'sample_fp':0})
                samples+=s['sample_count'];sample_fp+=s['sample_fp']
                if n:estimated+=n*s['sample_fp']/s['sample_count']
            cells.extend([str(count),f'{sample_fp} / {samples}',f'{estimated/size*1e9:,.1f}'])
        table+='| '+' | '.join(cells)+' |\n'
    return table


def generate(check=False):
    rows=json.loads((ROOT/'doc/countries.json').read_text())
    manifest=json.loads((ROOT/'doc/real-logs-manifest.json').read_text())
    summary=json.loads((ROOT/'doc/real-logs-summary.json').read_text())
    blocks={'countries':render_accuracy(rows),'country-logs':render_logs({r['kind'] for r in rows},manifest,summary)}
    page=ROOT/'doc/countries.md';original=page.read_text();updated=original
    for name,table in blocks.items():
        pattern=r'(?s)(<!-- '+name+r':start -->\n).*?(<!-- '+name+':end -->)'
        if len(re.findall(pattern,updated))!=1:raise ValueError('missing country table marker')
        updated=re.sub(pattern,lambda m:m[1]+table+m[2],updated)
    if check:
        if original!=updated:raise ValueError('country documentation is stale')
    else:page.write_text(updated)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true');args=parser.parse_args()
    generate(args.check)
