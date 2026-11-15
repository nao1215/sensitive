#!/usr/bin/env python3
"""Measure pinned cached logs, or check only the committed aggregate evidence."""
import argparse
import hashlib
import html
import json
import os
import pathlib
import re
import subprocess
import tarfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOC = ROOT / 'doc'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def source_hash():
    paths = sorted([p for p in ROOT.glob('*.go') if not p.name.endswith('_test.go')]
                   + [p for p in (ROOT/'internal').rglob('*.go') if not p.name.endswith('_test.go')]
                   + list((ROOT/'tests/cmd/logscan').glob('*.go')))
    return digest(b''.join(p.relative_to(ROOT).as_posix().encode()+b'\0'+p.read_bytes() for p in paths))


def load(name):
    return json.loads((DOC/name).read_text(encoding='utf-8'))


def download(url, path, expected):
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(url, timeout=120) as response:
            data = response.read()
        if digest(data) != expected:
            raise ValueError('download checksum mismatch: '+url)
        path.write_bytes(data)
    if digest(path.read_bytes()) != expected:
        raise ValueError('cached checksum mismatch: '+str(path))


def cache_datasets(cache, manifest):
    if cache.resolve().is_relative_to(ROOT):
        raise ValueError('logs must be cached outside the repository')
    rev = manifest['upstream_commit']
    download(f'https://raw.githubusercontent.com/logpai/loghub/{rev}/LICENSE', cache/'LICENSE', manifest['datasets'][0]['license_sha256'])
    for item in manifest['datasets']:
        path = cache/item['path']
        if 'archive_sha256' in item:
            archive = cache/'archives'/item['url'].split('/files/')[1].split('?')[0]
            download(item['url'], archive, item['archive_sha256'])
            if not path.exists():
                with tarfile.open(archive) as bundle:
                    stream = bundle.extractfile(item['member'])
                    if stream is None:
                        raise ValueError('missing pinned archive member')
                    data = stream.read()
                if digest(data) != item['sha256']:
                    raise ValueError('extracted checksum mismatch')
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
        else:
            download(item['url'], path, item['sha256'])
        if digest(path.read_bytes()) != item['sha256']:
            raise ValueError('log checksum mismatch: '+str(path))


def summarize(raw, labels):
    rows = []
    for dataset in raw:
        row = {k:v for k,v in dataset.items() if k != 'samples'}
        row['strata'] = {}
        for kind, samples in dataset['samples'].items():
            ids = [sample['id'] for sample in samples]
            missing = [key for key in ids if key not in labels]
            if missing:
                raise ValueError('unreviewed samples: '+','.join(missing))
            if any(labels[key]['classification'] not in ('false-positive','sensitive-reference') for key in ids):
                raise ValueError('invalid classification')
            fp = sum(labels[key]['classification'] == 'false-positive' for key in ids)
            row['strata'][kind] = {'sample_ids':ids, 'sample_count':len(ids), 'sample_fp':fp}
        rows.append(row)
    return sorted(rows, key=lambda row:row['dataset'])


def measure(cache, manifest, labels):
    cache = cache.resolve()
    cache_datasets(cache, manifest)
    fingerprint = source_hash()
    rows = []
    for split in ('development', 'held'):
        output = cache/('measured-'+split+'.json')
        command = ['go','-C','tests','run','./cmd/logscan','--cache',str(cache), '--split',split,'--output',str(output)]
        subprocess.run(command, cwd=ROOT, env=dict(os.environ,GOMAXPROCS='4'), check=True)
        rows.extend(json.loads(output.read_text(encoding='utf-8')))
    if fingerprint != source_hash():
        raise ValueError('source changed during measurement; discard both scans and retry')
    summary = {'source_sha256':fingerprint, 'manifest_sha256':digest((DOC/'real-logs-manifest.json').read_bytes()),
               'labels_sha256':digest((DOC/'real-logs-labels.json').read_bytes()), 'baseline_sha256':digest((DOC/'real-logs-baseline.json').read_bytes()), 'datasets':summarize(rows,labels)}
    (DOC/'real-logs-summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')


def validate_strata(rows, labels):
    for row in rows:
        for s in row['strata'].values():
            classes = [labels[key]['classification'] for key in s['sample_ids']]
            if any(value not in ('false-positive', 'sensitive-reference') for value in classes):
                raise ValueError('invalid classification')
            if s['sample_count'] != len(classes) or s['sample_fp'] != classes.count('false-positive'):
                raise ValueError('aggregate labels disagree')


def estimate(rows, names, config, kind=None):
    count, fp, samples, sample_fp = 0, 0.0, 0, 0
    for row in rows:
        if row['dataset'] not in names:
            continue
        for name, total in row['counts'][config].items():
            if kind is not None and name != kind:
                continue
            s = row['strata'][name]
            count += total
            fp += total * s['sample_fp'] / s['sample_count']
            samples += s['sample_count']
            sample_fp += s['sample_fp']
    return count, fp, samples, sample_fp


def render(manifest, before, after):
    datasets = manifest['datasets']
    groups = {split:[d['name'] for d in datasets if d['split']==split] for split in ('development','held')}
    table = '| Dataset | Split | Scope | Bytes | Lines | License / source |\n|---|---|---|---:|---:|---|\n'
    for d in datasets:
        table += f"| {d['name']} | {d['split']} | {d['scope']} | {d['bytes']:,} | {d['lines']:,} | [LogHub research/academic use]({d['license_url']}); [provenance]({d['readme_url']}) |\n"
    table += '\nBefore retains b8290bc, the input to round 13; after uses the round-14 policy. These columns include the earlier round-13 fixes. The held split has now been seen and serves as regression data, not an independent evaluation of this change.\n\nRates below are estimated false-positive findings per decimal GB (10⁹ bytes), not counts of affected lines. IP addresses and published user/contact identities are sensitive references under this evaluation policy; the unspecified listener address 0.0.0.0 is an FP. Checksums do not establish a real account. A hostname fragment is an FP for MyNumber even if the hostname itself identifies a machine.\n\n'
    table += '| Detector | Development before / GB | Development after / GB | Held before / GB | Held after / GB |\n|---|---:|---:|---:|---:|\n'
    active=[]
    for kind in manifest['kinds']:
        values=[]
        for split in ('development','held'):
            size=sum(d['bytes'] for d in datasets if d['split']==split)
            for rows in (before,after):
                values.append(estimate(rows,groups[split],'all',kind)[1]/size*1e9)
        table+='| '+kind+' | '+' | '.join(f'{n:,.1f}' for n in values)+' |\n'
        if any(values): active.append((kind,values))
    table+='\n| Configuration | Development before / GB | Development after / GB | Held before / GB | Held after / GB |\n|---|---:|---:|---:|---:|\n'
    for config in ('all','default','kinds1','kinds3','kinds8'):
        values=[]
        for split in ('development','held'):
            size=sum(d['bytes'] for d in datasets if d['split']==split)
            for rows in (before,after):values.append(estimate(rows,groups[split],config)[1]/size*1e9)
        table+='| '+{'all':'WithAll','default':'Default slog handler'}.get(config,config)+' | '+' | '.join(f'{n:,.1f}' for n in values)+' |\n'
    table+='\nThe handler receives each raw line as its message and no attributes; its encoded message is checked against the scanner mask after JSON UTF-8 replacement. These numbers do not measure application-specific field-key policies. All 26 detectors also run separately, with exact findings compared to WithAll.\n\n'
    for name,kinds in manifest['configurations'].items():table+=f"- {name}: "+', '.join(kinds)+'.\n'
    table+='\nEach dataset/kind stratum uses the 40 lowest SHA-256 finding IDs, or every finding if there are fewer. Review labels are in [real-logs-labels.json](real-logs-labels.json); counts and sampled FP fractions are in [real-logs-summary.json](real-logs-summary.json). The estimate sums count × sampled FP fraction across datasets. Zero observed sample FPs does not establish zero population FPs. Small samples, repeated templates and this 92.4 MB source mix cannot predict a deployment’s rate. No recall estimate is possible without labeling undetected secrets.\n'
    height=125+len(active)*64
    maximum=max(max(v) for _,v in active)
    svg=[f'<svg xmlns="http://www.w3.org/2000/svg" width="960" height="{height}" viewBox="0 0 960 {height}" role="img" aria-labelledby="title desc">',
         '<title id="title">Estimated false positives on public logs</title>',
         '<desc id="desc">Before and after rates per decimal GB, split by development and held-out sources. Bars show the same sample-based estimates as the adjacent table; they are not recall measurements.</desc>',
         f'<rect width="960" height="{height}" fill="#101923"/>',
         '<g font-family="sans-serif" fill="#eff6ff"><text x="24" y="30" font-size="22">Public logs · estimated FP per GB · lower is better</text>',
         '<text x="24" y="55" font-size="14">Development: before / after (blue) · Held-out: before / after (orange)</text>',
         '<text x="24" y="78" font-size="13">8 datasets · 819,576 lines · 92.4 MB · at most 40 sampled findings per stratum</text>']
    for i,(kind,values) in enumerate(active):
        y=100+i*64
        svg.append(f'<text x="24" y="{y+18}" font-size="15">{html.escape(kind)}</text>')
        for j,value in enumerate(values):
            width=value/maximum*570
            color=('#85b8ff','#347ac7','#ffc78a','#b87629')[j]
            svg.append(f'<rect x="160" y="{y+j*13}" width="{width:.2f}" height="10" fill="{color}"/><text x="{170+width:.2f}" y="{y+j*13+9}" font-size="10">{value:,.1f}</text>')
    svg.append('</g></svg>\n')
    return table,'\n'.join(svg)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--measure',action='store_true')
    parser.add_argument('--check',action='store_true')
    parser.add_argument('--cache',type=pathlib.Path,default=pathlib.Path.home()/'.cache/embargo-real-logs')
    args=parser.parse_args()
    manifest=load('real-logs-manifest.json')
    labels=load('real-logs-labels.json')['labels']
    if args.measure:measure(args.cache,manifest,labels)
    summary=load('real-logs-summary.json')
    if summary['source_sha256']!=source_hash():raise SystemExit('real-log source changed: run make real-log-accuracy')
    for name,key in (('real-logs-manifest.json','manifest_sha256'),('real-logs-labels.json','labels_sha256'),('real-logs-baseline.json','baseline_sha256')):
        if digest((DOC/name).read_bytes())!=summary[key]:raise SystemExit('real-log evidence changed: '+name)
    before=load('real-logs-baseline.json')['datasets']
    after=summary['datasets']
    for rows in (before,after):
        validate_strata(rows, labels)
    table,svg=render(manifest,before,after)
    page=DOC/'real-logs.md'
    text=page.read_text(encoding='utf-8')
    pattern = r'(?s)(<!-- real-logs:start -->\n).*?(<!-- real-logs:end -->)'
    if len(re.findall(pattern,text)) != 1:
        raise ValueError('expected one real-log table block')
    updated=re.sub(pattern,lambda m:m[1]+table+m[2],text)
    readme = ROOT/'README.md'
    original = readme.read_text(encoding='utf-8')
    synopsis = '![Estimated false positives on public logs](doc/images/real-logs.svg)\n\nRound 14: 8 public datasets, 92.4 MB, 819,576 lines. [Licenses, classification rules, per-kind and per-configuration FP/GB](doc/accuracy.md#public-system-logs). Rates are sample estimates on previously seen splits; contact and endpoint references count as sensitive data, and no recall claim is made.\n'
    readme_pattern = r'(?s)(<!-- real-logs-summary:start -->\n).*?(<!-- real-logs-summary:end -->)'
    if len(re.findall(readme_pattern,original)) != 1:
        raise ValueError('expected one README real-log block')
    readme_updated = re.sub(readme_pattern,lambda m:m[1]+synopsis+m[2],original)
    for path,data in ((page,updated),(DOC/'images/real-logs.svg',svg),(readme,readme_updated)):
        if args.check:
            if path.read_text(encoding='utf-8')!=data:raise SystemExit('stale generated real-log evidence: '+str(path))
        else:path.write_text(data,encoding='utf-8')
    import accuracy_figures
    accuracy_figures.generate(check=args.check)


if __name__=='__main__':main()
