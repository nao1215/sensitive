"""Check prose using explicit rules and exact, reasoned exceptions."""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
FILLER = re.compile(r'\b(robust|seamless|comprehensive|leverage|effortless|powerful|simply|just)\b', re.I)
STOCK = re.compile(r'\b(in today.s (?:world|landscape)|in conclusion|in summary|it.s worth noting|look no further|happy coding|thank you again for considering|this document explains how to)\b', re.I)
EMOJI = re.compile('[\U0001f000-\U0001faff\u2600-\u27bf\ufe0f]')


def rendered(text):
    text = re.sub(r'!?\[([^\]]*)\]\([^)]*\)', r'\1', text)
    return re.sub(r'<[^>]+>|`|\*', '', text)


def issue(path, rule, text, line=0):
    digest = hashlib.sha256(text.encode()).hexdigest()[:16]
    return {'key': f'{path}:{rule}:{digest}', 'path': path, 'line': line, 'rule': rule, 'text': text}


def text_rules(path, text, line=0, code=False):
    result = []
    visible = re.sub(r'https?://\S+', '', text)
    for rule, regex in [('filler', FILLER), ('stock', STOCK), ('emoji', EMOJI)]:
        if regex.search(visible):
            result.append(issue(path, rule, text, line))
    if not code and re.search(r'\*\*\S[^*]*\*\*|__\S[^_]*__', re.sub(r'`[^`]*`', '', visible)):
        result.append(issue(path, 'bold', text, line))
    return result


def markdown(path, text):
    result = []
    fence = False
    paragraph = []
    def flush():
        if len(paragraph) > 1:
            result.append(issue(path, 'paragraph', '\n'.join(x[1] for x in paragraph), paragraph[0][0]))
        paragraph.clear()
    for line, raw in enumerate(text.splitlines(), 1):
        if raw.startswith('```'):
            fence = not fence
            flush()
            continue
        if fence:
            continue
        result.extend(text_rules(path, raw, line))
        if raw.startswith('|'):
            cells = re.split(r'(?<!\\)\|', raw.strip('|'))
            for cell in cells:
                # 120 visible characters approximate two lines in a wide cell
                # at 1280px. Narrow columns still require visual review.
                if len(rendered(cell).strip()) > 120:
                    result.append(issue(path, 'table', cell.strip(), line))
        if not raw or re.match(r'\s*(?:#|\||<|>|[-*+] |\d+\.|\[.*\]:|---)', raw) or raw.startswith(' '):
            flush()
        elif re.search('[A-Za-z]', raw) and not raw.startswith(('[![', '![', '](http')):
            paragraph.append((line,raw))
    flush()
    return result


def godoc(items):
    result = []
    templates = collections.defaultdict(list)
    sentences = collections.defaultdict(list)
    totals = collections.Counter()
    for item in items:
        name,text,path = item['name'],item['text'],item['path']
        result.extend(text_rules(path,text,item['line'],code='/literal' in name))
        if name.startswith('Example'):
            continue
        if not text.strip():
            result.append(issue(path,'missing-godoc',name,item['line']))
            continue
        first = ' '.join(text.split('\n\n')[0].split())
        # Ignore the required identifier prefix when measuring templates.
        words = re.findall('[A-Za-z]+',first)[1:]
        totals[item['package']] += 1
        if len(words)>=3:
            templates[(item['package'],' '.join(words[:3]).lower())].append(item)
        simple = re.sub(r'[^a-z]', '', ' '.join(words).lower())
        identifier = re.sub(r'^(New|With|Get|Set)', '', name).lower()
        if simple in {identifier,'returns'+identifier,'createsthe'+identifier,'createsanew'+identifier+'detect','createsanew'+identifier+'detector'} or re.fullmatch(r'New\w+ creates a new [A-Za-z /-]+ detect(?:or)?\.', first):
            result.append(issue(path,'restatement',text,item['line']))
        for sentence in re.split(r'(?<=[.!?])\s+',first):
            if len(sentence)>70:
                sentences[(item['package'],sentence)].append(item)
        if re.search(r'\d+(?:\.\d+)?/\d+(?:\.\d+)?/\d+(?:\.\d+)?\s*(?:µs|ms|ns)', text):
            result.append(issue(path,'benchmark-list',text,item['line']))
    for (package,template),entries in templates.items():
        if len(entries)>=8 and len(entries)/totals[package]>.25:
            result.append(issue(package,'template',template+': '+','.join(sorted(x['name'] for x in entries))))
    for (package,sentence),entries in sentences.items():
        if len(entries)>=3:
            result.append(issue(package,'repeated-sentence',sentence))
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json',action='store_true')
    args=parser.parse_args()
    findings=[]
    for path in [ROOT/'README.md',ROOT/'CHANGELOG.md',ROOT/'CONTRIBUTING.md',*sorted((ROOT/'doc').glob('*.md'))]:
        findings.extend(markdown(str(path.relative_to(ROOT)),path.read_text()))
    extracted=subprocess.check_output(['go','-C',str(ROOT/'tests'),'run','./cmd/prose',str(ROOT)],text=True)
    findings.extend(godoc(json.loads(extracted)))
    allow_path=ROOT/'scripts/prose_allowlist.json'
    allow=json.loads(allow_path.read_text()) if allow_path.exists() else {}
    for key,reason in allow.items():
        if not reason.strip():raise RuntimeError('exception lacks reason: '+key)
    keys={f['key'] for f in findings}
    stale=set(allow)-keys
    failures=[f for f in findings if f['key'] not in allow]
    if args.json:print(json.dumps(findings,indent=2));return
    for f in failures:print(f"{f['path']}:{f['line']}: {f['rule']}: {f['text'][:180]}")
    for key in sorted(stale):print('stale prose exception: '+key)
    print(f'{len(failures)} prose violations; {len(allow)} exact exceptions')
    if failures or stale:sys.exit(1)


if __name__=='__main__':main()
