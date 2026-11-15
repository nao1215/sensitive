#!/usr/bin/env python3
"""Render scored synthetic fixtures and reviewed misses without rescoring inputs."""
import argparse
import html
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read_jsonl(name):
    return [json.loads(line) for line in (ROOT/'tests/testdata'/name).read_text(encoding='utf-8').splitlines()]


def chart(rows):
    height = 113+30*len(rows)
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="960" height="{height}" viewBox="0 0 960 {height}" role="img">',
             '<title>Precision and recall on synthetic samples</title>',
             '<desc>Blue bars show precision; orange bars show recall. Counts are positive and negative inputs per detector.</desc>',
             '<rect width="100%" height="100%" fill="white"/>',
             '<g font-family="Arial, sans-serif" font-size="14" fill="#172033">']
    def text(x,y,value,size=14):
        parts.append(f'<text x="{x}" y="{y}" font-size="{size}">{html.escape(str(value))}</text>')
    text(20,28,'Precision and recall · synthetic corpus',21)
    text(20,54,'Precision: how many reported matches were correct. Recall: how many expected matches were found.',14)
    text(20,81,'Detector');text(205,81,'Precision',15);text(435,81,'Recall',15);text(685,81,'Positive / negative inputs')
    for i,row in enumerate(rows):
        y=105+30*i
        text(20,y+5,row['detector'])
        for x,key,color in [(205,'precision','#1877b8'),(435,'recall','#b34b19')]:
            parts.append(f'<rect x="{x}" y="{y-9}" width="150" height="14" fill="#edf0f4"/>')
            width=float(row[key].rstrip('%'))*1.5
            parts.append(f'<rect x="{x}" y="{y-9}" width="{width:.2f}" height="14" fill="{color}"/>')
            text(x+158,y+4,row[key])
        text(730,y+5,f"{row['positive']} / {row['negative']}")
    return '\n'.join(parts+['</g></svg>',''])


TEST_FILES = {'aba_routing':'aba','ach_trace':'ach','google_api_key':'google_apikey','uk_sortcode':'sortcode'}
HARD_CASES = {
 'pan':'Luhn-valid Visa, Mastercard, Amex and JCB shapes, hyphen-separated groups and full-width digits.',
 'phone_jp':'Hyphenated mobile numbers, full-width digits and Japanese text boundaries.',
 'mynumber':'Independently generated MOD 11 check digits, full-width digits and Japanese text boundaries.',
 'iban':'Independently generated German MOD 97 check digits and surrounding JSON or log text.',
 'btc':'Independently generated Base58Check P2PKH addresses and invalid checksum look-alikes.',
 'eth':'Lowercase hexadecimal addresses and malformed non-hexadecimal look-alikes.',
 'email':'Plus-addressing, JSON fields, Japanese boundaries and doubled-at-sign negatives.',
 'ipaddr':'Documentation-range IPv4 and IPv6 addresses, Japanese boundaries and invalid octets.',
 'jwt':'Base64url header, payload and signature fields; malformed payload look-alikes.',
 'private_key_pem':'RSA, EC, OpenSSH and PKCS#8 private-key headers; public-key and certificate headers as negatives.',
 'swiftbic':'Eight- and eleven-character shapes near SWIFT context, with invalid country-code look-alikes.',
 'uk_sortcode':'Separated sort codes, context words, and overlong sequences as negatives.',
 'awskey':'AKIA and ASIA prefixes in log, JSON and Japanese text; short tokens as negatives.',
 'github_token':'Four classic token prefixes in log, JSON and Japanese text; short tokens as negatives.',
 'slack_token':'Multi-part xoxb shapes in log, JSON and Japanese text; an unsupported type letter as a negative.',
 'google_api_key':'AIza-prefixed keys in log, JSON and Japanese text; short bodies as negatives.',
 'payment_token':'Five payment-token prefixes in log, JSON and Japanese text; short bodies as negatives.',
 'aba_routing':'Independently generated routing checksums, line endings and checksum failures.',
 'ach_trace':'Contextual fifteen-digit traces, line endings and short traces as negatives.',
 'bank_account':'Contextual account numbers in log, JSON and Japanese text; too-short values as negatives.',
 'card_expiry':'Month/year dates near expiry context in log, JSON and Japanese text; invalid months as negatives.',
 'cvv':'Three-digit values near CVV context in log, JSON and Japanese text; two-digit values as negatives.',
 'merchant_id':'Contextual merchant IDs in log, JSON and Japanese text; short IDs as negatives.',
}


def excerpt(value):
    # Keep public documentation free of complete generated credential-shaped tokens.
    if '?value=' in value:
        value = 'value=' + value.split('?value=', 1)[1].split('&result=', 1)[0]
    value = value.replace('\n',' ↵ ').replace('|','&#124;').replace('`','&#96;')
    return value if len(value) <= 65 else value[:40]+'…'+value[-12:]


def page(rows):
    samples = {row['id']:row for row in read_jsonl('accuracy_generated.jsonl')}
    controls = {row['id']:row for row in read_jsonl('accuracy_generated_controls.jsonl')}
    for row in json.loads((ROOT/'tests/testdata/accuracy_controls.json').read_text(encoding='utf-8')):
        key = 'hand-control/' + hashlib.sha256((row['source']+'\0'+row['text']).encode()).hexdigest()
        controls[key] = row
    for kind in [row['detector'] for row in rows]:
        for key, row in controls.items(): samples[kind+'/'+key] = row
    hand = json.loads((ROOT/'tests/testdata/accuracy.json').read_text(encoding='utf-8'))
    samples.update({'hand/'+str(i):row for i,row in enumerate(hand)})
    limits=read_jsonl('accuracy_limits.jsonl')
    total=sum(row['positive']+row['negative'] for row in rows)
    out = ['# Synthetic accuracy corpus', '',
           '## Conditions', '',
           f'This corpus contains {total:,} detector/input evaluations. It is generated offline with Python `random.Random(20261115)` and contains no production observations. Repeated surroundings reuse values, so sample counts are not independent statistical trials.', '',
           f'The [generator](../scripts/generate_accuracy.py) constructs values and byte ranges without invoking embargo. Each detector receives {rows[0]["positive"]} positive inputs and {rows[0]["negative"]} negative inputs: two hand-written positives plus 24 values in six surroundings, and hand-written, generated and shared negative controls. CI checks the generated fixtures, scores, figures and this page for drift.', '',
           'Surroundings include logs, JSON, URLs, line endings and Japanese text, with full-width digits and separators for supported numeric families. Negative controls include UUIDs, Git SHAs, hashes, timestamps, order/invoice identifiers, base64 without a JWT header, versions and phone-shaped serial numbers. Detector-specific negatives include bad checksums, invalid prefixes, short credentials and invalid months.', '',
           'A hit requires an unused expected range with the same detector kind and exact original byte positions. Partial, duplicate and extra matches are false positives; an unmatched expected range is a false negative. Precision is TP/(TP+FP), and recall is TP/(TP+FN).', '',
           'Each detector runs alone at the default confidence threshold. URL-encoded positives remain labeled sensitive even where the scanner cannot decode them. This deliberately exposes misses instead of redefining the expected answer.', '',
           'The samples cover only the listed format variants. They do not establish account existence, credential validity or behavior on other encodings.', '',
           '[Scoring tests](../tests/accuracy_test.go) cover partial, wrong-kind and duplicate matches. [Regression tests](../tests/accuracy_regression_test.go) reject new mismatches and obsolete exceptions. The reviewed [limit list](../tests/testdata/accuracy_limits.jsonl) records each mismatch and its reason; the first expanded run failed before those limits were documented.', '',
           '## Results', '',
           '![Precision and recall on synthetic samples](images/accuracy.svg)', '',
           '| Detector | Positive / negative inputs | TP / FP / FN spans | Precision | Recall |',
           '|---|---:|---:|---:|---:|']
    for row in rows:
        k=row['detector'];out.append(f"| [{k}](#{k.replace('_','-')}) | {row['positive']} / {row['negative']} | {row['tp']} / {row['fp']} / {row['fn']} | {row['precision']} | {row['recall']} |")
    for row in rows:
        kind=row['detector']; test=TEST_FILES.get(kind,kind)
        if not (ROOT/f'internal/detect/{test}_test.go').exists(): raise ValueError(kind)
        out += ['',f"## {kind.replace('_',' ')}",'',f'![{kind} precision and recall](images/accuracy-{kind}.svg)', '',
                f"Verified by the [{kind} format tests](../internal/detect/{test}_test.go) and the [corpus regression check](../tests/accuracy_regression_test.go). {HARD_CASES[kind]}", '']
        selected=[];seen=set()
        for limit in limits:
            sample=samples.get(limit['id'])
            if sample is None: raise ValueError('missing sample '+limit['id'])
            if sample.get('kind',limit['id'].split('/')[0]) != kind: continue
            key=limit['reason']
            if key in seen: continue
            seen.add(key);selected.append((limit,sample))
        if not selected:
            out += ['No misses or false alarms appeared in these samples.']
        else:
            out += ['| Observed limit | Input example | Why it remains |','|---|---|---|']
            for limit,sample in selected:
                original=sample.get('text','')+''.join(sample.get('parts',[]))
                out.append(f"| `{limit['id']}` | `{excerpt(original)}` | {limit['reason']} |")
        out += ['', '[Inspect generated inputs and original byte ranges](../tests/testdata/accuracy_generated.jsonl).']
    out += ['', '## Regeneration', '', '```sh', 'make accuracy-doc', 'python3 scripts/generate_accuracy.py --check', 'python3 scripts/accuracy_figures.py --check', 'go -C tests test -run "Test(Accuracy|GeneratedAccuracy)" .', '```', '',
            'PEM fixtures test headers rather than complete private keys. Generated service tokens test syntax, not authentication; generated identity and phone values must not be used for contacting people or transactions.', '',
            '[Support maintenance](https://github.com/sponsors/nao1215).', '']
    return '\n'.join(out)


def artifacts():
    rows=json.loads((ROOT/'doc/accuracy.json').read_text(encoding='utf-8'))
    yield ROOT/'doc/images/accuracy.svg',chart(rows)
    for row in rows: yield ROOT/f"doc/images/accuracy-{row['detector']}.svg",chart([row])
    yield ROOT/'doc/accuracy.md',page(rows)


def generate(check=False):
    for path, expected in artifacts():
        if check:
            if not path.exists() or path.read_text(encoding='utf-8') != expected:
                raise ValueError(f'{path.relative_to(ROOT)} is stale; run make accuracy-doc')
        else: path.write_text(expected,encoding='utf-8')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true')
    generate(parser.parse_args().check)
