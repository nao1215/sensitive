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
             '<title>Precision and recall on held-out synthetic samples</title>',
             '<desc>Blue bars show precision; orange bars show recall. Counts are positive and negative inputs per detector.</desc>',
             '<rect width="100%" height="100%" fill="white"/>',
             '<g font-family="Arial, sans-serif" font-size="14" fill="#172033">']
    def text(x,y,value,size=14):
        parts.append(f'<text x="{x}" y="{y}" font-size="{size}">{html.escape(str(value))}</text>')
    text(20,28,'Precision and recall · held-out synthetic corpus',21)
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


def result_table(rows):
    out = ['| Detector | Positive / negative inputs | TP / FP / FN spans | Precision | Recall |', '|---|---:|---:|---:|---:|']
    for row in rows:
        k = row['detector']
        out.append(f"| [{k}](#{k.replace('_','-')}) | {row['positive']} / {row['negative']} | {row['tp']} / {row['fp']} / {row['fn']} | {row['precision']} | {row['recall']} |")
    return out


def sample_index(held):
    prefix = 'accuracy_held_' if held else 'accuracy_'
    samples = {row['id']: row for row in read_jsonl(prefix+'generated.jsonl')}
    controls = {row['id']: row for row in read_jsonl(prefix+'generated_controls.jsonl')}
    if not held:
        for row in json.loads((ROOT/'tests/testdata/accuracy_controls.json').read_text(encoding='utf-8')):
            key = 'hand-control/' + hashlib.sha256((row['source']+'\0'+row['text']).encode()).hexdigest()
            controls[key] = row
        hand = json.loads((ROOT/'tests/testdata/accuracy.json').read_text(encoding='utf-8'))
        samples.update({'hand/'+str(i): row for i, row in enumerate(hand)})
    for kind in HARD_CASES:
        for key, row in controls.items(): samples[kind+'/'+key] = row
    return samples


def severity_section():
    rows = json.loads((ROOT/'doc/severity.json').read_text())
    out = ['## Severity and residual exposure', '',
           'These evaluation tiers are private to the test suite. Critical covers credentials, service and payment tokens, cloud and VCS tokens, private keys, PAN and JWT. High covers national IDs, bank accounts, IBAN and routing numbers, including UK sort codes. Email, phone, IP, crypto addresses and the remaining kinds are standard. Tier labels do not change the public Scanner API.', '',
           'Both committed synthetic corpora are combined with the credential corpus for the same split. Each detector runs alone. Recall still requires an exact kind and span; residual exposure independently counts original bytes outside the union of masked ranges for every expected secret. A partially masked value remains exposed. Overlapping findings cover a byte once, and an invalid range follows Mask’s whole-input redaction rule. The [per-secret ledger](../tests/testdata/residual-exposure.json) records every expected range and its unmasked byte count at threshold zero, including zeros. These historical held fixtures are regression evidence after inspection.', '',
           '| Set | Tier | Threshold | TP / FP / misses | Recall | Exposed values / bytes |',
           '|---|---|---:|---:|---:|---:|']
    for row in rows:
        recall = 100*row['tp']/(row['tp']+row['fn'])
        out.append(f"| {row['set']} | {row['tier']} | {row['threshold']:.1f} | {row['tp']} / {row['fp']} / {row['fn']} | {recall:.2f}% | {row['exposed_secrets']} / {row['residual_bytes']} |")
    out += ['', 'The critical gate requires the current 100% exact-span recall and zero residual bytes in each split at threshold zero. Updating a snapshot cannot relax this assertion. Unit tests inject a partial mask, overlapping ranges, missing findings and an empty corpus to check the gate and exposure calculation.', '',
            'The default confidence decision is 0 for every tier. Critical precision improves at 0.7 on these committed fixtures, but the fixtures do not establish that a mislabeled card can be discarded safely; a business label can reduce a real PAN’s score to 0.4. High loses 152 development and 150 held findings at 0.7, leaving 1,215 and 1,200 bytes exposed. Standard loses all 120 entropy positives in each split at 0.5. Entropy remains opt-in because its public-ID negatives have the same value distribution. These observations support retaining findings and selecting kinds or sensitive keys for a particular output boundary; they do not support an implicit per-tier cutoff.', '']
    return out


def page(rows):
    development = json.loads((ROOT/'doc/accuracy.json').read_text())
    dev50 = json.loads((ROOT/'doc/accuracy-50.json').read_text())
    held50 = json.loads((ROOT/'doc/accuracy-held-50.json').read_text())
    dev70 = json.loads((ROOT/'doc/accuracy-70.json').read_text())
    held70 = json.loads((ROOT/'doc/accuracy-held-70.json').read_text())
    out = ['# Synthetic accuracy corpus', '', '## Conditions', '',
           'The development set uses Python `random.Random(20261115)`; the held-out set uses `random.Random(20270129)` and six different surrounding templates. Both were fixed before detector changes. Tuning used development failures and independent code-review regressions; the held-out evaluation rejected a stricter SWIFT context rule because it reduced recall. We treated this as overfitting and reverted the rule; no held-out failure was used to tune the retained changes.', '',
           f'Development contains {sum(r["positive"]+r["negative"] for r in development):,} evaluations; held-out contains {sum(r["positive"]+r["negative"] for r in rows):,}. The [generator](../scripts/generate_accuracy.py) constructs values and original byte ranges without invoking embargo. Development includes hand-written controls; held-out includes only independently generated values and controls. Repeated surroundings reuse values, and deterministic format examples such as email names and date cycles occur in both sets. Counts are not independent statistical trials. This is synthetic evaluation, not evidence of production accuracy or credential validity.', '',
           'Surroundings include logs, JSON, URLs, line endings and Japanese text. Negative controls include hashes, UUIDs, timestamps, order/invoice/tracking identifiers, versions, invalid checksums and malformed credentials. Labels and templates are not a substitute for a real-world corpus.', '',
           'A hit requires the same kind and exact unused original byte range. Partial, duplicate and extra matches count as false positives; missing expected ranges count as false negatives. Precision is TP/(TP+FP); recall is TP/(TP+FN). Each detector runs alone.', '',
           'The default minimum confidence remains 0: ambiguous candidates are included. Confidence is a heuristic, not a probability. PAN checksum failures score 0.6; PAN, My Number and Japanese phone candidates with an attached order, invoice, tracking, version, build, serial or shipment label score 0.4. `WithMinConfidence(0.7)` excludes these candidates and can therefore miss genuine secrets under misleading business labels. A global 0.7 threshold also removes the 0.5–0.65 bank-account findings and some sort-code findings; it is not a universal accuracy setting. Both policies are measured below; the README chart uses held-out results at the default threshold.', '',
           '## Encoding policy', '',
           'The original 23 built-in detectors decode exactly one layer of valid `%HH` escapes anywhere in the input before detection. Findings map back to original bytes, so masking covers the escaped representation. Literal `+` and malformed percent escapes remain unchanged. Custom detectors receive the original bytes. Base64, hexadecimal, HTML entities, JSON escapes and recursively percent-encoded forms are not decoded by Scanner; decode application fields explicitly when needed. The logger adapters separately decode JSON strings at their output boundary.', '',
           '[Round-trip and offset properties](../scanner_encoding_test.go) exercise random partial escaping and all byte values. [Regression tests](../tests/accuracy_regression_test.go) reject new mismatches and obsolete exceptions in both sets. Known limits retain reasons in [development](../tests/testdata/accuracy_limits.jsonl) and [held-out](../tests/testdata/accuracy_held_limits.jsonl) fixtures.', '',
           '## Held-out results: default threshold 0', '',
           '![Held-out precision and recall](images/accuracy.svg)', ''] + result_table(rows)
    out += ['', '## Development results: default threshold 0', ''] + result_table(development)
    out += ['', '## Held-out results: minimum confidence 0.5', ''] + result_table(held50)
    out += ['', '## Development results: minimum confidence 0.5', ''] + result_table(dev50)
    out += ['', '## Held-out results: minimum confidence 0.7', ''] + result_table(held70)
    out += ['', '## Development results: minimum confidence 0.7', ''] + result_table(dev70)
    limits = [(name, sample_index(held), read_jsonl(('accuracy_held_' if held else 'accuracy_')+'limits.jsonl')) for name, held in [('development', False), ('held-out', True)]]
    for row in rows:
        kind = row['detector']; test = TEST_FILES.get(kind, kind)
        out += ['', f"## {kind.replace('_', ' ')}", '', f'![Held-out {kind} precision and recall](images/accuracy-{kind}.svg)', '', f"Verified by the [{kind} format tests](../internal/detect/{test}_test.go) and the [corpus regression check](../tests/accuracy_regression_test.go). {HARD_CASES[kind]}", '']
        selected = []; seen = set()
        for name, samples, entries in limits:
            for limit in entries:
                sample = samples[limit['id']]
                if sample.get('kind', limit['id'].split('/')[0]) != kind: continue
                if limit['reason'] in seen: continue
                seen.add(limit['reason']); selected.append((name, limit, sample))
        if not selected:
            out += ['At the default threshold, no misses or false alarms appeared in either set.']
        else:
            out += ['| Set / observed limit | Input example | Why it remains |', '|---|---|---|']
            explanations = []
            for name, limit, sample in selected:
                original = sample.get('text', '')+''.join(sample.get('parts', []))
                reason = limit['reason']
                if len(reason) > 120:
                    explanations.append(reason)
                    reason = f'Explanation {len(explanations)} below.'
                out.append(f"| {name}: `{limit['id']}` | `{excerpt(original)}` | {reason} |")
            for index, reason in enumerate(explanations, 1):
                out += ['', f'{index}. {reason}']
    out += ['', '## Regeneration', '', '```sh', 'make accuracy-doc', 'python3 scripts/generate_accuracy.py --check', 'python3 scripts/accuracy_figures.py --check', 'go -C tests test -run "Test(Accuracy|GeneratedAccuracy)" .', '```', '',
            'The 0.7 results improve PAN, My Number and phone precision on both sets without losing recall in these samples; the default retains their ambiguous business identifiers. Email and encoded-form recall improve on both sets. SWIFT word false positives remain: the rejected attachment rule improved development precision but failed held-out evaluation. Round 12 adds development regressions for reserved IBAN check digits 00, 01 and 99 and rejects them before MOD 97. The four formerly held-out false positives are fixed; this historical set is now regression evidence, not unseen evaluation.', '',
            'PEM samples test headers, not full private keys. Generated service tokens test syntax, not authentication. Do not use synthetic identities, account or phone values for transactions or contacting people.', '', '[Support maintenance](https://github.com/sponsors/nao1215).', '']
    out += ['', (ROOT/'doc/credentials-accuracy.md').read_text(), '', '## Default policy decision', '', 'Scanner, slog, adapters and embargotest keep threshold 0. NewScanner and the zero Scanner now omit KindHighEntropy; WithAll or WithKinds(KindHighEntropy) enables it. The historical credential held set gave entropy 50.0% precision and 98.3% recall: public random IDs share the token distribution. The real-log study removed 273 path findings but cannot establish that a bare random token is a secret. Opt-in keeps that trade-off visible instead of disguising it with a confidence adjustment. Slog and adapters honor the explicit Scanner supplied by the caller, while embargotest favors finding forgotten values. Threshold 0.5 removes business-label candidates but retains PAN checksum failures and loses every unlabeled entropy finding. Threshold 0.7 additionally loses bank-account and some sort-code findings. Neither becomes a hidden default. Choose a threshold explicitly for the selected kinds; confidence is not probability. SWIFT development precision remains 54.9%; changing the global threshold does not repair ambiguous alphabetic bank codes.', '']
    out += ['', *severity_section()]
    out += ['', (ROOT/'doc/real-logs.md').read_text(encoding='utf-8')]
    return '\n'.join(out)


def artifacts():
    rows=json.loads((ROOT/'doc/accuracy-held.json').read_text(encoding='utf-8'))
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
