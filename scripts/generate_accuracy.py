#!/usr/bin/env python3
"""Build labeled synthetic fixtures without importing or invoking embargo.

Development seed 20261115 and held-out seed 20270129 use separate surroundings.
Each set has 24 generated values per kind, six surroundings and 16
invalid values per kind. Byte ranges come from construction, never detection.
The generated tokens are test data and must never be used as credentials.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import random
import string
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
SEED = 20261115


def digits(rng, n):
    return ''.join(rng.choice(string.digits) for _ in range(n))


def chars(rng, n):
    return ''.join(rng.choice(string.ascii_letters + string.digits) for _ in range(n))


def luhn(body):
    total = sum((2 * int(c) // 10 + 2 * int(c) % 10) if i % 2 == 0 else int(c)
                for i, c in enumerate(reversed(body)))
    return body + str(-total % 10)


def mynumber(body):
    remainder = sum(int(c) * w for c, w in zip(body, [6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2])) % 11
    return body + str(0 if remainder <= 1 else 11 - remainder)


def aba(body):
    return body + str(-sum(int(c) * [3, 7, 1][i % 3] for i, c in enumerate(body)) % 10)


def iban(body):
    return 'DE' + f'{98 - int(body + "131400") % 97:02}' + body


def bitcoin(payload):
    data = b'\0' + payload
    data += hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    value, result = int.from_bytes(data, 'big'), ''
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    while value:
        value, digit = divmod(value, 58)
        result = alphabet[digit] + result
    return '1' * (len(data) - len(data.lstrip(b'\0'))) + result


def fullwidth(value):
    return value.translate(str.maketrans('0123456789-', '０１２３４５６７８９－'))


def specimens(rng, i):
    pan = luhn(['4', '51', '37', '3528'][i % 4] + digits(rng, [14, 13, 12, 11][i % 4]))
    phone = '090-' + digits(rng, 4) + '-' + digits(rng, 4)
    national_id = mynumber(digits(rng, 11))
    if i % 3 == 1:
        pan = '-'.join(pan[j:j+4] for j in range(0, len(pan), 4))
    if i % 3 == 2:
        pan, phone, national_id = map(fullwidth, (pan, phone, national_id))
    jwt = '.'.join(base64.urlsafe_b64encode(v).decode().rstrip('=') for v in
                   [b'{"alg":"HS256","typ":"JWT"}', json.dumps({'sub': f'fixture-{i}'}).encode(), chars(rng, 24).encode()])
    return {
        'pan': ('', pan), 'email': ('', f'user.{i}+fixture@example.com'),
        'phone_jp': ('', phone), 'mynumber': ('', national_id),
        'jwt': ('', jwt), 'awskey': ('', ['AKIA', 'ASIA'][i % 2] + ''.join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(16))),
        'iban': ('', iban(digits(rng, 18))), 'ipaddr': ('', f'192.0.2.{i+1}' if i % 2 else f'2001:db8::{i+1:x}'),
        'swiftbic': ('SWIFT: ', 'TESTGB' + chars(rng, 2).upper() + (chars(rng, 3).upper() if i % 2 else '')),
        'aba_routing': ('', aba('02' + digits(rng, 6))),
        'uk_sortcode': ('sort code: ', f'{i+1:02}-{rng.randrange(100):02}-{rng.randrange(100):02}'),
        'cvv': ('CVV: ', digits(rng, 3)), 'card_expiry': ('expiry ', f'{i % 12+1:02}/{28+i%5}'),
        'payment_token': ('', ['sk_test_', 'pk_test_', 'tok_', 'PAYID-', 'sq0idp-'][i % 5] + chars(rng, 24)),
        'bank_account': ('bank account ', digits(rng, 8)), 'ach_trace': ('ACH trace ', '02100002' + digits(rng, 7)),
        'merchant_id': ('merchant ID ', chars(rng, 15).upper()),
        'btc': ('', bitcoin(bytes(rng.randrange(256) for _ in range(20)))),
        'eth': ('', '0x' + ''.join(rng.choice('0123456789abcdef') for _ in range(40))),
        'github_token': ('', ['ghp_', 'gho_', 'ghu_', 'ghs_'][i % 4] + chars(rng, 36)),
        'slack_token': ('', 'xoxb-' + digits(rng, 12) + '-' + digits(rng, 12) + '-' + chars(rng, 24)),
        'google_api_key': ('', 'AIza' + chars(rng, 35)),
        'private_key_pem': ('', '-----BEGIN ' + ['RSA ', 'EC ', 'OPENSSH ', ''][i % 4] + 'PRIVATE KEY-----'),
    }


def invalids(rng, i):
    pan = luhn('4' + digits(rng, 14))
    national_id = mynumber(digits(rng, 11))
    routing = aba('02' + digits(rng, 6))
    return {
        'pan': 'card-like ' + pan[:-1] + str((int(pan[-1]) + 1) % 10),
        'email': f'user{i}@@example.com', 'phone_jp': '190-' + digits(rng, 4) + '-' + digits(rng, 4),
        'mynumber': national_id[:-1] + str((int(national_id[-1]) + 1) % 10),
        'jwt': 'eyJhbGciOiJIUzI1NiJ9.!invalid.' + chars(rng, 10), 'awskey': 'AKIA' + chars(rng, 15),
        'iban': 'DE00' + digits(rng, 18), 'ipaddr': f'999.0.2.{i+1}',
        'swiftbic': 'TEST00' + chars(rng, 2).upper(),
        'aba_routing': routing[:-1] + str((int(routing[-1]) + 1) % 10),
        'uk_sortcode': f'{i+1:02}-12-34-56', 'cvv': 'CVV: ' + digits(rng, 2), 'card_expiry': f'expiry 13/{28+i%5}',
        'payment_token': 'sk_test_' + chars(rng, 5), 'bank_account': 'bank account ' + digits(rng, 2),
        'ach_trace': 'ACH trace ' + digits(rng, 14), 'merchant_id': 'merchant ID ' + chars(rng, 2),
        'btc': bitcoin(bytes(rng.randrange(256) for _ in range(20)))[:-1] + '0',
        'eth': '0x' + chars(rng, 38) + 'gg', 'github_token': 'ghp_' + chars(rng, 35),
        'slack_token': 'xoxz-' + chars(rng, 24), 'google_api_key': 'AIza' + chars(rng, 34),
        'private_key_pem': ['-----BEGIN PUBLIC KEY-----', '-----BEGIN CERTIFICATE-----'][i % 2],
    }


def surround(prefix, value, mode):
    if mode == "held_plain": return "[payload] " + prefix, value, " [/payload]"
    if mode == "held_log": return "audit: field=(" + prefix, value, "); done"
    if mode == "held_json": return '{"entry": {"value": "' + prefix, value, '"}}'
    if mode == "held_url": return "https://example.invalid/a?entry=" + quote(prefix, safe=""), quote(value, safe="@:-_."), "&ok=true"
    if mode == "held_japanese": return "入力〈" + prefix, value, "〉確認済み"
    if mode == "held_multiline": return "audit\r\nfield: " + prefix, value, "\r\nend"
    if mode == 'plain': return prefix, value, ''
    if mode == 'log': return 'INFO checkout ' + prefix, value, '; result=accepted'
    if mode == 'json': return '{"message":"' + prefix, value, '","result":"accepted"}'
    if mode == 'url': return 'https://example.invalid/?value=' + quote(prefix, safe=''), quote(value, safe='@:-_.'), '&result=accepted'
    if mode == 'japanese': return '処理結果【' + prefix, value, '】を記録しました'
    if mode == 'multiline': return 'request accepted\n' + prefix, value, '\nworker finished'
    raise ValueError(mode)


def generate(held=False):
    rng = random.Random(20270129 if held else SEED)
    samples, controls = [], []
    for i in range(24):
        for kind, (prefix, value) in sorted(specimens(rng, i).items()):
            for mode in ['plain', 'log', 'json', 'url', 'japanese', 'multiline']:
                before, rendered, after = surround(prefix, value, ('held_' if held else '') + mode)
                samples.append(dict(id=f'{kind}/positive/{i}/{mode}', kind=kind, text=before+rendered+after,
                                    expected=[dict(start=len(before.encode()), end=len((before+rendered+(after if kind == "private_key_pem" else "")).encode()))]))
    for i in range(16):
        for kind, value in sorted(invalids(rng, i).items()):
            for mode in ['plain', 'log', 'json', 'japanese']:
                before, rendered, after = surround('', value, ('held_' if held else '') + mode)
                samples.append(dict(id=f'{kind}/negative/{i}/{mode}', kind=kind, text=before+rendered+after, expected=[]))
    for i in range(32):
        raw = f'{"validation" if held else "public"} fixture {i}'.encode()
        hex32 = hashlib.md5(raw, usedforsecurity=False).hexdigest()
        for source, text in [
            ('UUID', f'{hex32[:8]}-{hex32[8:12]}-{hex32[12:16]}-{hex32[16:20]}-{hex32[20:]}'),
            ('git SHA', hashlib.sha1(raw, usedforsecurity=False).hexdigest()),
            ('SHA-256', hashlib.sha256(raw).hexdigest()),
            ('timestamp', f'2026-11-{i%28+1:02}T12:34:56.{i:09}Z'),
            ('order', ('order_number = ' if held else 'Order ID: ') + luhn('4' + digits(rng,14))),
            ('invoice', ('invoice_ref = ' if held else 'Invoice: ') + mynumber(digits(rng,11))),
            ('base64', base64.b64encode(raw).decode()),
            ('version', f'release v{i+1}.26.11 build-20261115'),
            ('phone-shaped serial', f'{"tracking_serial =" if held else "Serial:"} 090-{1000+i:04}-{2000+i:04}'),
            ('invalid phone prefix', f'Serial: 190-{1000+i:04}-{2000+i:04}'),
            ('base64 without JWT header', 'e30.e30.' + base64.urlsafe_b64encode(raw).decode().rstrip('=')),
        ]: controls.append(dict(id=f'control/{source}/{i}', source=source, text=text))
    for i in range(32):
        account = mynumber(f'{12345678000+i:011}')
        for source, text in [
            ('ARN account', f'arn:aws:iam::{account}:role/fixture'),
            ('Swift build', ['swift package resolved', 'swift package RESOLVED', 'swift dependencies resolved'][i%3]),
            ('SSH remote', f'git clone git@code{i}.example.org:org/repo.git'),
            ('IP-like version', f'{["version", "v", "ver", "build", "release"][i%5]} 10.2.3.{i+1}'),
        ]:
            controls.append(dict(id=f'control/{source}/{i}', source=source, text=text))
    # Keep synthetic credential prefixes split in source, as in accuracy.json,
    # so hosting push protection does not mistake offline fixtures for live keys.
    credential_kinds = {'awskey', 'jwt', 'payment_token', 'github_token', 'slack_token', 'google_api_key', 'private_key_pem'}
    for row in samples:
        if row['kind'] in credential_kinds and row['expected']:
            text = row.pop('text')
            start = row['expected'][0]['start'] if row['expected'] else 0
            raw = text.encode()
            # Prefixes are ASCII; start is an original-byte boundary.
            row['parts'] = [raw[:start+2].decode(), raw[start+2:].decode()]
    return samples, controls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    for held in (False, True):
        for name, rows in zip(['accuracy_generated.jsonl', 'accuracy_generated_controls.jsonl'], generate(held)):
            if held: name = name.replace('accuracy_', 'accuracy_held_')
            data = ''.join(json.dumps(row, ensure_ascii=False, separators=(',', ':'))+'\n' for row in rows)
            path = ROOT / 'tests/testdata' / name
            if args.check:
                if path.read_text(encoding='utf-8') != data: raise SystemExit(f'{name} is stale')
            else: path.write_text(data, encoding='utf-8', newline='\n')


if __name__ == '__main__':
    main()
