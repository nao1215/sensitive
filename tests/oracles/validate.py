"""Independent validation, offline from the unmodified upstream wheel."""
import hashlib
import json
from pathlib import Path
import sys

wheel = Path(__file__).with_name('python_stdnum-2.2-py3-none-any.whl')
if hashlib.sha256(wheel.read_bytes()).hexdigest() != 'bdf98fd117a0ca152e4047aa8ad254bae63853d4e915ddd4e0effb33ba0e9260':
    raise RuntimeError('oracle wheel checksum mismatch')
sys.path.insert(0, str(wheel))
from stdnum import iban, bic, luhn

for case in json.load(sys.stdin):
    kind, value = case['kind'], case['value']
    if kind == 'iban':
        valid = iban.is_valid(value, check_country=False)
    elif kind == 'swiftbic':
        valid = bic.is_valid(value)
    elif kind == 'pan':
        valid = luhn.is_valid(value)
    else:
        raise ValueError('unknown kind')
    print(json.dumps({'kind': kind, 'value': value, 'valid': valid}))
