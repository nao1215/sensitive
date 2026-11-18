"""Independent validation, offline from unmodified python-stdnum 2.2 modules.

The modules under stdnum/ are copied byte for byte from the upstream wheel
python_stdnum-2.2-py3-none-any.whl (LGPL-2.1-or-later, see stdnum/COPYING);
each digest below is the one the wheel's RECORD lists for that file.
"""
import base64
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
RECORD = {
    'stdnum/__init__.py': 'WyleLfbiIjJBHSoNEPop1JqY4UJ-VrhWpjeIeIXCOsU',
    'stdnum/bic.py': 'hTlz-aY2e5e3LvNrtu22ZWJm-HF_94hzV_FRzKL180A',
    'stdnum/exceptions.py': 'cVlNlYvhNJKS3NX21VpM2TwBbluK7YcryaRyNMf8P2Q',
    'stdnum/iban.dat': 'JuuBvRvjPTdhMyd7xxcj8rcgtLIFSHXlJyMUmsq1A-Y',
    'stdnum/iban.py': 'eIGRQbR5EEdY74M-88TexaFGvzKpcdRYokMsfu9TMdc',
    'stdnum/luhn.py': 'rIftrj53DRGlCMmhW7TICrs0dyzDBEw0qkyoXmR1lNg',
    'stdnum/numdb.py': 'DCbC_i7h50VYnKLj5wpgEDlTDfuotgD3bHWDKIlWNIE',
    'stdnum/util.py': '2yVmaddIJd2pqRWsIQ63pD5oTcBW1eEQ5LaUNH34QwY',
    'stdnum/iso7064/__init__.py': 'SEyBlYRMp0ONFnKtwZunDJfCMh7mBWMfulnmQDc45AE',
    'stdnum/iso7064/mod_97_10.py': '_9cmQqnhqArfwNE7oQqCcVJWe-DxZrEXzvfaKGpY7Tw',
}
for name, digest in RECORD.items():
    actual = base64.urlsafe_b64encode(hashlib.sha256((HERE/name).read_bytes()).digest()).rstrip(b'=').decode()
    if actual != digest:
        raise RuntimeError('oracle module checksum mismatch: '+name)
sys.path.insert(0, str(HERE))
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
