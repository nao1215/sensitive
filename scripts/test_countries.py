"""Keep the pre-implementation fixture freeze and independent checksum definitions reproducible."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
import unittest

import country_reference as reference
import generate_countries
import country_docs


class CountryTests(unittest.TestCase):
    def test_frozen_corpus_still_matches_definition(self):
        generate_countries.generate(generate_countries.ROOT/'tests/testdata',check=True)
        freeze=json.loads((generate_countries.ROOT/'tests/testdata/countries-freeze.json').read_text())
        self.assertFalse(freeze['implementation_started'])
        for name,digest in freeze['files'].items():
            folder='scripts' if name.endswith('.py') else 'tests/testdata'
            self.assertEqual(hashlib.sha256((generate_countries.ROOT/folder/name).read_bytes()).hexdigest(),digest)

    def test_documented_results_match_snapshots(self):
        country_docs.generate(check=True)

    def test_published_checksum_examples(self):
        self.assertEqual(reference.cpf_digits('280012389'),'38')
        self.assertEqual(reference.cnpj_digits('12ABC34501DE'),'35')
        self.assertEqual(reference.china_digit('11010519491231002'),'X')
        self.assertTrue(reference.verhoeff_valid('2363'))
        self.assertFalse(reference.verhoeff_valid('2364'))
        self.assertEqual(reference.nhs_digit('943476591'),9)

    def test_structure_boundaries(self):
        for value in ('000123456','666123456','900123456','123004567','123450000'):
            self.assertFalse(reference.valid('us_ssn',value))
        for group in range(100):
            expected=50<=group<=65 or 70<=group<=88 or 90<=group<=92 or 94<=group<=99
            self.assertEqual(reference.valid('us_itin',f'912{group:02}1234'),expected)
        for prefix in ('BG','GB','KN','NK','NT','TN','ZZ','AO','DA','AI'):
            self.assertFalse(reference.valid('uk_nino',prefix+'123456A'))

    def test_country_docs_under_ascii_locale(self):
        env=dict(os.environ, LC_ALL='C', PYTHONUTF8='0', PYTHONCOERCECLOCALE='0')
        subprocess.run([sys.executable, '-X', 'utf8=0', str(country_docs.ROOT/'scripts/country_docs.py'), '--check'], env=env, check=True, capture_output=True)
