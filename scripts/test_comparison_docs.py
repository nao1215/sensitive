"""Only dependencies used by the measured paths should invalidate timings."""
import pathlib
import tempfile
import unittest
from unittest.mock import patch
import comparison_docs as docs

class FingerprintTests(unittest.TestCase):
    def test_unrelated_dependency_does_not_invalidate_measurements(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root/'tests').mkdir()
            (root/'go.mod').write_text('module example\n')
            module = root/'tests/go.mod'
            module.write_text('module example/tests\nrequire (\n github.com/m-mizutani/masq v0.2.3\n github.com/getsentry/sentry-go v0.40.0\n)\n')
            (root/'tests/go.sum').write_text('old checksum\n')
            with patch.object(docs, 'ROOT', root):
                before = docs.source_hash()
                full_before = docs.full_source_hash()
                module.write_text(module.read_text().replace('v0.40.0','v0.41.0'))
                (root/'tests/go.sum').write_text('new checksum\n')
                self.assertEqual(before, docs.source_hash())
                self.assertNotEqual(full_before, docs.full_source_hash())
                module.write_text(module.read_text().replace('v0.2.3','v0.2.4'))
                self.assertNotEqual(before, docs.source_hash())

if __name__ == '__main__':
    unittest.main()
