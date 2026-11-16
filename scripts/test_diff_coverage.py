"""Negative controls for diff coverage, missing instrumentation and stale exceptions."""
import hashlib
from pathlib import Path
import tempfile
import unittest

import diff_coverage as coverage


class DiffCoverageTests(unittest.TestCase):
    def test_changed_statement_must_be_covered(self):
        changes = coverage.changed_lines('+++ b/a.go\n@@ -2 +2,2 @@\n-return 0\n+if b {\n+ return 1\n')
        self.assertEqual(changes, {'a.go': {2, 3}})
        blocks = coverage.read_blocks('mode: set\ngithub.com/nao1215/embargo/a.go:2.1,2.5 1 1\ngithub.com/nao1215/embargo/a.go:3.1,3.8 1 0\n')
        with self.assertRaisesRegex(ValueError, 'uncovered'):
            coverage.check(changes, blocks, {'a.go': 'func f() {}'}, {})
        self.assertEqual(coverage.check(changes, blocks, {'a.go': 'func f() {}'}, {'a.go': {3}}), 2)
        with self.assertRaisesRegex(ValueError, 'no instrumented'):
            coverage.check(changes, {}, {'a.go': 'func f() {}'}, {})

    def test_unrelated_uncovered_code_is_not_a_diff_failure(self):
        self.assertEqual(coverage.check({'a.go': {8}}, {'a.go': [(2, 3, 1, 0)]}, {'a.go': 'func f() {}'}, {}), 0)
        self.assertEqual(coverage.check({'tests/a.go': {3}}, {}, {'a.go': 'func f() {}'}, {}), 0)

    def test_exception_is_bound_to_source_and_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'a.go').write_text('return err\n')
            entry = dict(file='a.go', start=1, end=1, reason='standard library defensive error', sha256=hashlib.sha256(b'return err\n').hexdigest())
            self.assertEqual(coverage.exceptions(root, [entry]), {'a.go': {1}})
            (root/'a.go').write_text('return nil\n')
            with self.assertRaisesRegex(ValueError, 'stale'):
                coverage.exceptions(root, [entry])
            entry['file'] = '../a.go'
            with self.assertRaisesRegex(ValueError, 'invalid'):
                coverage.exceptions(root, [entry])

    def test_malformed_input_cannot_pass(self):
        for text in ('', 'mode: other', 'mode: set\ninvalid'):
            with self.assertRaises(ValueError):
                coverage.read_blocks(text)
