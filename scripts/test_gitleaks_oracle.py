"""The gitleaks oracle patch and table must not depend on network access."""
import unittest

import gitleaks_oracle


SOURCE = '''package utils

import (
\t"strings"
)

func Validate(rule config.Rule, truePositives []string, falsePositives []string) *config.Rule {
\tr := &rule
\td := createSingleRuleDetector(r)
\tfor _, tp := range truePositives {
\t}
\treturn r
}
'''


class GitleaksOracleTests(unittest.TestCase):
    def test_patch_records_before_validation(self):
        patched = gitleaks_oracle.patch_validate(SOURCE)
        self.assertIn('recordTruePositives(r, truePositives, d)\n\tfor _, tp', patched)
        self.assertIn('"encoding/json"', patched)
        self.assertIn('func recordTruePositives', patched)

    def test_patch_rejects_moved_upstream_code(self):
        with self.assertRaisesRegex(ValueError, 'unexpected gitleaks'):
            gitleaks_oracle.patch_validate('package utils\n')

    def test_table_reports_both_inputs(self):
        summary = {'rules': 4, 'lines': 10, 'masked_lines': 9, 'rules_all_lines': 3, 'secrets': 5, 'masked_bare': 2, 'rules_all_bare': 1}
        rendered = gitleaks_oracle.table(summary)
        self.assertIn('| Generated lines with keys and syntax | 9/10 (90.0%) | 3/4 |', rendered)
        self.assertIn('| Bare secrets without a key | 2/5 (40.0%) | 1/4 |', rendered)


if __name__ == '__main__':
    unittest.main()
