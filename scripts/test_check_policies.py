"""Policy failures are exercised without editing the active checkout."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_policies as policies
import fuzz_targets


class PolicyTests(unittest.TestCase):
    def test_test_file_budget_rejects_extra_files(self):
        for extra in ('scan_contract_test.go', 'scan_linux_test.go',
                      'adapters/logger/secret_test.go', 'tests/accuracy_extra_test.go',
                      'tests/cmd/tool/scores_test.go'):
            with self.subTest(extra=extra):
                files = ['scan.go', 'scan_test.go', 'adapters/logger/adapter.go',
                         'tests/doc.go', 'tests/cmd/tool/main.go', extra]
                with self.assertRaisesRegex(ValueError, 'test file budget'):
                    policies.test_file_budget(files)

    def test_test_file_budget_accepts_source_files_and_subjects(self):
        policies.test_file_budget(['scan.go', 'scan_test.go', 'doc.go', 'doc_test.go',
                                  'example_test.go', 'fuzz_test.go', 'benchmark_test.go',
                                  'adapters/logger/adapter.go', 'adapters/logger/adapter_test.go',
                                  'tests/doc.go', 'tests/accuracy_test.go', 'tests/quality_gates_test.go',
                                  'tests/contracts/policy_test.go', 'tests/cmd/tool/main.go',
                                  'tests/cmd/tool/main_test.go'])

    def test_repository_traces_reject_development_labels(self):
        labels = ['Rou'+'nd 99', 'rou'+'nd-99', 'rou'+'nd99', 'rou'+'nds 98 and 99',
                  'R'+'98-01', 'ADR'+'-42', 'PR'+' A']
        for label in labels:
            with self.subTest(label=label):
                for files in ({'doc/current.md': label}, {label+'.md': 'current behavior'}):
                    with self.assertRaisesRegex(ValueError, 'development trace'):
                        policies.repository_traces(files)

    def test_repository_traces_keep_provenance_and_changelog(self):
        policies.repository_traces({'CHANGELOG.md': 'Rou'+'nd 99',
                                    'doc/source.md': 'https://github.com/logpai/loghub/commit/'+'a'*40,
                                    'scanner_test.go': 'TestRoundTrip; protocol R2; port 443'})

    def test_documented_inventory_and_coverage_reject_drift(self):
        for text in ('<!-- packages:start -->\n<!-- packages:end -->\nCoverage: 97%',
                     '<!-- packages:start -->\n'+('- `example.com/module`\n'*7)+'<!-- packages:end -->\nCoverage: 80%'):
            with patch.object(policies.subprocess, 'check_output', return_value='example.com/module\n'), patch.object(policies, 'read', side_effect=lambda path: {'CLAUDE.md': '@AGENTS.md\n', '.octocov.yml': 'acceptable: 97%'}.get(path, text)):
                with self.assertRaises(ValueError):
                    policies.documentation_contract()

    def test_shared_agent_guide_is_the_documentation_source(self):
        text = '<!-- packages:start -->\n' + '- `example.com/module`\n'*7 + '<!-- packages:end -->\nCoverage: 97%'
        files = {'AGENTS.md': text, 'CLAUDE.md': '@AGENTS.md\n', '.octocov.yml': 'acceptable: 97%'}
        with patch.object(policies.subprocess, 'check_output', return_value='example.com/module\n'), patch.object(policies, 'read', side_effect=files.__getitem__):
            policies.documentation_contract()
            files['CLAUDE.md'] = 'a separate guide'
            with self.assertRaisesRegex(ValueError, 'shared agent guide'):
                policies.documentation_contract()

    def test_cohesion_rejects_scattered_owners(self):
        bad = {'internal/detect/pan.go': "func isDigit(b byte) bool { return b >= '0' && b <= '9' }",
               'scanner.go': 'if c, ok := d.(*detect.Credential); ok {}',
               'internal/detect/two.go': 'func (d *A) Scan(data []byte) []Finding {}\nfunc (d *B) Scan(data []byte) []Finding {}',
               'internal/detect/fullwidth.go': 'func composePositions(child, parent []int) []int {}'}
        for name, text in bad.items():
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, 'cohesion'):
                    policies.cohesion({name: text})

    def test_cohesion_accepts_owners_and_tests(self):
        policies.cohesion({'internal/ascii/ascii.go': "func IsDigit(b byte) bool { return b >= '0' && b <= '9' }",
                           'internal/detect/view.go': 'func composePositions(child, parent []int) []int {}',
                           'internal/detect/pan.go': 'func (d *PAN) Scan(data []byte) []Finding {}',
                           'internal/detect/pan_test.go': "b >= '0' && b <= '9'",
                           'tests/oracle.go': "b >= 'a' && b <= 'z'"})

    def test_root_dependencies(self):
        for manifest in ({'Require':[{'Path':'example.com/runtime'}]}, {'Tool':['example.com/tool']}):
            with patch.object(policies.subprocess, 'check_output', return_value=json.dumps(manifest)):
                with self.assertRaises(ValueError):
                    policies.root_module()

    def test_missing_technique(self):
        row = dict(name='fake', bug='real bug', ci='verification:policies', paths=['does-not-exist.go'])
        with patch.object(policies, 'read', return_value=json.dumps([row])):
            with self.assertRaisesRegex(ValueError, 'path missing'):
                policies.linked_tests()

    def test_rule_without_check(self):
        row = dict(rule='Owner rule', source='CLAUDE', check='missing.py#test', where='Verification')
        real_read = policies.read
        def read(path):
            return json.dumps([row]) if path == 'scripts/policies.json' else real_read(path)
        with patch.object(policies, 'read', side_effect=read):
            with self.assertRaises((ValueError, FileNotFoundError)):
                policies.mapping()

    def test_fuzz_discovery_excludes_nested_modules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'x_test.go').write_text('func FuzzRoot(f *testing.F) {}\n')
            nested = root/'nested'; nested.mkdir()
            (nested/'go.mod').write_text('module example.com/nested\n')
            (nested/'x_test.go').write_text('func FuzzNested(f *testing.F) {}\n')
            self.assertEqual(fuzz_targets.targets(root), [{'pkg':'.', 'name':'FuzzRoot'}])

    def test_detector_documentation_commands_cannot_disappear(self):
        commands = ['go -C tests run ./cmd/detectordocs --check',
                    'go -C tests test ./cmd/detectordocs -count=1']
        for retained in commands:
            with self.subTest(retained=retained):
                with patch.object(policies, 'read', return_value=retained):
                    with self.assertRaisesRegex(ValueError, 'detector documentation check missing'):
                        policies.detector_docs()
        policies.detector_docs()

    def test_widened_permissions_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflows = root/'.github/workflows'; workflows.mkdir(parents=True)
            (workflows/'verification.yml').write_text('permissions:\n  contents: write\n')
            with patch.object(policies, 'ROOT', root):
                with self.assertRaisesRegex(ValueError, 'unexpected write permissions'):
                    policies.workflows()


if __name__ == '__main__':
    unittest.main()
