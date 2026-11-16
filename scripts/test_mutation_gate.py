"""Mutation infrastructure and package floors must fail closed."""
import unittest
import json
from pathlib import Path
import tempfile
from unittest.mock import patch
import mutation_gate as gate


class MutationGateTests(unittest.TestCase):
    def test_project_publication_excludes_calibration_and_requires_completion(self):
        control = 'Mutation testing completed\nKilled: 2, Lived: 1, Not covered: 0\nTimed out: 0, Not viable: 0, Skipped: 0\nTest efficacy: 66.67%\nMutator coverage: 100.00%\n'
        self.assertEqual(gate.measurement_from_log(control)['mutation']['killed'], 2)
        log = 'EMBARGO_MUTATION_START\n'+control
        with self.assertRaises(ValueError):
            gate.measurement_from_log(log)
        summary = 'EMBARGO_MUTATION_SUMMARY '+json.dumps({'packages': {'a': {'counts': {'KILLED': 9, 'LIVED': 1, 'TIMED OUT': 1, 'NOT COVERED': 1}}, 'b': {'counts': {'KILLED': 10}}}})+'\n'
        measured = gate.measurement_from_log(log+summary)
        self.assertEqual(measured['mutation']['killed'], 19)
        self.assertEqual(measured['mutation']['timed_out'], 1)
        self.assertEqual(measured['efficacy'], 95)
        with self.assertRaises(ValueError):
            gate.measurement_from_log(log+summary+summary)

    def test_timeout_is_not_a_kill(self):
        report = {'files': [{'file_name': 'embargotest/run.go', 'mutations': [{'status': value} for value in ['KILLED', 'LIVED', 'TIMED OUT', 'NOT COVERED', 'NOT VIABLE']]}]}
        got = gate.package_scores(report)['embargotest']
        self.assertEqual(got['score'], 33.33)
        self.assertEqual(got['coverage'], 75)
        self.assertEqual(gate.package_scores(report, 'command')['command'], got)

    def test_each_package_and_metric_must_remain_above_baseline(self):
        baseline = {'a': {'score': 90, 'coverage': 95}, 'b': {'score': 60, 'coverage': 80}}
        gate.check(baseline, baseline)
        for actual in ({'a': baseline['a']}, dict(baseline, a={'score': 89, 'coverage': 100}), dict(baseline, b={'score': 100, 'coverage': 79})):
            with self.assertRaises(ValueError):
                gate.check(actual, baseline)

    def test_missing_or_unexecuted_results_cannot_pass(self):
        for report in ({'files': []}, {'files': [{'file_name': 'a.go', 'mutations': [{'status': 'NOT COVERED'}]}]}, {'files': [{'file_name': 'a.go', 'mutations': [{'status': 'RUNNING'}]}]}, {'files': [{'file_name': '../a.go', 'mutations': []}]}):
            with self.assertRaises(ValueError):
                gate.package_scores(report)

    def test_truncated_and_duplicate_mutation_inventories_are_rejected(self):
        mutant = {'type': 'CONDITIONALS_BOUNDARY', 'line': 2, 'column': 10, 'status': 'KILLED'}
        report = {'files': [{'file_name': 'a.go', 'mutations': [mutant]}]}
        gate.validate_inventory(report, report)
        for changed in ({'files': []}, {'files': [{'file_name': 'a.go', 'mutations': []}]}, {'files': report['files']*2}, {'files': [{'file_name': 'a.go', 'mutations': [dict(mutant, line=3)]}]}):
            with self.assertRaises(ValueError):
                gate.validate_inventory(changed, report)

    def test_recorded_scores_cannot_diverge_from_expression_results(self):
        evidence = {'tool': gate.TOOL, 'files': [{'file_name': 'a.go', 'mutations': [{'type': 'CONDITIONALS_BOUNDARY', 'line': 2, 'column': 10, 'status': 'KILLED'}]}], 'source_sha256': {'a.go': 'a'*64}}
        baseline = {'packages': gate.package_scores(evidence)}
        with tempfile.TemporaryDirectory() as directory:
            baseline_path, evidence_path = Path(directory)/'baseline.json', Path(directory)/'evidence.json'
            baseline_path.write_text(json.dumps(baseline), encoding='utf-8')
            evidence_path.write_text(json.dumps(evidence), encoding='utf-8')
            document_path = Path(directory)/'testing.md'
            document_path.write_text('<!-- mutation-baseline:start -->\n'+gate.mutation_table(baseline['packages'])+'<!-- mutation-baseline:end -->\n', encoding='utf-8')
            with patch.object(gate, 'BASELINE', baseline_path), patch.object(gate, 'EVIDENCE', evidence_path), patch.object(gate, 'DOCUMENT', document_path):
                gate.check_recorded_evidence()
                evidence['files'][0]['mutations'][0]['status'] = 'LIVED'
                evidence_path.write_text(json.dumps(evidence), encoding='utf-8')
                with self.assertRaises(ValueError):
                    gate.check_recorded_evidence()

    def test_document_baseline_rejects_missing_and_stale_rows(self):
        packages = {'a': {'score': 80, 'coverage': 90, 'counts': {'KILLED': 4, 'LIVED': 1}}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'testing.md'
            with patch.object(gate, 'DOCUMENT', path):
                for text in ('', '<!-- mutation-baseline:start -->\n<!-- mutation-baseline:end -->\n'):
                    path.write_text(text, encoding='utf-8')
                    with self.assertRaises(ValueError):
                        gate.document_baseline(packages)
                gate.document_baseline(packages, write=True)
                gate.document_baseline(packages)
