"""Negative fixtures keep each prose rule capable of rejecting a regression."""
import unittest

import check_prose as prose


def item(name, text, package='pkg'):
    return dict(name=name, text=text, path='fixture.go', line=1, package=package)


class ProseTests(unittest.TestCase):
    def test_markdown_rules(self):
        cases = {'filler': 'A robust scanner.', 'stock': 'In conclusion, use this.',
                 'emoji': 'Status: \U0001f680', 'bold': 'A **claim**.',
                 'paragraph': 'One source line\ncontinued here.',
                 'table': '| ' + 'x' * 121 + ' |'}
        for rule, text in cases.items():
            with self.subTest(rule=rule):
                self.assertIn(rule, [x['rule'] for x in prose.markdown('fixture.md', text)])

    def test_prose_scope(self):
        self.assertEqual(prose.markdown('fixture.md', '```go\n// simply a code fixture\n```\n\nOne line.\n\nAnother line.'), [])
        self.assertEqual(prose.markdown('fixture.md', '| [short](https://example.com/' + 'x'*140 + ') |'), [])

    def test_godoc_rules(self):
        for rule, value in [('missing-godoc', ''), ('restatement', 'NewEmail creates a new Email detector.'),
                            ('benchmark-list', 'NewEmail scans in 0.097/14.70/17.40 µs.')]:
            self.assertIn(rule, [x['rule'] for x in prose.godoc([item('NewEmail', value)])])
        repeated = 'This sentence describes the same benchmark cost with enough detail to exceed the duplication threshold.'
        values = [item('Name'+str(i), 'Name'+str(i)+' creates a new value. '+repeated) for i in range(8)]
        self.assertEqual({x['rule'] for x in prose.godoc(values)}, {'template', 'repeated-sentence'})
        self.assertEqual(prose.godoc([item('Example', 'Example explains the event.'), item('Scan', 'Scan returns findings with original byte offsets.')]), [])

    def test_expanded_abbreviation_is_still_restatement(self):
        values = [item('NewBTC', 'NewBTC creates a new Bitcoin address detect.')]
        self.assertIn('restatement', [x['rule'] for x in prose.godoc(values)])


class KindContractProseTests(unittest.TestCase):
    def test_kind_contract_requires_validation_score_and_default(self):
        for text in ['', 'KindPAN selects cards.',
                     'KindPAN finds digits; length checks give 0.6.',
                     'KindPAN finds digits; checks the length (NewScanner default: on).',
                     'KindPAN finds digits; reports 0.6 (NewScanner default: on).']:
            value = item('KindPAN', text)
            value['path'] = 'finding.go'
            self.assertIn('kind-contract', [x['rule'] for x in prose.godoc([value])])
        value = item('KindPAN', 'KindPAN finds digits; length checks give 0.6 (NewScanner default: on).')
        value['path'] = 'finding.go'
        self.assertNotIn('kind-contract', [x['rule'] for x in prose.godoc([value])])


if __name__ == '__main__':
    unittest.main()
