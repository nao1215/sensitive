import unittest
from require_tag_checks import verdict

OWN = 7


def run(name, status='completed', conclusion='success', suite=1):
    return {'name': name, 'status': status, 'conclusion': conclusion, 'suite': suite}


class VerdictTest(unittest.TestCase):
    def test_passing_skipped_and_neutral_checks_pass(self):
        runs = [run('Unit test'), run('Coverage', conclusion='skipped'), run('Lint', conclusion='neutral'),
                run('Release', 'in_progress', None, OWN), run('SLSA provenance', 'queued', None, OWN)]
        self.assertEqual(verdict(runs, OWN), 'pass')

    def test_a_failed_or_cancelled_check_fails(self):
        self.assertEqual(verdict([run('Unit test', conclusion='failure'), run('Coverage')], OWN), 'failed: Unit test')
        self.assertTrue(verdict([run('Unit test', conclusion='cancelled')], OWN).startswith('failed'))

    def test_running_or_missing_checks_wait(self):
        self.assertEqual(verdict([run('Unit test', 'in_progress', None)], OWN), 'wait')
        self.assertEqual(verdict([run('Release', 'in_progress', None, OWN)], OWN), 'wait')
        self.assertEqual(verdict([], OWN), 'wait')


if __name__ == '__main__':
    unittest.main()
