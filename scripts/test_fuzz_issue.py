"""Exercise scheduled fuzz issue ownership, evidence and recovery transitions."""
import unittest
from unittest.mock import patch

import fuzz_issue


class FuzzIssueTests(unittest.TestCase):
    def setUp(self):
        self.env = dict(GITHUB_REPOSITORY='nao1215/embargo', GITHUB_EVENT_NAME='schedule',
                        GITHUB_REF='refs/heads/main', GITHUB_RUN_ID='123',
                        GITHUB_RUN_NUMBER='5', GITHUB_RUN_ATTEMPT='1',
                        TARGET_RESULT='success', FUZZ_RESULT='failure')
        self.jobs = [dict(name='FuzzExample (.)', conclusion='failure', html_url='https://example.com/job')]
        self.artifacts = [dict(name='fuzz-crashers-FuzzExample-0', id=456)]

    def owned(self, state='open', run='4/1'):
        return dict(number=7, state=state, user={'login': 'github-actions[bot]'},
                    body=f'{fuzz_issue.MARKER}\n<!-- fuzz-run: {run} -->')

    def update(self, issues=()):
        return fuzz_issue.issue_update(self.env, self.jobs, self.artifacts, issues)

    def test_failure_creates_one_issue_with_evidence(self):
        path, method, body = self.update()
        self.assertEqual((path, method), ('issues', 'POST'))
        self.assertIn('FuzzExample', body['body'])
        self.assertIn('/actions/runs/123)', body['body'])
        self.assertIn('/actions/runs/123/artifacts/456)', body['body'])
        self.assertNotIn('state', body)

    def test_failure_updates_or_reopens_owned_issue(self):
        for state in ('open', 'closed'):
            with self.subTest(state=state):
                path, method, body = self.update([self.owned(state)])
                self.assertEqual((path, method, body['state']), ('issues/7', 'PATCH', 'open'))

    def test_green_closes_existing_issue_and_records_latest_run(self):
        self.env['FUZZ_RESULT'] = 'success'
        path, method, body = self.update([self.owned()])
        self.assertEqual((path, method, body['state']), ('issues/7', 'PATCH', 'closed'))
        self.assertEqual(body['state_reason'], 'completed')
        self.assertIsNone(self.update())
        closed = self.update([self.owned('closed')])[2]
        self.assertEqual(closed['state'], 'closed')
        self.assertIn('<!-- fuzz-run: 5/1 -->', closed['body'])

    def test_green_manual_run_closes_the_scheduled_failure(self):
        self.env.update(GITHUB_EVENT_NAME='workflow_dispatch', FUZZ_RESULT='success')
        self.assertEqual(self.update([self.owned()])[2]['state'], 'closed')

    def test_human_issues_and_pull_requests_are_never_modified(self):
        human = self.owned()
        human['user']['login'] = 'maintainer'
        pr = dict(self.owned(), pull_request={})
        unrelated = dict(self.owned(), body='An unrelated bot issue')
        self.assertEqual(self.update([human, pr, unrelated])[1], 'POST')

    def test_canceled_skipped_manual_and_foreign_runs_do_nothing(self):
        for key, value in [('FUZZ_RESULT', 'cancelled'), ('FUZZ_RESULT', 'skipped'),
                           ('GITHUB_EVENT_NAME', 'workflow_dispatch'),
                           ('GITHUB_REF', 'refs/heads/topic'),
                           ('GITHUB_REPOSITORY', 'another/project')]:
            with self.subTest(key=key, value=value):
                env = dict(self.env, **{key: value})
                self.assertIsNone(fuzz_issue.issue_update(env, self.jobs, self.artifacts, [self.owned()]))

    def test_stale_runs_and_attempts_do_not_overwrite_newer_results(self):
        for run in ('6/1', '5/2'):
            self.assertIsNone(self.update([self.owned(run=run)]))
        self.env['GITHUB_RUN_ATTEMPT'] = '2'
        self.env['FUZZ_RESULT'] = 'success'
        self.assertEqual(self.update([self.owned(run='5/1')])[2]['state'], 'closed')

    def test_discovery_failure_without_crasher_is_visible(self):
        self.env.update(TARGET_RESULT='failure', FUZZ_RESULT='skipped')
        self.jobs = [dict(name='targets', conclusion='failure', html_url='https://example.com/job')]
        self.artifacts = []
        body = self.update()[2]['body']
        self.assertIn('Target discovery', body)
        self.assertIn('No crasher artifact was uploaded', body)

    def test_missing_failure_evidence_and_duplicate_ownership_fail(self):
        with self.assertRaises(RuntimeError):
            self.update([self.owned(), dict(self.owned(), number=8)])
        self.jobs = []
        with self.assertRaises(RuntimeError):
            self.update()

    def test_pagination_keeps_late_artifacts(self):
        with patch.object(fuzz_issue, 'api', side_effect=[{'artifacts': list(range(100))}, {'artifacts': [100]}]) as api:
            self.assertEqual(fuzz_issue.pages('actions/runs/123/artifacts', 'artifacts'), list(range(101)))
        self.assertIn('page=2', api.call_args.args[0])


if __name__ == '__main__':
    unittest.main()
