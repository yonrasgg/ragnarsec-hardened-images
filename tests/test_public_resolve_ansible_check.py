from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from prepare_staging_draft import Hold, REPO, REPO_ID
from resolve_ansible_check import resolve


class ResolveAnsibleCheckTests(unittest.TestCase):
    def setUp(self):
        self.head, self.base = '1' * 40, '2' * 40
        repo = {'id': REPO_ID, 'full_name': REPO}
        self.run = dict(event='pull_request', status='completed', workflow_id=35,
                        head_sha=self.head, head_repository=repo, pull_requests=[{'number': 27}])
        self.event = {'action': 'completed', 'repository': repo, 'workflow_run': self.run}
        self.pr = dict(number=27, state='open',
                       head=dict(ref='fix/approved-candidate', sha=self.head, repo=repo),
                       base=dict(ref='development', sha=self.base, repo=repo))
        self.api = {
            'actions/workflows/promotion-route-preflight.yml': {'id': 35},
            'pulls/27': self.pr,
            f'commits/{self.head}/pulls?per_page=100': [self.pr],
            'git/ref/heads/development': {'object': {'sha': self.base}},
        }
        self.expected = {'head_sha': self.head, 'base_sha': self.base, 'pr_number': 27}

    def test_resolves_current_pr_using_only_github_metadata(self):
        self.run['conclusion'] = 'failure'
        self.run['outputs'] = {'pr_number': 99}
        self.assertEqual(resolve(self.event, self.api.__getitem__), self.expected)

    def test_resolves_missing_event_pr_but_refuses_ambiguous_lookup(self):
        self.run['pull_requests'] = []
        self.assertEqual(resolve(self.event, self.api.__getitem__), self.expected)
        duplicate = dict(self.pr, number=28)
        self.api[f'commits/{self.head}/pulls?per_page=100'].append(duplicate)
        with self.assertRaisesRegex(Hold, 'ambiguous-check-pr'):
            resolve(self.event, self.api.__getitem__)

    def test_fails_closed_for_discrepant_live_bindings(self):
        cases = (
            ('workflow', self.run, 'workflow_id', 99, 'unexpected-trigger-workflow'),
            ('fork', self.pr['head'], 'repo', {'id': 99}, 'not-the-current-development-candidate'),
            ('head', self.pr['head'], 'sha', '3' * 40, 'not-the-current-development-candidate'),
            ('base', self.pr['base'], 'sha', '3' * 40, 'check-pr-base-moved'),
            ('target', self.pr['base'], 'ref', 'staging', 'not-the-current-development-candidate'),
        )
        for name, record, field, value, reason in cases:
            with self.subTest(name=name):
                original = record[field]
                try:
                    record[field] = value
                    with self.assertRaisesRegex(Hold, reason):
                        resolve(self.event, self.api.__getitem__)
                finally:
                    record[field] = original
