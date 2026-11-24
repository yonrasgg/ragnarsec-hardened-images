from copy import deepcopy
from pathlib import Path
import sys
import unittest
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from prepare_staging_draft import (
    Correct, Hold, OPEN_DRAFTS, REPO, REPO_ID, create_once, fingerprint, plan_draft,
)


class StagingDraftTests(unittest.TestCase):
    def setUp(self):
        self.fix, self.prior, self.dev, self.staging, self.tree = [c * 40 for c in 'abcde']
        self.name, self.app = 'ansible/validate', 1234
        self.repo = dict(id=REPO_ID, full_name=REPO)
        self.checks = f'commits/{self.fix}/check-runs?' + urlencode(
            dict(check_name=self.name, filter='latest', per_page=100))
        self.data = {
            'pulls/17': dict(number=17, merged=True, state='closed', merge_commit_sha=self.dev,
                             head=dict(sha=self.fix, ref='fix/repair', repo=self.repo),
                             base=dict(ref='development', repo=self.repo),
                             merged_at='2026-11-23T18:01:00Z'),
            'git/ref/heads/development': dict(object=dict(sha=self.dev)),
            'git/ref/heads/staging': dict(object=dict(sha=self.staging)),
            f'commits/{self.dev}': dict(sha=self.dev, parents=[dict(sha=self.prior)], commit=dict(
                tree=dict(sha=self.tree), verification=dict(verified=True, reason='valid'))),
            f'git/commits/{self.fix}': dict(tree=dict(sha=self.tree)),
            f'git/commits/{self.staging}': dict(tree=dict(sha='2' * 40)),
            'rules/branches/development': [dict(type='required_status_checks', parameters=dict(
                strict_required_status_checks_policy=True,
                required_status_checks=[dict(context=self.name, integration_id=self.app)]))],
            self.checks: dict(total_count=1, check_runs=[dict(
                id=29, name=self.name, app=dict(id=self.app), head_sha=self.fix,
                status='completed', conclusion='success', completed_at='2026-11-23T18:00:00Z',
                output=dict(summary=f'pr=17;base={self.prior};head={self.fix}'))]),
            OPEN_DRAFTS: [],
        }
        self.posts = []

    def get(self, key):
        return deepcopy(self.data[key])

    def post(self, path, body):
        self.posts.append((path, body))
        return dict(number=18, draft=True, head=dict(ref='development', sha=self.dev, repo=self.repo),
                    base=dict(ref='staging', sha=self.staging, repo=self.repo))

    def plan(self):
        return plan_draft(self.get, 17, self.name, self.app)

    def create(self, plan):
        return create_once(self.get, self.post, 17, self.name, self.app, fingerprint(plan))

    def test_creates_only_development_to_staging_draft(self):
        plan = self.plan()
        self.assertEqual(self.posts, [])
        self.assertEqual(self.create(plan), 18)
        (path, body), = self.posts
        self.assertEqual((path, body['head'], body['base'], body['draft']),
                         ('pulls', 'development', 'staging', True))
        self.assertIn('A human marks it ready', body['body'])
        self.assertIn('**Squash and merge**', body['body'])

    def test_does_not_create_duplicate_or_touch_existing_review(self):
        plan = self.plan()
        self.data[OPEN_DRAFTS] = [{'number': 25, 'draft': False}]
        with self.assertRaisesRegex(Hold, 'staging-pr-already-open'):
            self.create(plan)
        self.assertFalse(self.posts)

    def test_jenkins_check_cannot_substitute_for_ansible(self):
        gate = self.data['rules/branches/development'][0]['parameters']['required_status_checks'][0]
        gate['context'] = 'continuous-integration/jenkins/pr-head'
        with self.assertRaisesRegex(Hold, 'ansible-not-required-by-github'):
            self.plan()

    def test_failed_returns_to_new_fix_and_pending_does_not(self):
        check = self.data[self.checks]['check_runs'][0]
        check['conclusion'] = 'failure'
        with self.assertRaisesRegex(Correct, 'fix/ansible-retry-pr-17'):
            self.plan()
        check['status'] = 'in_progress'
        with self.assertRaises(Hold):
            self.plan()
        self.assertFalse(self.posts)

    def test_stale_or_wrong_app_and_post_merge_checks_not_accepted(self):
        mutations = (
            ('app', dict(id=self.app + 1)),
            ('head_sha', '2'*40),
            ('completed_at', '2026-11-23T18:02:00Z'),
            ('output', dict(summary=f"pr=17;base={'8'*40};head={self.fix}")),
        )
        for key, val in mutations:
            check = self.data[self.checks]['check_runs'][0]
            with self.subTest(key=key):
                original = check[key]
                check[key] = val
                with self.assertRaises(Hold):
                    self.plan()
                check[key] = original

    def test_ref_moving_after_preflight_blocks_creation(self):
        plan = self.plan()
        changed = '9'*40
        self.data['git/ref/heads/staging']['object']['sha'] = changed
        self.data[f'git/commits/{changed}'] = dict(tree=dict(sha='2'*40))
        with self.assertRaisesRegex(Hold, 'draft-plan-changed'):
            self.create(plan)
        self.assertFalse(self.posts)

    def test_no_draft_before_fix_enters_development(self):
        self.data['pulls/17']['merged'] = False
        with self.assertRaisesRegex(Hold, 'not-an-integrated-fix'):
            self.plan()
        self.assertFalse(self.posts)
