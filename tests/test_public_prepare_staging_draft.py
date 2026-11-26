from copy import deepcopy
from pathlib import Path
import sys
import unittest
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from ansible_receipt_gate import reviewed_tree_sha
from prepare_staging_draft import (
    Correct, Hold, OPEN_DRAFTS, REPO, REPO_ID, create_once, fingerprint, plan_draft,
)


class StagingDraftTests(unittest.TestCase):
    def setUp(self):
        self.fix, self.prior, self.dev, self.staging, self.tree = [c * 40 for c in 'abcde']
        self.name, self.app = 'ansible/validate', 5929884
        self.receipt_sha = 'f' * 64
        self.receipt_ref = ('40-Evidence/Audits/change-validation/heimdall/'
                            'run-ansible-syntax-15ab3d14/receipt.json')
        self.tree_entries = [
            {'path': 'README.md', 'mode': '100644', 'type': 'blob', 'sha': 'a' * 40},
            {'path': 'receipts', 'mode': '40000', 'type': 'tree', 'sha': 'b' * 40},
        ]
        self.reviewed_tree = reviewed_tree_sha(self.tree_entries)
        self.receipt_text = '\n'.join((
            'Tree-bound Ansible validation receipt verified.',
            f'receipt_ref={self.receipt_ref}',
            f'receipt_sha256={self.receipt_sha}',
            f'target_tree_sha={self.reviewed_tree}',
            f'head_tree_sha={self.tree}',
            'verification_time=2026-11-26T00:00:00Z',
            'result=pass',
        ))
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
            f'git/trees/{self.tree}': dict(tree=self.tree_entries, truncated=False),
            'rules/branches/development': [dict(type='required_status_checks', parameters=dict(
                strict_required_status_checks_policy=True,
                required_status_checks=[dict(context=self.name, integration_id=self.app)]))],
            self.checks: dict(total_count=1, check_runs=[dict(
                id=29, name=self.name, app=dict(id=self.app), head_sha=self.fix,
                status='completed', conclusion='success', completed_at='2026-11-23T18:00:00Z',
                external_id=self.receipt_sha,
                output=dict(summary=f'pr=17;base={self.prior};head={self.fix}',
                            text=self.receipt_text))]),
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

    def test_required_check_with_another_app_id_is_rejected(self):
        gate = self.data['rules/branches/development'][0]['parameters']['required_status_checks'][0]
        gate['integration_id'] = self.app + 1
        with self.assertRaisesRegex(Hold, 'ansible-not-required-by-github'):
            self.plan()

    def test_check_run_with_wrong_summary_is_rejected(self):
        check = self.data[self.checks]['check_runs'][0]
        check['output']['summary'] = f'pr=17;base={self.prior};head={"2" * 40}'
        with self.assertRaisesRegex(Hold, 'ansible-check-not-bound-to-the-integrated-fix'):
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

    def test_missing_receipt_reference_holds_the_draft(self):
        check = self.data[self.checks]['check_runs'][0]
        for key in ('external_id',):
            original = check.pop(key)
            try:
                with self.subTest(key=key):
                    with self.assertRaisesRegex(Hold, 'ansible-receipt-not-bound'):
                        self.plan()
            finally:
                check[key] = original
        original = check['output'].pop('text')
        try:
            with self.assertRaisesRegex(Hold, 'ansible-receipt-not-bound'):
                self.plan()
        finally:
            check['output']['text'] = original
        self.assertFalse(self.posts)

    def test_invalid_receipt_hash_or_unallowlisted_ref_holds_the_draft(self):
        check = self.data[self.checks]['check_runs'][0]
        mutations = (
            ('external_id', 'not-a-sha256'),
            ('external_id', 'e' * 64),
            ('text', self.receipt_text.replace(self.receipt_ref,
                'tmp/leaked/' + self.receipt_ref.split('/')[-1])),
        )
        for key, value in mutations:
            original = check['external_id'] if key == 'external_id' else check['output']['text']
            with self.subTest(key=key, value=value[:24]):
                if key == 'external_id':
                    check['external_id'] = value
                else:
                    check['output']['text'] = value
                with self.assertRaisesRegex(Hold, 'ansible-receipt-not-bound'):
                    self.plan()
                if key == 'external_id':
                    check['external_id'] = original
                else:
                    check['output']['text'] = original
        self.assertFalse(self.posts)

    def test_stale_or_tree_mismatched_receipt_holds_the_draft(self):
        check = self.data[self.checks]['check_runs'][0]
        stale_tree = '2' * 40
        variants = (
            self.receipt_text.replace(f'target_tree_sha={self.reviewed_tree}',
                                      f'target_tree_sha={stale_tree}'),
            self.receipt_text.replace(f'head_tree_sha={self.tree}',
                                      f'head_tree_sha={stale_tree}'),
            self.receipt_text.replace(f'receipt_sha256={self.receipt_sha}',
                                      f'receipt_sha256={"9" * 64}'),
        )
        for text in variants:
            original = check['output']['text']
            with self.subTest(text=text[:60]):
                check['output']['text'] = text
                with self.assertRaisesRegex(Hold, 'ansible-receipt-not-bound'):
                    self.plan()
                check['output']['text'] = original
        self.assertFalse(self.posts)

    def test_no_draft_before_fix_enters_development(self):
        self.data['pulls/17']['merged'] = False
        with self.assertRaisesRegex(Hold, 'not-an-integrated-fix'):
            self.plan()
        self.assertFalse(self.posts)
