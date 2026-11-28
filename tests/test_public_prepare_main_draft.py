from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from prepare_main_draft import (  # noqa: E402
    Hold, OPEN_MAIN, OWNER_ID, REPO, REPO_ID, create_once, fingerprint, plan_draft,
    staging_notification,
)
from prepare_staging_draft import JENKINS_CONTEXT, JENKINS_ISSUER  # noqa: E402


class MainDraftTests(unittest.TestCase):
    def setUp(self):
        self.staging, self.parent, self.head, self.main, self.tree, self.old_tree = [
            value * 40 for value in 'abcdef'
        ]
        self.repo = {'id': REPO_ID, 'full_name': REPO}
        self.merged_at = '2026-11-23T18:01:00Z'
        self.statuses = f'commits/{self.head}/statuses?per_page=100'
        self.associations = f'commits/{self.staging}/pulls?per_page=100'
        self.integrated = f'git/commits/{self.staging}'
        self.data = {
            'git/ref/heads/staging': dict(object=dict(sha=self.staging)),
            'git/ref/heads/main': dict(object=dict(sha=self.main)),
            self.associations: [dict(number=27, merge_commit_sha=self.staging,
                                     base=dict(ref='staging'), state='closed', merged_at=self.merged_at)],
            'pulls/27': dict(number=27, merged=True, state='closed', draft=False,
                             merged_at=self.merged_at, merge_commit_sha=self.staging,
                             merged_by=dict(id=OWNER_ID),
                             head=dict(ref='development', sha=self.head, repo=self.repo),
                             base=dict(ref='staging', sha=self.parent, repo=self.repo)),
            self.integrated: dict(sha=self.staging, tree=dict(sha=self.tree),
                                  parents=[dict(sha=self.parent)],
                                  verification=dict(verified=True, reason='valid')),
            f'git/commits/{self.head}': dict(tree=dict(sha=self.tree)),
            f'git/commits/{self.parent}': dict(tree=dict(sha=self.old_tree)),
            f'git/commits/{self.main}': dict(tree=dict(sha=self.old_tree)),
            self.statuses: [dict(id=21, context=JENKINS_CONTEXT, state='success',
                                 creator=dict(login=JENKINS_ISSUER), created_at='2026-11-23T18:00:00Z')],
            OPEN_MAIN: [],
        }
        self.posted = []

    def get(self, path):
        return deepcopy(self.data[path])

    def route(self, staging, main):
        self.assertEqual((staging, main), (self.staging, self.main))
        return self.tree

    def post(self, path, body):
        self.posted.append((path, body))
        return dict(number=28, draft=True, head=dict(ref='staging', sha=self.staging, repo=self.repo),
                    base=dict(ref='main', sha=self.main, repo=self.repo))

    def plan(self):
        return plan_draft(self.get, self.staging, self.route)

    def create(self, plan):
        return create_once(self.get, self.post, self.staging, fingerprint(plan), self.route)

    def test_preflight_creates_only_an_exact_staging_to_main_draft(self):
        plan = self.plan()
        self.assertEqual(plan['staging_jenkins_status'], 21)
        self.assertEqual(self.posted, [])
        self.assertEqual(self.create(plan), 28)
        (endpoint, payload), = self.posted
        self.assertEqual((endpoint, payload['head'], payload['base'], payload['draft']),
                         ('pulls', 'staging', 'main', True))

    def test_latest_status_cannot_be_replaced_by_an_older_success(self):
        latest = dict(self.data[self.statuses][0], id=22, state='pending')
        self.data[self.statuses].insert(0, latest)
        with self.assertRaisesRegex(Hold, 'jenkins-missing-trusted-pre-merge-success'):
            self.plan()
        self.assertEqual(self.posted, [])

    def test_recheck_holds_new_main_pr_or_different_candidate(self):
        plan = self.plan()
        self.data[OPEN_MAIN] = [dict(number=31)]
        with self.assertRaisesRegex(Hold, 'main-pr-already-open'):
            self.create(plan)
        self.data[OPEN_MAIN].clear()
        plan['tree'] = '0' * 40
        with self.assertRaisesRegex(Hold, 'main-draft-plan-changed'):
            self.create(plan)
        self.assertEqual(self.posted, [])

    def test_owner_signature_and_reviewed_tree_are_required(self):
        self.data['pulls/27']['merged_by'] = {'id': OWNER_ID + 1}
        with self.assertRaisesRegex(Hold, 'not-an-owner-reviewed-ordinary-staging-squash'):
            self.plan()
        self.data['pulls/27']['merged_by'] = {'id': OWNER_ID}
        self.data[self.integrated]['verification']['verified'] = False
        with self.assertRaisesRegex(Hold, 'staging-squash-not-signed-with-reviewed-tree'):
            self.plan()
        self.data[self.integrated]['verification']['verified'] = True
        self.data[f'git/commits/{self.head}']['tree']['sha'] = self.old_tree
        with self.assertRaisesRegex(Hold, 'staging-squash-not-signed-with-reviewed-tree'):
            self.plan()

    def test_stale_push_rerun_cannot_create_a_draft(self):
        self.data['git/ref/heads/staging']['object']['sha'] = '0' * 40
        with self.assertRaisesRegex(Hold, 'staging-event-is-not-current'):
            self.plan()

    def test_main_must_contain_the_previously_reviewed_staging_tree(self):
        self.data[f'git/commits/{self.main}']['tree']['sha'] = '0' * 40
        with self.assertRaisesRegex(Hold, 'staging-review-does-not-start-from-current-main-tree'):
            self.plan()

    def test_git_simulation_must_produce_the_reviewed_tree(self):
        with self.assertRaisesRegex(Hold, 'ordinary-main-route-tree-mismatch'):
            plan_draft(self.get, self.staging, lambda *_: self.old_tree)

    def test_only_same_repository_staging_push_metadata_is_accepted(self):
        run = dict(event='push', conclusion='success', head_branch='staging',
                   head_repository=self.repo, head_sha=self.staging)
        self.assertEqual(staging_notification({'workflow_run': run}), self.staging)
        for field, value in (('event', 'pull_request'), ('head_branch', 'development'),
                             ('head_repository', {'id': 1, 'full_name': REPO})):
            with self.subTest(field=field), self.assertRaisesRegex(Hold, 'ignored-staging-notification'):
                staging_notification({'workflow_run': dict(run, **{field: value})})


if __name__ == '__main__':
    unittest.main()
