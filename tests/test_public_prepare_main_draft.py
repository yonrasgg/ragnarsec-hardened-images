from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from prepare_main_draft import (  # noqa: E402
    ACTIONS_APP_ID, ACTIONS_CHECK, ACTIONS_WORKFLOW, ANSIBLE_APP_ID, ANSIBLE_CHECK,
    Hold, MainRouteHold, OPEN_MAIN, OWNER_ID, REPO, REPO_ID, SYNC_TRAILER,
    create_once, fingerprint, ordinary_route, plan_draft, staging_notification,
)
from ansible_receipt_gate import GIT_TREE_SCHEMA, git_tree_sha, reviewed_tree_sha  # noqa: E402
from prepare_staging_draft import JENKINS_CONTEXT, JENKINS_ISSUER  # noqa: E402


class MainDraftTests(unittest.TestCase):
    def setUp(self):
        self.staging, self.parent, self.head, self.main, self.tree, self.old_tree = [
            value * 40 for value in 'abcdef'
        ]
        self.repo = {'id': REPO_ID, 'full_name': REPO}
        self.tree_entries = [dict(path='app.py', mode='100644', type='blob', sha='8' * 40),
                             dict(path='receipts', mode='040000', type='tree', sha='9' * 40)]
        self.tree = git_tree_sha(self.tree_entries, schema=GIT_TREE_SCHEMA)
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
            f'git/commits/{self.head}': dict(sha=self.head, tree=dict(sha=self.tree),
                                           parents=[dict(sha='3' * 40)],
                                           verification=dict(verified=True, reason='valid')),
            f'git/commits/{self.parent}': dict(tree=dict(sha=self.old_tree)),
            f'git/commits/{self.main}': dict(tree=dict(sha=self.old_tree)),
            self.statuses: [dict(id=21, context=JENKINS_CONTEXT, state='success',
                                 creator=dict(login=JENKINS_ISSUER), created_at='2026-11-23T18:00:00Z')],
            OPEN_MAIN: [],
        }
        self.bind_actions(self.head)
        self.bind_ansible()
        self.posted = []

    @staticmethod
    def checks_path(head, name):
        return f'commits/{head}/check-runs?' + urlencode(
            dict(check_name=name, filter='latest', per_page=100))

    def bind_actions(self, head):
        self.actions_path = self.checks_path(head, ACTIONS_CHECK)
        self.actions_runs = 'actions/workflows/41/runs?' + urlencode(
            dict(head_sha=head, event='pull_request', per_page=100))
        self.data.update({
            self.actions_path: dict(total_count=1, check_runs=[dict(
                id=43, app=dict(id=ACTIONS_APP_ID), name=ACTIONS_CHECK, head_sha=head,
                status='completed', conclusion='success', completed_at='2026-11-23T18:00:00Z',
                check_suite=dict(id=44))]),
            f'actions/workflows/{ACTIONS_WORKFLOW}': dict(id=41),
            self.actions_runs: dict(total_count=1, workflow_runs=[dict(id=42)]),
            'actions/runs/42': dict(id=42, workflow_id=41, run_attempt=1,
                                    path=f'.github/workflows/{ACTIONS_WORKFLOW}',
                                    event='pull_request', head_sha=head, status='completed',
                                    conclusion='success', repository=self.repo,
                                    head_repository=self.repo, check_suite_id=44,
                                    pull_requests=[dict(number=27, head=dict(sha=head),
                                                        base=dict(sha=self.parent))]),
            'actions/runs/42/attempts/1/jobs?per_page=100': dict(total_count=1, jobs=[dict(
                id=43, name=ACTIONS_CHECK, status='completed', conclusion='success',
                completed_at='2026-11-23T18:00:00Z',
                check_run_url=f'https://api.github.com/repos/{REPO}/check-runs/43')]),
            f'contents/.github/workflows/{ACTIONS_WORKFLOW}?ref={self.parent}':
                dict(type='file', sha='5' * 40),
            f'contents/.github/workflows/{ACTIONS_WORKFLOW}?ref={head}':
                dict(type='file', sha='5' * 40),
        })

    def bind_ansible(self):
        self.fix_head, self.fix_parent, self.dev_parent = ['1' * 40, '2' * 40, '3' * 40]
        self.ansible_path = self.checks_path(self.fix_head, ANSIBLE_CHECK)
        reviewed = reviewed_tree_sha(self.tree_entries, schema=GIT_TREE_SCHEMA)
        receipt_ref = '40-Evidence/Audits/change-validation/fixture/run/SHA256SUMS.captures'
        text = '\n'.join([f'receipt_schema={GIT_TREE_SCHEMA}',
                          'receipt_sha256=' + '7' * 64,
                          f'receipt_ref={receipt_ref}', f'target_tree_sha={reviewed}',
                          f'head_tree_sha={self.tree}', f'target_commit_sha={self.fix_parent}'])
        self.data.update({
            f'commits/{self.head}/pulls?per_page=100': [dict(
                number=26, merge_commit_sha=self.head, base=dict(ref='development'),
                state='closed', merged_at='2026-11-23T17:59:00Z')],
            'pulls/26': dict(number=26, merged=True, state='closed', merge_commit_sha=self.head,
                             merged_at='2026-11-23T17:59:00Z',
                             head=dict(ref='fix/fixture', sha=self.fix_head, repo=self.repo),
                             base=dict(ref='development', sha=self.dev_parent, repo=self.repo)),
            f'git/commits/{self.fix_head}': dict(sha=self.fix_head, tree=dict(sha=self.tree),
                                               parents=[dict(sha=self.fix_parent)]),
            f'git/trees/{self.tree}': dict(tree=self.tree_entries, truncated=False),
            self.ansible_path: dict(total_count=1, check_runs=[dict(
                id=25, name=ANSIBLE_CHECK, head_sha=self.fix_head, app=dict(id=ANSIBLE_APP_ID),
                status='completed', conclusion='success', completed_at='2026-11-23T17:58:00Z',
                external_id='7' * 64,
                output=dict(summary=f'pr=26;base={self.dev_parent};head={self.fix_head}', text=text))]),
        })

    def reconcile_staging(self):
        candidate = '4' * 40
        self.data['pulls/27']['head'] = dict(
            ref=f'sync/development-to-staging-{self.head}', sha=candidate, repo=self.repo)
        self.data[f'git/commits/{candidate}'] = dict(
            sha=candidate, tree=dict(sha=self.tree), parents=[dict(sha=self.parent)],
            verification=dict(verified=True, reason='valid',
                              signature='-----BEGIN SSH SIGNATURE-----\nfixture'),
            message=f'Exact tree\n\n{SYNC_TRAILER}: development@{self.head} -> staging')
        self.data[f'commits/{candidate}/statuses?per_page=100'] = deepcopy(self.data[self.statuses])
        self.bind_actions(candidate)
        return candidate

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
        self.assertEqual(plan['staging_actions']['run'], 42)
        self.assertEqual(plan['ansible_provenance']['mode'], 'verified-integration-provenance')
        self.assertEqual(plan['ansible_provenance']['integration_head'], self.fix_head)
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
        with self.assertRaisesRegex(Hold, 'not-an-owner-reviewed-staging-squash'):
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

    def test_generic_reconciliation_uses_pinned_upstream_not_live_development(self):
        candidate = self.reconcile_staging()
        self.data['git/ref/heads/development'] = dict(object=dict(sha='0' * 40))
        plan = self.plan()
        self.assertEqual(plan['ansible_provenance']['development'], self.head)
        self.assertNotEqual(plan['ansible_provenance']['integration_head'], candidate)
        self.assertEqual(self.create(plan), 28)

    def test_reconciliation_rejects_wrong_parent_signature_or_lane(self):
        candidate = self.reconcile_staging()
        key = f'git/commits/{candidate}'
        original = deepcopy(self.data[key])
        for field, value in [('parents', [dict(sha=self.main)]),
                             ('verification', dict(verified=False, reason='invalid')),
                             ('message', f'{SYNC_TRAILER}: development@{self.head} -> main')]:
            with self.subTest(field=field):
                self.data[key] = dict(original, **{field: value})
                with self.assertRaisesRegex(Hold, 'reconciled-staging-source-not-bound'):
                    self.plan()
        self.data[key] = original
        self.data['pulls/27']['head']['ref'] = 'sync/development-to-staging-old-exception'
        with self.assertRaisesRegex(Hold, 'unsupported-staging-source'):
            self.plan()
        self.assertEqual(self.posted, [])

    def test_actions_requires_real_latest_pre_merge_success(self):
        check = self.data[self.actions_path]['check_runs'][0]
        original = deepcopy(check)
        for field, value in [('conclusion', 'failure'), ('status', 'in_progress'),
                             ('completed_at', '2026-11-23T18:02:00Z')]:
            with self.subTest(field=field):
                self.data[self.actions_path]['check_runs'] = [dict(original, **{field: value})]
                with self.assertRaisesRegex(Hold, 'actions-missing-pre-merge-success'):
                    self.plan()
        self.data[self.actions_path]['check_runs'] = [original]
        self.data[self.actions_runs]['workflow_runs'].insert(0, dict(id=45))
        self.data['actions/runs/45'] = dict(self.data['actions/runs/42'], id=45,
                                           status='in_progress', conclusion=None)
        with self.assertRaisesRegex(Hold, 'actions-run-not-bound-to-staging-review'):
            self.plan()

    def test_actions_rejects_other_issuer_workflow_head_base_or_changed_definition(self):
        check = self.data[self.actions_path]['check_runs'][0]
        check['app'] = dict(id=1)
        with self.assertRaisesRegex(Hold, 'missing-or-ambiguous-trusted-check'):
            self.plan()
        check['app'] = dict(id=ACTIONS_APP_ID)
        run = deepcopy(self.data['actions/runs/42'])
        variants = [('path', '.github/workflows/forged-green.yml'),
                    ('head_sha', '0' * 40), ('check_suite_id', 46),
                    ('pull_requests', [dict(number=27, head=dict(sha=self.head),
                                            base=dict(sha='0' * 40))])]
        for field, value in variants:
            with self.subTest(field=field):
                self.data['actions/runs/42'] = dict(run, **{field: value})
                with self.assertRaisesRegex(Hold, 'actions-run-not-bound-to-staging-review'):
                    self.plan()
        self.data['actions/runs/42'] = run
        self.data[f'contents/.github/workflows/{ACTIONS_WORKFLOW}?ref={self.head}']['sha'] = '6' * 40
        with self.assertRaisesRegex(Hold, 'actions-workflow-differs-from-protected-base'):
            self.plan()

    def test_actions_refuses_ambiguous_or_truncated_proof(self):
        original = deepcopy(self.data[self.actions_path])
        self.data[self.actions_path]['check_runs'].append(deepcopy(original['check_runs'][0]))
        with self.assertRaisesRegex(Hold, 'missing-or-ambiguous-trusted-check'):
            self.plan()
        self.data[self.actions_path] = original
        self.data[self.actions_runs]['total_count'] = 100
        with self.assertRaisesRegex(Hold, 'actions-runs-missing-or-incomplete'):
            self.plan()

    def test_actions_rejects_a_success_from_an_older_attempt(self):
        jobs = self.data['actions/runs/42/attempts/1/jobs?per_page=100']
        jobs['jobs'][0]['check_run_url'] = f'https://api.github.com/repos/{REPO}/check-runs/46'
        with self.assertRaisesRegex(Hold, 'actions-check-not-from-latest-attempt'):
            self.plan()
        jobs['jobs'][0]['check_run_url'] = f'https://api.github.com/repos/{REPO}/check-runs/43'
        jobs['jobs'][0]['completed_at'] = '2026-11-23T18:02:00Z'
        with self.assertRaisesRegex(Hold, 'actions-check-not-from-latest-attempt'):
            self.plan()

    def test_inherited_ansible_does_not_accept_other_issuer_or_wrong_receipt_parent(self):
        check = self.data[self.ansible_path]['check_runs'][0]
        check['app'] = dict(id=1)
        with self.assertRaisesRegex(Hold, 'missing-or-ambiguous-trusted-check'):
            self.plan()
        check['app'] = dict(id=ANSIBLE_APP_ID)
        check['output']['text'] = check['output']['text'].replace(self.fix_parent, self.main)
        with self.assertRaisesRegex(Hold, 'ansible-origin-receipt-not-bound'):
            self.plan()

    def test_inherited_ansible_requires_same_tree_and_pre_merge_proof(self):
        check = self.data[self.ansible_path]['check_runs'][0]
        check['completed_at'] = '2026-11-23T18:00:00Z'
        with self.assertRaisesRegex(Hold, 'ansible-missing-bound-pre-merge-success'):
            self.plan()
        check['completed_at'] = '2026-11-23T17:58:00Z'
        self.data[f'git/commits/{self.fix_head}']['tree']['sha'] = self.old_tree
        with self.assertRaisesRegex(Hold, 'ansible-origin-tree-or-parent-mismatch'):
            self.plan()

    def test_final_ref_recheck_holds_concurrent_main_move(self):
        def moving_route(*args):
            self.data['git/ref/heads/main']['object']['sha'] = '0' * 40
            return self.route(*args)
        with self.assertRaisesRegex(Hold, 'promotion-refs-moved-during-plan'):
            plan_draft(self.get, self.staging, moving_route)
        self.assertEqual(self.posted, [])

    def test_conflict_hold_retains_exact_refs_and_paths_without_a_draft(self):
        with patch('prepare_main_draft.Repository') as repository, \
                patch('prepare_main_draft.assess', return_value=(1, 'conflict')):
            repository.return_value.phases = [dict(conflict_paths=['Jenkinsfile'])]
            with self.assertRaises(MainRouteHold) as caught:
                ordinary_route(self.staging, self.main)
        self.assertEqual(caught.exception.details['staging'], self.staging)
        self.assertEqual(caught.exception.details['main'], self.main)
        self.assertEqual(caught.exception.details['conflict_paths'], ['Jenkinsfile'])
        self.assertEqual(self.posted, [])


if __name__ == '__main__':
    unittest.main()
