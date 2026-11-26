"""Exercise the exact development PR route gate against disposable Git refs."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools/jenkins_promotion_route.py'
sys.path.insert(0, str(ROOT / 'tools'))
from jenkins_promotion_route import (
    RECONCILIATIONS,
    RouteUnavailable,
    check,
    plan_reconciliation,
    require_actions_reconciliation_context,
    require_reconciliation_context,
    require_reconciliation_pins,
)


class JenkinsPromotionRoute(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.remote = Path(temp.name) / 'remote'
        self.checkout = Path(temp.name) / 'checkout'
        self.git(self.remote.parent, 'init', '-q', str(self.remote))
        self.git(self.remote, 'config', 'user.name', 'Route Fixture')
        self.git(self.remote, 'config', 'user.email', 'route-fixture@invalid')
        self.git(self.remote, 'config', 'commit.gpgsign', 'false')
        self.base = self.commit('README.md', 'common\n')

    def git(self, repo, *args):
        return subprocess.run(['git', '-C', str(repo), *args], check=True,
                              capture_output=True, text=True).stdout.strip()

    def commit(self, path, content):
        (self.remote / path).write_text(content)
        self.git(self.remote, 'add', '--', path)
        branch = self.git(self.remote, 'branch', '--show-current')
        self.git(self.remote, 'commit', '-qm', f'{branch}: {path}')
        return self.git(self.remote, 'rev-parse', 'HEAD')

    def branch(self, name, base):
        self.git(self.remote, 'switch', '-qc', name, base)

    def setup_checkout(self, *, conflict):
        self.branch('main', self.base)
        if conflict:
            self.commit('receipt.sh', 'old\n')
        self.branch('staging', self.base)
        if conflict:
            self.commit('receipt.sh', 'old\n')
        stage = self.git(self.remote, 'rev-parse', 'HEAD')
        self.branch('development', stage)
        self.branch('fix/reviewed-change', 'development')
        self.commit('receipt.sh', 'new\n')
        self.git(self.remote.parent, 'clone', '-q', str(self.remote), str(self.checkout))

    def run_gate(self, source='fix/reviewed-change', *args):
        before = self.git(self.checkout, 'show-ref')
        result = subprocess.run([sys.executable, str(TOOL), '--source', source, *args],
                                cwd=self.checkout, env=dict(os.environ, GIT_CONFIG_NOSYSTEM='1'),
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(before, self.git(self.checkout, 'show-ref'))
        self.assertEqual(self.git(self.checkout, 'status', '--porcelain'), '')
        report = json.loads(result.stdout)
        self.assertEqual(report['exit_code'], result.returncode)
        self.assertFalse(report['merge_authorized'])
        return report

    def test_conflict_after_clean_staging_is_not_a_green_development_check(self):
        self.setup_checkout(conflict=True)
        report = self.run_gate()
        self.assertEqual(report['result'], 'conflict')
        self.assertEqual(report['phases'][-1]['lane'], 'staging-to-main')
        self.assertEqual(report['phases'][-1]['conflict_paths'], ['receipt.sh'])

    def test_reconciliation_uses_both_target_parents_and_exact_reviewed_tree(self):
        self.setup_checkout(conflict=True)
        before = self.git(self.checkout, 'show-ref')
        inputs = {name: self.git(self.checkout, 'rev-parse', 'origin/' + name)
                  for name in ('development', 'staging', 'main')}
        inputs['fix_head'] = self.git(self.checkout, 'rev-parse', 'HEAD')
        report = plan_reconciliation(self.checkout, inputs)
        self.assertEqual(report['result'], 'pass')
        self.assertFalse(report['merge_authorized'])
        self.assertTrue(report['requires_verified_reconciliation_prs'])
        tree = self.git(self.checkout, 'rev-parse', 'HEAD^{tree}')
        self.assertEqual([p['tree'] for p in report['phases']], [tree] * 3)
        self.assertEqual([p['base_sha'] for p in report['phases'][1:]],
                         [inputs['staging'], inputs['main']])
        self.assertEqual(before, self.git(self.checkout, 'show-ref'))

    def test_approved_reconciliation_cannot_be_requested_by_other_jobs_or_actions(self):
        exact = dict(JOB_NAME='ragnarsec-hardened-images/PR-164', CHANGE_ID='164',
                     CHANGE_TARGET='development')
        source = 'fix/automated-promotion-preflight'
        require_reconciliation_context(source, None, exact)
        for branch, action, env in (
                ('fix/other', None, exact), (source, '1'*40, exact),
                (source, None, dict(exact, CHANGE_ID='165')),
                (source, None, dict(exact, JOB_NAME='folder/PR-164')),
                (source, None, dict(exact, CHANGE_TARGET='staging'))):
            with self.subTest(branch=branch, action=action, env=env):
                with self.assertRaisesRegex(RouteUnavailable, 'unsupported-reconciliation-context'):
                    require_reconciliation_context(branch, action, env)

    def test_actions_checkout_reconciliation_is_scoped_to_pr173_and_reviewed_files(self):
        approved = RECONCILIATIONS['173']
        env = dict(JOB_NAME='ragnarsec-hardened-images/PR-173', CHANGE_ID='173',
                   CHANGE_TARGET='development')
        self.assertEqual(require_reconciliation_context(approved['source'], None, env), approved)
        with self.assertRaisesRegex(RouteUnavailable, 'unsupported-reconciliation-context'):
            require_reconciliation_context(approved['source'], None, dict(env, CHANGE_ID='174'))
        with self.assertRaisesRegex(RouteUnavailable, 'unsupported-reconciliation-context'):
            require_reconciliation_context(approved['source'], '1' * 40, env)
        with self.assertRaisesRegex(RouteUnavailable, 'unsupported-reconciliation-context'):
            require_reconciliation_context(approved['source'], None, dict(env, CHANGE_FORK='fork/repo'))

        head = '2' * 40
        refs = {f'refs/heads/{name}': sha for name, sha in approved['bases'].items()}
        with patch('jenkins_promotion_route.git', side_effect=[
                f"{head} {approved['parent']}\n", '\0'.join(approved['guard_files']) + '\0']):
            require_reconciliation_pins(approved, refs, head)
        with self.assertRaisesRegex(RouteUnavailable, 'reconciliation-bases-or-source-parent-moved'):
            require_reconciliation_pins(approved, dict(refs, **{'refs/heads/main': '3' * 40}), head)
        with patch('jenkins_promotion_route.git', return_value=f"{head} {'3' * 40}\n"):
            with self.assertRaisesRegex(RouteUnavailable, 'reconciliation-bases-or-source-parent-moved'):
                require_reconciliation_pins(approved, refs, head)
        with patch('jenkins_promotion_route.git', side_effect=[
                f"{head} {approved['parent']}\n", 'versions.json\0']):
            with self.assertRaisesRegex(RouteUnavailable, 'reconciliation-unreviewed-guard-files'):
                require_reconciliation_pins(approved, refs, head)

    def test_actions_reconciliation_context_is_scoped_to_trusted_event(self):
        approved = RECONCILIATIONS['237']
        head = 'a' * 40
        repo = 'yonrasgg/ragnarsec-hardened-images'
        self.assertEqual(
            require_actions_reconciliation_context(approved['source'], head, '237', repo), approved)
        for change_id, source, reviewed_head, event_repo in (
                ('238', approved['source'], head, repo),
                ('237', 'fix/other', head, repo),
                ('237', approved['source'], None, repo),
                ('237', approved['source'], 'xyz', repo),
                ('237', approved['source'], head, 'attacker/example'),
                (None, approved['source'], head, repo)):
            with self.subTest(change_id=change_id, source=source,
                              reviewed_head=reviewed_head, repo=event_repo):
                with self.assertRaisesRegex(RouteUnavailable,
                                            'unsupported-reconciliation-context'):
                    require_actions_reconciliation_context(
                        source, reviewed_head, change_id, event_repo)

    def test_actions_reconciliation_check_keeps_pins_conflict_and_plan(self):
        approved = RECONCILIATIONS['237']
        head = 'a' * 40
        dev = approved['bases']['development']
        refs = {f'refs/heads/{name}': sha for name, sha in approved['bases'].items()}
        refs['refs/heads/' + approved['source']] = head
        direct = {'schema_version': 1, 'result': 'conflict', 'exit_code': 1,
                  'merge_authorized': False, 'phases': [
                      {'lane': 'fix-to-development', 'result': 'clean'},
                      {'lane': 'development-to-staging', 'result': 'conflict',
                       'conflict_paths': approved['conflicts']}]}
        planned = {'schema_version': 1, 'result': 'pass', 'exit_code': 0,
                   'merge_authorized': False, 'phases': [
                       {'lane': 'fix-to-development', 'result': 'clean'},
                       {'lane': 'development-to-staging-reconciliation', 'result': 'clean'},
                       {'lane': 'staging-to-main-reconciliation', 'result': 'clean'}],
                   'requires_verified_reconciliation_prs': True}

        def fake_git(*args):
            if args[:2] == ('rev-parse', '--verify'):
                return dev + '\n'
            if args[:3] == ('rev-list', '--parents', '-n1'):
                return f"{head} {approved['parent']}\n"
            if args[:3] == ('diff', '--name-only', '-z'):
                return '\0'.join(approved['guard_files']) + '\0'
            return ''

        def fake_run(argv, **kwargs):
            self.assertEqual(argv[0], sys.executable)
            return subprocess.CompletedProcess(argv, 1, json.dumps(direct), '')

        with patch('jenkins_promotion_route.git', side_effect=fake_git), \
             patch('jenkins_promotion_route.live', side_effect=[refs, refs, refs]), \
             patch('jenkins_promotion_route.subprocess.run', side_effect=fake_run), \
             patch('jenkins_promotion_route.plan_reconciliation',
                   return_value=planned) as plan:
            report = check(approved['source'], head, True, '237',
                           'yonrasgg/ragnarsec-hardened-images')
        self.assertEqual(report, dict(planned, direct_route=direct))
        self.assertEqual(report['result'], 'pass')
        self.assertFalse(report['merge_authorized'])
        self.assertEqual([p['lane'] for p in report['phases']],
                         ['fix-to-development', 'development-to-staging-reconciliation',
                          'staging-to-main-reconciliation'])
        plan.assert_called_once_with('.', dict(approved['bases'], fix_head=head))
        for change_id, repo in (('238', 'yonrasgg/ragnarsec-hardened-images'),
                                ('237', None)):
            with self.subTest(change_id=change_id, repo=repo):
                with self.assertRaisesRegex(RouteUnavailable,
                                            'unsupported-reconciliation-context'):
                    check(approved['source'], head, True, change_id, repo)

    def test_actions_workflow_guards_reconciliation_to_listed_prs(self):
        workflow = (ROOT / '.github/workflows/promotion-route-preflight.yml').read_text()
        for marker in ('--change-id "$PR_NUMBER"', '--repo "$REPO"',
                       "'236:fix/ansible-check-publisher-20261126'",
                       "'237:fix/staging-draft-app-token-20261126'",
                       "'238:fix/actions-reconciliation-preflight-20261126'",
                       'set -- "$@" --approved-reconciliation'):
            self.assertIn(marker, workflow)
        run = workflow.rsplit('run: |', 1)[1]
        self.assertEqual(subprocess.run(['bash', '-n'], input=run,
                                        capture_output=True, text=True).returncode, 0)

    def test_recovery_aliases_are_named_and_frozen_in_jenkins(self):
        pipeline = (ROOT / 'Jenkinsfile').read_text()
        self.assertIn('sync/development-to-staging-pr164-repair-20261123', pipeline)
        self.assertIn('sync/staging-to-main-pr164-repair-20261123', pipeline)
        self.assertIn('sync/development-to-staging-actions-base-20261124-v2', pipeline)
        self.assertIn('sync/staging-to-main-actions-base-20261124-v2', pipeline)
        self.assertIn('ragnarsec-hardened-images/PR-173:173:fix/actions-promotion-base-checkout', pipeline)
        self.assertIn('e9ab7f4655ff1c32cd60bc3e4f6750e3d7b68e26', pipeline)
        self.assertIn('f0a1d6f044406d04e0410016985c638b04b4e47f', pipeline)
        self.assertIn('--approved-reconciliation', pipeline)

    def test_clean_route_binds_exact_live_refs(self):
        self.setup_checkout(conflict=False)
        report = self.run_gate()
        self.assertEqual(report['result'], 'pass')
        self.assertEqual(len(report['phases']), 3)
        self.assertEqual(report['inputs']['fix_head'], self.git(self.checkout, 'rev-parse', 'HEAD'))
        self.assertEqual(report['inputs']['main'], self.git(self.remote, 'rev-parse', 'main'))

    def test_rejects_wrong_checkout_or_unsupported_source(self):
        self.setup_checkout(conflict=False)
        self.git(self.checkout, 'switch', '--detach', '-q', 'origin/development')
        self.assertEqual(self.run_gate()['reason'], 'checkout-does-not-match-live-source')
        self.assertEqual(self.run_gate('topic/path')['reason'], 'unsupported-source')

    def test_deleted_protected_ref_is_not_satisfied_by_cached_tracking_ref(self):
        self.setup_checkout(conflict=False)
        self.git(self.remote, 'branch', '-D', 'staging')
        self.assertEqual(self.run_gate()['reason'], 'missing-live-ref')

    def test_actions_uses_base_checkout_and_only_fetches_pr_objects(self):
        self.setup_checkout(conflict=False)
        head = self.git(self.checkout, 'rev-parse', 'HEAD')
        source = 'fix/reviewed-change'
        self.git(self.remote, 'switch', '-q', 'main')
        self.git(self.remote, 'commit', '--allow-empty', '-qm', 'Advance the default branch')
        self.git(self.checkout, 'fetch', '--quiet', 'origin', 'main')
        self.git(self.checkout, 'switch', '--detach', '-q', 'origin/main')
        self.assertEqual(self.run_gate(source, '--reviewed-head', head)['reason'],
                         'checkout-does-not-match-live-base')
        self.git(self.checkout, 'switch', '--detach', '-q', 'origin/development')
        self.assertEqual(self.run_gate(source, '--reviewed-head', head)['result'], 'pass')
        self.assertEqual(self.run_gate(source, '--reviewed-head', '1'*40)['reason'],
                         'event-does-not-match-live-source')

    def test_jenkins_archives_report_and_fails_before_plan(self):
        stage = (ROOT / 'Jenkinsfile').read_text().split("stage('Promotion route')", 1)[1]
        stage = stage.split("stage('Tools')", 1)[0]
        self.assertIn("env.CHANGE_TARGET == 'development'", stage)
        self.assertIn('set -euo pipefail', stage)
        self.assertIn('python3 tools/jenkins_promotion_route.py', stage)
        self.assertIn("archiveArtifacts artifacts: 'ci-route/promotion-route.json'", stage)
        shell = stage.split("sh '''", 1)[1].split("'''", 1)[0]
        result = subprocess.run(['sh', '-n'], input=shell, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_actions_has_read_only_automatic_triggers_and_base_checkout(self):
        workflow = (ROOT / '.github/workflows/promotion-route-preflight.yml').read_text()
        for marker in ('pull_request_target:', 'synchronize', 'ready_for_review',
                       'contents: read', 'ref: ${{ github.event.pull_request.base.sha }}',
                       'persist-credentials: false',
                       '"$BASE_REPO" == "$GITHUB_REPOSITORY"', '"$BASE_BRANCH" == development',
                       '--reviewed-head "$PR_HEAD_SHA"'):
            self.assertIn(marker, workflow)
        self.assertNotIn('ref: ${{ github.sha }}', workflow)
        self.assertNotIn('ref: ${{ github.event.pull_request.head.sha }}', workflow)
        self.assertNotIn('contents: write', workflow)
        self.assertNotIn('self-hosted', workflow)


if __name__ == '__main__':
    unittest.main()
