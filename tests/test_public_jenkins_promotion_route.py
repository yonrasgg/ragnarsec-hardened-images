"""Exercise the exact development PR route gate against disposable Git refs."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools/jenkins_promotion_route.py'
sys.path.insert(0, str(ROOT / 'tools'))
from jenkins_promotion_route import RouteUnavailable, plan_reconciliation, require_reconciliation_context


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

    def test_recovery_aliases_are_named_and_frozen_in_jenkins(self):
        pipeline = (ROOT / 'Jenkinsfile').read_text()
        self.assertIn('sync/development-to-staging-pr164-repair-20261123', pipeline)
        self.assertIn('sync/staging-to-main-pr164-repair-20261123', pipeline)
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
