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
    OWNER_SSH_PUBLIC_KEY,
    RouteUnavailable,
    canonical_manifest,
    check,
    plan_reconciliation,
    require_actions_reconciliation_context,
    require_reconciliation_context,
    require_reconciliation_pins,
    verify_manifest_signature,
)


SIGN_NAMESPACE = 'ragnarsec-promotion-reconciliation-v1'
SIGN_IDENTITY = 'ragnarsec-owner'


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
        # A disposable owner key: the tool must verify against the pinned public
        # key, so a fixture manifest is signed with this key and patched in.
        self.key = Path(temp.name) / 'owner_key'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.key)],
                       check=True, capture_output=True, timeout=30)
        self.owner_key = Path(str(self.key) + '.pub').read_text().strip()

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

    def signed_manifest(self, *, pr='237', source='fix/reviewed-change', parent=None,
                        reviewed_head=None, reviewed_tree=None, bases=None,
                        conflicts=None, run_id='fixture-run', guards=None,
                        signer=None):
        body = {'schema_version': 1, 'pr': str(pr), 'source_branch': source,
                'parent': parent or 'a' * 40, 'reviewed_head': reviewed_head or 'b' * 40,
                'reviewed_tree': reviewed_tree or 'c' * 40,
                'bases': bases or {name: d * 40 for d, name in zip('123',
                                    ('development', 'staging', 'main'))},
                'conflict_paths': conflicts or ['receipt.sh'], 'run_id': run_id}
        if guards is not None:
            body['guard_files'] = guards
        payload = canonical_manifest(body)
        signed = subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(signer or self.key),
                                 '-n', SIGN_NAMESPACE, '-'], input=payload,
                                check=True, capture_output=True, timeout=30).stdout.decode()
        return dict(body, signature=signed)

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
        tree = self.git(self.checkout, 'rev-parse', 'HEAD^{tree}')
        report = plan_reconciliation(self.checkout, inputs, tree)
        self.assertEqual(report['result'], 'pass')
        self.assertFalse(report['merge_authorized'])
        self.assertTrue(report['requires_verified_reconciliation_prs'])
        self.assertEqual(report['reviewed_tree'], tree)
        self.assertEqual([p['tree'] for p in report['phases']], [tree] * 3)
        self.assertEqual([p['base_sha'] for p in report['phases'][1:]],
                         [inputs['staging'], inputs['main']])
        with self.assertRaisesRegex(RouteUnavailable, 'reconciliation-reviewed-tree-mismatch'):
            plan_reconciliation(self.checkout, inputs, 'f' * 40)
        self.assertEqual(before, self.git(self.checkout, 'show-ref'))

    def test_approved_reconciliation_cannot_be_requested_by_other_jobs_or_actions(self):
        manifest = self.signed_manifest(pr='164', source='fix/automated-promotion-preflight')
        with patch('jenkins_promotion_route.OWNER_SSH_PUBLIC_KEY', self.owner_key):
            verify_manifest_signature(manifest)
        exact = dict(JOB_NAME='ragnarsec-hardened-images/PR-164', CHANGE_ID='164',
                     CHANGE_TARGET='development')
        require_reconciliation_context(manifest, manifest['source_branch'], exact)
        for env in (dict(exact, CHANGE_ID='165'),
                    dict(exact, JOB_NAME='folder/PR-164'),
                    dict(exact, CHANGE_TARGET='staging'),
                    dict(exact, CHANGE_FORK='fork/repo')):
            with self.subTest(env=env):
                with self.assertRaisesRegex(RouteUnavailable, 'unsupported-reconciliation-context'):
                    require_reconciliation_context(manifest, manifest['source_branch'], env)
        with self.assertRaisesRegex(RouteUnavailable, 'unsupported-reconciliation-context'):
            require_reconciliation_context(manifest, 'fix/other', exact)

    def test_actions_checkout_reconciliation_is_scoped_to_signed_manifest_and_reviewed_tree(self):
        manifest = self.signed_manifest(pr='173', source='fix/actions-promotion-base-checkout',
                                        guards=['Jenkinsfile', 'tools/jenkins_promotion_route.py'])
        env = dict(JOB_NAME='ragnarsec-hardened-images/PR-173', CHANGE_ID='173',
                   CHANGE_TARGET='development')
        require_reconciliation_context(manifest, manifest['source_branch'], env)
        with self.assertRaisesRegex(RouteUnavailable, 'unsupported-reconciliation-context'):
            require_reconciliation_context(manifest, manifest['source_branch'],
                                           dict(env, CHANGE_ID='174'))
        with self.assertRaisesRegex(RouteUnavailable, 'manifest-signature-invalid'):
            verify_manifest_signature(dict(manifest, run_id='tampered-after-signing'))
        with patch('jenkins_promotion_route.OWNER_SSH_PUBLIC_KEY', self.owner_key):
            verify_manifest_signature(manifest)
        head = 'a' * 40
        refs = {f'refs/heads/{name}': sha for name, sha in manifest['bases'].items()}
        calls = [f"{head} {manifest['parent']}\n", manifest['reviewed_tree'] + '\n',
                 '\0'.join(manifest['guard_files']) + '\0']
        with patch('jenkins_promotion_route.git', side_effect=calls):
            require_reconciliation_pins(manifest, refs, head)
        # A live-base mismatch is detected before any object is read.
        with self.assertRaisesRegex(RouteUnavailable, 'reconciliation-bases-or-source-parent-moved'):
            require_reconciliation_pins(manifest, dict(refs, **{'refs/heads/main': '4' * 40}), head)
        for replacement, side_effect in (
                (f"{head} {'3' * 40}\n", [f"{head} {'3' * 40}\n"]),
                ('d' * 40, [f"{head} {manifest['parent']}\n", 'd' * 40 + '\n'])):
            with self.subTest(replacement=replacement):
                with patch('jenkins_promotion_route.git', side_effect=side_effect):
                    with self.assertRaisesRegex(RouteUnavailable,
                                                'reconciliation-bases-or-source-parent-moved'):
                        require_reconciliation_pins(manifest, refs, head)
        with patch('jenkins_promotion_route.git', side_effect=[
                f"{head} {manifest['parent']}\n", manifest['reviewed_tree'] + '\n',
                'versions.json\0']):
            with self.assertRaisesRegex(RouteUnavailable, 'reconciliation-unreviewed-guard-files'):
                require_reconciliation_pins(manifest, refs, head)

    def test_actions_reconciliation_context_is_scoped_to_trusted_event(self):
        manifest = self.signed_manifest(pr='237', source='fix/staging-draft-app-token-20261126')
        head = 'a' * 40
        repo = 'yonrasgg/ragnarsec-hardened-images'
        require_actions_reconciliation_context(manifest, manifest['source_branch'], head, '237', repo)
        for change_id, source, reviewed_head, event_repo in (
                ('238', manifest['source_branch'], head, repo),
                ('237', 'fix/other', head, repo),
                ('237', manifest['source_branch'], None, repo),
                ('237', manifest['source_branch'], 'xyz', repo),
                ('237', manifest['source_branch'], head, 'attacker/example'),
                (None, manifest['source_branch'], head, repo)):
            with self.subTest(change_id=change_id, source=source,
                              reviewed_head=reviewed_head, repo=event_repo):
                with self.assertRaisesRegex(RouteUnavailable,
                                            'unsupported-reconciliation-context'):
                    require_actions_reconciliation_context(
                        manifest, source, reviewed_head, change_id, event_repo)

    def test_actions_reconciliation_check_keeps_pins_conflict_and_plan(self):
        manifest = self.signed_manifest(pr='237', source='fix/staging-draft-app-token-20261126',
                                        parent='9' * 40, reviewed_head='a' * 40,
                                        reviewed_tree='c' * 40)
        head = 'a' * 40
        reviewed = manifest['reviewed_head']
        dev = manifest['bases']['development']
        refs = {f'refs/heads/{name}': sha for name, sha in manifest['bases'].items()}
        refs['refs/heads/' + manifest['source_branch']] = head
        direct = {'schema_version': 1, 'result': 'conflict', 'exit_code': 1,
                  'merge_authorized': False, 'phases': [
                      {'lane': 'fix-to-development', 'result': 'clean'},
                      {'lane': 'development-to-staging', 'result': 'conflict',
                       'conflict_paths': manifest['conflict_paths']}]}
        planned = {'schema_version': 1, 'result': 'pass', 'exit_code': 0,
                   'reviewed_tree': manifest['reviewed_tree'], 'merge_authorized': False,
                   'phases': [
                       {'lane': 'fix-to-development', 'result': 'clean'},
                       {'lane': 'development-to-staging-reconciliation', 'result': 'clean'},
                       {'lane': 'staging-to-main-reconciliation', 'result': 'clean'}],
                   'requires_verified_reconciliation_prs': True}
        git_calls = ['', dev + '\n', '', json.dumps(manifest),
                     f"{reviewed} {manifest['parent']}\n", manifest['reviewed_tree'] + '\n',
                     '', '100644 blob ' + 'd' * 40 + '\treceipts/ansible-validate.json\0',
                     '100644 blob ' + 'e' * 40 + '\treconciliation/PR-237.json\0',
                     manifest['reviewed_tree'] + '\n']
        real_run = subprocess.run

        def fake_run(argv, **kwargs):
            if argv[0] == 'ssh-keygen':
                return real_run(argv, **kwargs)
            if argv[:1] == ['git'] and 'merge-base' in argv:
                return subprocess.CompletedProcess(argv, 0, '', '')
            self.assertEqual(argv[0], sys.executable)
            return subprocess.CompletedProcess(argv, 1, json.dumps(direct), '')

        with patch('jenkins_promotion_route.OWNER_SSH_PUBLIC_KEY', self.owner_key), \
             patch('jenkins_promotion_route.git', side_effect=git_calls), \
             patch('jenkins_promotion_route.live', side_effect=[refs, refs, refs]), \
             patch('jenkins_promotion_route.subprocess.run', side_effect=fake_run), \
             patch('jenkins_promotion_route.plan_reconciliation',
                   return_value=planned) as plan:
            report = check(manifest['source_branch'], head, True, '237',
                           'yonrasgg/ragnarsec-hardened-images', head, '237')
        self.assertEqual(report, dict(planned, direct_route=direct, manifest_pr='237',
                                      manifest_reviewed_head=reviewed,
                                      manifest_reviewed_tree=manifest['reviewed_tree'],
                                      candidate_head=head, candidate_tree=manifest['reviewed_tree'],
                                      run_id=manifest['run_id']))
        self.assertEqual(report['result'], 'pass')
        self.assertFalse(report['merge_authorized'])
        self.assertEqual([p['lane'] for p in report['phases']],
                         ['fix-to-development', 'development-to-staging-reconciliation',
                          'staging-to-main-reconciliation'])
        plan.assert_called_once_with('.', dict(manifest['bases'], fix_head=head),
                                     manifest['reviewed_tree'])
        for change_id, repo in (('238', 'yonrasgg/ragnarsec-hardened-images'),
                                ('237', None)):
            with self.subTest(change_id=change_id, repo=repo):
                with self.assertRaisesRegex(RouteUnavailable,
                                            'unsupported-reconciliation-context'):
                    check(manifest['source_branch'], head, True, change_id, repo, head, '237')

    def test_clean_ordinary_route_does_not_require_a_reconciliation_manifest(self):
        repo = 'yonrasgg/ragnarsec-hardened-images'
        source = 'fix/ordinary'
        dev, stage, main, head = (digit * 40 for digit in '1234')
        refs = {'refs/heads/development': dev, 'refs/heads/staging': stage,
                'refs/heads/main': main, f'refs/heads/{source}': head}
        direct = dict(exit_code=0, result='pass', merge_authorized=False, phases=[
            dict(lane=lane, result='clean', source_tree_matches=True)
            for lane in ('fix-to-development', 'development-to-staging', 'staging-to-main')
        ])
        with patch('jenkins_promotion_route.git', side_effect=['', dev + '\n', '']), \
             patch('jenkins_promotion_route.live', return_value=refs), \
             patch('jenkins_promotion_route.subprocess.run', return_value=subprocess.CompletedProcess(
                 ['python3'], 0, json.dumps(direct), '')), \
             patch('jenkins_promotion_route.load_manifest') as manifest:
            self.assertEqual(check(source, head, True, '237', repo, head, '237'), direct)
        manifest.assert_not_called()

    def test_actions_workflow_reads_the_signed_pr_manifest_without_allowlists(self):
        workflow = (ROOT / '.github/workflows/promotion-route-preflight.yml').read_text()
        for marker in ('--change-id "$PR_NUMBER"', '--repo "$REPO"', '--pr "$PR_NUMBER"',
                       '--manifest-from-pr "$PR_HEAD_SHA"',
                       '--allow-manifest-reconciliation'):
            self.assertIn(marker, workflow)
        self.assertNotIn('case "$PR_NUMBER:$SOURCE_BRANCH"', workflow)
        self.assertNotIn('--approved-reconciliation', workflow)
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
        self.assertIn('--allow-manifest-reconciliation', pipeline)
        self.assertIn('--pr "$CHANGE_ID"', pipeline)
        self.assertNotIn('case "$JOB_NAME:$CHANGE_ID:$CHANGE_BRANCH"', pipeline)
        self.assertNotIn('--approved-reconciliation', pipeline)

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
        for marker in ('pull_request:', 'synchronize', 'ready_for_review',
                       'contents: read', 'ref: ${{ github.event.pull_request.base.sha }}',
                       'persist-credentials: false',
                       '"$BASE_REPO" == "$GITHUB_REPOSITORY"', '"$BASE_BRANCH" == development',
                       '--reviewed-head "$PR_HEAD_SHA"', '--manifest-from-pr "$PR_HEAD_SHA"',
                       '--pr "$PR_NUMBER"', '--allow-manifest-reconciliation'):
            self.assertIn(marker, workflow)
        self.assertNotIn('pull_request_target', workflow)
        self.assertNotIn('ref: ${{ github.sha }}', workflow)
        self.assertNotIn('ref: ${{ github.event.pull_request.head.sha }}', workflow)
        self.assertNotIn('contents: write', workflow)
        self.assertNotIn('secrets.', workflow)
        self.assertNotIn('self-hosted', workflow)


if __name__ == '__main__':
    unittest.main()
