"""Exercise protected promotion assessments on exact PR events."""
from contextlib import redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools/promotion_candidate.py'
sys.path.insert(0, str(ROOT / 'tools'))
from jenkins_promotion_route import RouteUnavailable
from promotion_candidate import REPO, REPO_ID, SYNC_TRAILER, UPSTREAM, assess, event_inputs, main
from promotion_route import Repository


class PromotionCandidate(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / 'repo'
        self.git_init = ['git', '-C', str(temp.name), 'init', '-q', str(self.path)]
        subprocess.run(self.git_init, check=True, capture_output=True, text=True)
        self.git('config', 'user.name', 'Promotion Candidate Fixture')
        self.git('config', 'user.email', 'candidate-fixture@invalid')
        self.git('config', 'commit.gpgsign', 'false')
        self.git('remote', 'add', 'origin', str(self.path))
        self.base = self.commit('base', 'README.md', 'target')
        self.head = self.base
        self.head = self.commit('source change', 'source', 'head')
        self.git('checkout', '-q', '--detach', self.base)
        self.repo = Repository(str(self.path))

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.path), *args], check=True,
                              capture_output=True, text=True).stdout.strip()

    def commit(self, message, path, target):
        attr, branch = ('head', 'development') if target == 'head' else ('base', 'staging')
        start = getattr(self, attr, None)
        if start is not None:
            self.git('checkout', '-q', '--detach', start)
        (self.path / path).write_text(message + '\n')
        self.git('add', '--', path)
        self.git('commit', '-qm', message)
        sha = self.git('rev-parse', 'HEAD')
        self.git('branch', '-f', branch, sha)
        setattr(self, attr, sha)
        return sha

    def event(self):
        side = lambda ref, sha: {'repo': {'id': REPO_ID, 'full_name': REPO},
                                 'ref': ref, 'sha': sha}
        return {'pull_request': {'head': side('development', self.head),
                                 'base': side('staging', self.base)}}

    def run_assessment(self, event, move=False, moved_on_final_read=None):
        pr = event['pull_request']
        refs = {f"refs/heads/{side['ref']}": side['sha'] for side in (pr['head'], pr['base'])}
        for ref, revision in refs.items():
            self.git('update-ref', ref, revision)
        upstream_ref = f"refs/heads/{UPSTREAM[pr['base']['ref']]}"
        if upstream_ref not in refs:
            refs[upstream_ref] = self.git('rev-parse', upstream_ref)
        reads = 0

        def read_live(requested):
            nonlocal reads
            reads += 1
            if move:
                return {ref: '1' * 40 for ref in requested}
            observed = {ref: refs[ref] for ref in requested}
            if moved_on_final_read is not None and reads > 1:
                observed[moved_on_final_read] = '1' * 40
            return observed

        def run_git(*args):
            return subprocess.run(['git', '-C', str(self.path), *args], check=True,
                                  capture_output=True, text=True).stdout

        self.repo.phases.clear()
        return assess(event, self.repo, read_live=read_live, run_git=run_git)

    def sync_candidate(self, *, conflict=True, signed=True, wrong_parent=False,
                       wrong_tree=False, wrong_lane=False, target='staging'):
        if conflict:
            self.commit('upstream changed common', 'common', 'head')
            self.commit('target changed common', 'common', 'target')
        upstream = UPSTREAM[target]
        self.git('update-ref', f'refs/heads/{upstream}', self.head)
        self.git('update-ref', f'refs/heads/{target}', self.base)
        self.git('checkout', '-q', '--detach', self.base)
        key = self.path.parent / 'owner'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)],
                       check=True, capture_output=True)
        args = ['-c', 'gpg.format=ssh', '-c', f'user.signingkey={key}', 'commit-tree',
                self.base + '^{tree}' if wrong_tree else self.head + '^{tree}',
                '-p', self.head if wrong_parent else self.base,
                '-m', 'Review exact tree for promotion',
                '-m', f'{SYNC_TRAILER}: {upstream}@{self.head} -> {"wrong" if wrong_lane else target}']
        candidate = self.git(*args, '-S' if signed else '--no-gpg-sign')
        event = self.event()
        event['pull_request']['head'].update(ref=f'sync/{upstream}-to-{target}-{self.head}', sha=candidate)
        event['pull_request']['base']['ref'] = target
        return event, key.with_suffix('.pub').read_text().strip()

    def test_clean_pass_emits_read_only_report(self):
        self.assertEqual(self.run_assessment(self.event()), (0, 'pass'))
        event_path = self.path / 'event.json'
        event_path.write_text(json.dumps(self.event()))
        run = subprocess.run([sys.executable, str(TOOL), str(event_path)], cwd=str(self.path),
                             text=True, capture_output=True, check=True)
        report = json.loads(run.stdout)
        self.assertFalse(report['merge_authorized'])
        self.assertEqual(report['phases'][0]['head_sha'], self.head)
        self.assertEqual(report['result'], 'pass')

    def test_conflict_fails_the_lane(self):
        self.git('checkout', '-q', '--detach', self.head)
        self.head = self.commit('head changed common', 'common', 'head')
        self.git('checkout', '-q', '--detach', self.base)
        self.base = self.commit('base changed common', 'common', 'target')
        self.assertEqual(self.run_assessment(self.event()), (1, 'conflict'))
        self.assertEqual(self.repo.phases[-1]['conflict_paths'], ['common'])

    def test_clean_merge_with_different_tree_fails(self):
        self.base = self.commit('another file in target', 'target-only', 'target')
        self.assertEqual(self.run_assessment(self.event()), (1, 'unexpected-candidate-tree'))

    def test_noop_fails(self):
        self.head = self.base
        self.assertEqual(self.run_assessment(self.event()), (1, 'no-op'))

    def test_moving_ref_fails(self):
        with self.assertRaisesRegex(RouteUnavailable, 'source-or-target-moved'):
            self.run_assessment(self.event(), move=True)

    def test_ordinary_refs_moving_after_simulation_fail(self):
        for ref in ('refs/heads/development', 'refs/heads/staging'):
            with self.subTest(ref=ref), self.assertRaisesRegex(RouteUnavailable, 'source-or-target-moved'):
                self.run_assessment(self.event(), moved_on_final_read=ref)
            self.assertEqual(len(self.repo.phases), 1)
            self.assertEqual(self.repo.phases[0]['result'], 'clean')

    def test_wrong_checkout_fails(self):
        self.git('checkout', '-q', '--detach', self.head)
        with self.assertRaisesRegex(RouteUnavailable, 'trusted-checkout'):
            self.run_assessment(self.event())

    def test_forks_and_unapproved_sync_branches_fail(self):
        for field, value in [('repo', {'id': 1, 'full_name': REPO}),
                             ('ref', 'sync/development-to-staging-unapproved')]:
            event = copy.deepcopy(self.event())
            event['pull_request']['head'][field] = value
            with self.subTest(field=field), self.assertRaises(RouteUnavailable):
                event_inputs(event)

    def assert_exact_tree_reproduces_conflict(self, target):
        event, public_key = self.sync_candidate(target=target)
        with patch('promotion_candidate.OWNER_SSH_PUBLIC_KEY', public_key):
            self.assertEqual(self.run_assessment(event), (0, 'pass-reconciled-exact-tree'))
        ordinary, reconciliation = self.repo.phases
        self.assertEqual(ordinary['conflict_paths'], ['common'])
        self.assertEqual(reconciliation['tree'], self.git('rev-parse', self.head + '^{tree}'))
        self.assertTrue(reconciliation['source_tree_matches'])

    def test_signed_exact_tree_for_staging_reproduces_conflict_then_passes(self):
        self.assert_exact_tree_reproduces_conflict('staging')

    def test_signed_exact_tree_for_main_reproduces_conflict_then_passes(self):
        self.assert_exact_tree_reproduces_conflict('main')

    def test_exact_tree_is_rejected_when_the_ordinary_route_is_clean(self):
        event, public_key = self.sync_candidate(conflict=False)
        with patch('promotion_candidate.OWNER_SSH_PUBLIC_KEY', public_key):
            self.assertEqual(self.run_assessment(event), (1, 'exact-tree-ordinary-route-not-conflicted'))

    def test_exact_tree_is_rejected_when_owner_signature_is_untrusted(self):
        event, _ = self.sync_candidate()
        with self.assertRaisesRegex(RouteUnavailable, 'exact-tree-owner-signature-invalid'):
            self.run_assessment(event)

    def test_exact_tree_is_rejected_when_unsigned(self):
        event, _ = self.sync_candidate(signed=False)
        with self.assertRaisesRegex(RouteUnavailable, 'exact-tree-owner-signature-required'):
            self.run_assessment(event)

    def test_exact_tree_is_rejected_on_wrong_parent(self):
        event, _ = self.sync_candidate(wrong_parent=True)
        with self.assertRaisesRegex(RouteUnavailable, 'exact-tree-target-parent-mismatch'):
            self.run_assessment(event)

    def test_exact_tree_is_rejected_on_changed_tree(self):
        event, _ = self.sync_candidate(wrong_tree=True)
        with self.assertRaisesRegex(RouteUnavailable, 'exact-tree-upstream-tree-mismatch'):
            self.run_assessment(event)

    def test_exact_tree_is_rejected_when_signed_for_another_lane(self):
        event, public_key = self.sync_candidate(wrong_lane=True)
        with patch('promotion_candidate.OWNER_SSH_PUBLIC_KEY', public_key):
            with self.assertRaisesRegex(RouteUnavailable, 'exact-tree-signed-lane-mismatch'):
                self.run_assessment(event)

    def test_exact_tree_is_rejected_when_the_pinned_upstream_moves(self):
        event, public_key = self.sync_candidate()
        self.git('update-ref', 'refs/heads/development', self.base)
        with patch('promotion_candidate.OWNER_SSH_PUBLIC_KEY', public_key):
            with self.assertRaisesRegex(RouteUnavailable, 'source-or-target-moved'):
                self.run_assessment(event)

    def test_exact_tree_refs_moving_after_simulation_fail(self):
        event, public_key = self.sync_candidate()
        refs = (f"refs/heads/{event['pull_request']['head']['ref']}",
                'refs/heads/staging', 'refs/heads/development')
        with patch('promotion_candidate.OWNER_SSH_PUBLIC_KEY', public_key):
            for ref in refs:
                with self.subTest(ref=ref), self.assertRaisesRegex(RouteUnavailable, 'source-or-target-moved'):
                    self.run_assessment(event, moved_on_final_read=ref)
                self.assertEqual([phase['result'] for phase in self.repo.phases], ['conflict', 'clean'])

    def test_event_and_jenkins_modes_produce_the_same_reconciliation_report(self):
        event, public_key = self.sync_candidate(target='main')
        event_path = self.path.parent / 'event.json'
        event_path.write_text(json.dumps(event))
        source, target, head, base = event_inputs(event)
        reports = []
        with patch('promotion_candidate.OWNER_SSH_PUBLIC_KEY', public_key):
            # Materialize the live fixture refs, then exercise both actual CLI paths.
            self.assertEqual(self.run_assessment(event), (0, 'pass-reconciled-exact-tree'))
            previous_cwd = Path.cwd()
            try:
                os.chdir(self.path)
                for arguments in ([str(event_path)], ['--jenkins-input', source, target, head, base]):
                    output = io.StringIO()
                    with patch.object(sys, 'argv', [str(TOOL), *arguments]), redirect_stdout(output):
                        self.assertEqual(main(), 0)
                    reports.append(json.loads(output.getvalue()))
            finally:
                os.chdir(previous_cwd)
        self.assertEqual(reports[0], reports[1])
        self.assertEqual(reports[0]['result'], 'pass-reconciled-exact-tree')
        self.assertFalse(reports[0]['merge_authorized'])


if __name__ == '__main__':
    unittest.main()
