"""Exercise the protected-policy loader with real local Git repositories."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / 'tools/verify_protected_promotion.sh'
APPROVED_ORIGIN = 'https://github.com/yonrasgg/ragnarsec-hardened-images.git'
PROTECTED_POLICY = '''import json
import os
from pathlib import Path
import subprocess
import sys

print(json.dumps({
    "policy": "protected-target",
    "arguments": sys.argv[1:],
    "checkout": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
}))
if os.environ.get("FIXTURE_LEAVE_TEMP"):
    (Path.cwd().parent / "left-by-fixture").write_text("cleanup must report this file")
raise SystemExit(int(os.environ.get("FIXTURE_POLICY_EXIT", "0")))
'''
CANDIDATE_POLICY = '''import os
from pathlib import Path
Path(os.environ["FIXTURE_TRAP"]).write_text("PR policy was executed")
raise SystemExit(91)
'''


class ProtectedPolicyAdapter(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name)
        self.remote = self.path / 'remote.git'
        self.repo = self.path / 'checkout'
        self.workspace_tmp = self.path / 'jenkins-tmp'
        self.workspace_tmp.mkdir()
        self.trap_path = self.path / 'candidate-executed'
        for arguments in (['init', '-q', '--bare', str(self.remote)],
                          ['init', '-q', str(self.repo)]):
            subprocess.run(['git', *arguments], check=True, capture_output=True, text=True)
        self.git('config', 'user.name', 'Protected Adapter Fixture')
        self.git('config', 'user.email', 'protected-adapter@invalid')
        self.git('config', 'commit.gpgsign', 'false')
        self.git('remote', 'add', 'origin', APPROVED_ORIGIN)
        # Exercise stock Git URL rewriting to a local bare remote; no production flag.
        self.git('config', f'url.{self.remote.as_uri()}.insteadOf', APPROVED_ORIGIN)
        (self.repo / 'tools').mkdir()
        self.policy_files = ('tools/promotion_candidate.py', 'tools/jenkins_promotion_route.py')
        for filename in self.policy_files:
            (self.repo / filename).write_text(PROTECTED_POLICY)
        self.git('add', 'tools')
        self.git('commit', '-qm', 'Protected fixture policy')
        self.base = self.git('rev-parse', 'HEAD')
        for target in ('development', 'staging', 'main'):
            self.git('update-ref', f'refs/heads/{target}', self.base)
        for filename in self.policy_files:
            (self.repo / filename).write_text(CANDIDATE_POLICY)
        self.git('commit', '-qam', 'Candidate policy must not run')
        self.head = self.git('rev-parse', 'HEAD')
        self.sources = {
            'development': 'fix/adapter-fixture',
            'staging': f'sync/development-to-staging-{self.base}',
            'main': f'sync/staging-to-main-{self.base}',
        }
        for source in self.sources.values():
            self.git('update-ref', f'refs/heads/{source}', self.head)
        self.git('push', '-q', 'origin', '--all')
        self.git('checkout', '-q', '--detach', self.head)
        self.fetch_head = self.repo / '.git/FETCH_HEAD'
        self.fetch_head.write_text('preserve this fixture FETCH_HEAD\n')

    def git(self, *arguments):
        return subprocess.run(['git', '-C', str(self.repo), *arguments],
                              check=True, capture_output=True, text=True).stdout.strip()

    def snapshot(self):
        return {
            'head': self.git('rev-parse', 'HEAD'),
            'status': self.git('status', '--porcelain'),
            'refs': self.git('for-each-ref', '--format=%(refname) %(objectname)'),
            'worktrees': self.git('worktree', 'list', '--porcelain'),
            'fetch_head': self.fetch_head.read_bytes(),
        }

    def run_adapter(self, target='staging', *, source=None, head=None, environment=None):
        source = self.sources.get(target, self.sources['staging']) if source is None else source
        head = self.head if head is None else head
        env = dict(os.environ, CHANGE_ID='321', JOB_NAME='ragnarsec-hardened-images/PR-321',
                   CHANGE_TARGET=target, CHANGE_BRANCH=source, CHANGE_FORK='',
                   WORKSPACE_TMP=str(self.workspace_tmp), FIXTURE_TRAP=str(self.trap_path))
        env.pop('FIXTURE_POLICY_EXIT', None)
        env.pop('FIXTURE_LEAVE_TEMP', None)
        env.update(environment or {})
        return subprocess.run(['bash', str(ADAPTER), source, target, head],
                              cwd=self.repo, env=env, capture_output=True, text=True, timeout=30)

    def assert_restored(self, before, *, expect_empty=True):
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.trap_path.exists(), 'The PR verifier must never execute')
        if expect_empty:
            self.assertEqual(list(self.workspace_tmp.iterdir()), [])

    def test_all_targets_run_only_the_protected_policy_and_cleanup(self):
        for target in ('development', 'staging', 'main'):
            with self.subTest(target=target):
                before = self.snapshot()
                result = self.run_adapter(target)
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(next(line for line in result.stdout.splitlines() if line.startswith('{')))
                self.assertEqual(report['policy'], 'protected-target')
                self.assertEqual(report['checkout'], self.base)
                if target == 'development':
                    self.assertEqual(report['arguments'], [
                        '--source', self.sources[target], '--reviewed-head', self.head,
                        '--manifest-from-pr', self.head, '--pr', '321', '--change-id', '321',
                        '--repo', 'yonrasgg/ragnarsec-hardened-images', '--allow-manifest-reconciliation',
                    ])
                else:
                    self.assertEqual(report['arguments'], [
                        '--jenkins-input', self.sources[target], target, self.head, self.base,
                    ])
                self.assert_restored(before)

    def test_owner_prefixed_branch_is_accepted(self):
        before = self.snapshot()
        result = self.run_adapter(environment={'CHANGE_BRANCH': 'yonrasgg:' + self.sources['staging']})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_restored(before)

    def test_wrong_job_fork_or_event_binding_is_rejected(self):
        invalid = (
            {'CHANGE_ID': ''}, {'CHANGE_ID': '321x'},
            {'JOB_NAME': 'ragnarsec-hardened-images/PR-322'},
            {'CHANGE_TARGET': 'main'}, {'CHANGE_BRANCH': 'fix/other'},
            {'CHANGE_BRANCH': 'another-owner:' + self.sources['staging']},
            {'CHANGE_FORK': 'fork-owner/repository'},
        )
        for overrides in invalid:
            with self.subTest(overrides=overrides):
                before = self.snapshot()
                result = self.run_adapter(environment=overrides)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assert_restored(before)

    def test_invalid_source_target_or_commit_is_rejected(self):
        for arguments in ({'source': '../bad'}, {'source': '-option'},
                          {'target': 'release'}, {'head': self.head[:12]}):
            with self.subTest(arguments=arguments):
                before = self.snapshot()
                result = self.run_adapter(**arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assert_restored(before)

    def test_merge_checkout_is_rejected_without_changing_it(self):
        merge = self.git('commit-tree', self.head + '^{tree}', '-p', self.base, '-p', self.head,
                         '--no-gpg-sign', '-m', 'Synthetic PR merge fixture')
        self.git('checkout', '-q', '--detach', merge)
        before = self.snapshot()
        result = self.run_adapter()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('not a synthetic merge', result.stderr)
        self.assert_restored(before)

    def test_unapproved_origin_is_rejected(self):
        for origin in ('https://github.com/another-owner/ragnarsec-hardened-images.git',
                       'https://user:credential@github.com/yonrasgg/ragnarsec-hardened-images.git'):
            with self.subTest(origin=origin):
                self.git('config', 'remote.origin.url', origin)
                before = self.snapshot()
                result = self.run_adapter()
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn(origin, result.stderr)
                self.assert_restored(before)

    def test_missing_protected_target_fails_closed(self):
        self.git('push', '-q', 'origin', ':refs/heads/staging')
        before = self.snapshot()
        result = self.run_adapter()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('target ref is unavailable or ambiguous', result.stderr)
        self.assert_restored(before)

    def test_old_target_policy_fails_and_is_cleaned_up(self):
        self.git('checkout', '-q', '--detach', self.base)
        (self.repo / 'tools/promotion_candidate.py').write_text(
            'import argparse\nparser = argparse.ArgumentParser()\n'
            'parser.add_argument("event")\nparser.parse_args()\n')
        self.git('commit', '-qam', 'Protected policy without Jenkins input support')
        old_policy = self.git('rev-parse', 'HEAD')
        self.git('update-ref', 'refs/heads/staging', old_policy)
        self.git('push', '-q', 'origin', 'refs/heads/staging')
        self.git('checkout', '-q', '--detach', self.head)
        before = self.snapshot()
        result = self.run_adapter()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('unrecognized arguments', result.stderr)
        self.assert_restored(before)

    def test_evaluator_failure_keeps_its_exit_code_and_cleans_up(self):
        before = self.snapshot()
        result = self.run_adapter(environment={'FIXTURE_POLICY_EXIT': '37'})
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assert_restored(before)

    def test_cleanup_failure_makes_success_fail(self):
        before = self.snapshot()
        result = self.run_adapter(environment={'FIXTURE_LEAVE_TEMP': '1'})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('temporary directory cleanup failed', result.stderr)
        self.assert_restored(before, expect_empty=False)

    def test_cleanup_failure_does_not_hide_evaluator_failure(self):
        before = self.snapshot()
        result = self.run_adapter(environment={'FIXTURE_POLICY_EXIT': '37', 'FIXTURE_LEAVE_TEMP': '1'})
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertIn('temporary directory cleanup failed', result.stderr)
        self.assert_restored(before, expect_empty=False)


if __name__ == '__main__':
    unittest.main()
