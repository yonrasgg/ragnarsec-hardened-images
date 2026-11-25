"""Exercise ordinary promotion assessments on exact PR events and a protected base."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools/promotion_candidate.py'
sys.path.insert(0, str(ROOT / 'tools'))
from jenkins_promotion_route import RouteUnavailable
from promotion_candidate import REPO, REPO_ID, assess, event_inputs
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

    def run_assessment(self, event, move=False):
        pr = event['pull_request']
        refs = {'refs/heads/development': pr['head']['sha'],
                'refs/heads/staging': pr['base']['sha']}
        self.git('branch', '-f', 'development', refs['refs/heads/development'])
        self.git('branch', '-f', 'staging', refs['refs/heads/staging'])

        def read_live(requested):
            if move:
                return {ref: '1' * 40 for ref in requested}
            return {ref: refs[ref] for ref in requested}

        def run_git(*args):
            return subprocess.run(['git', '-C', str(self.path), *args], check=True,
                                  capture_output=True, text=True).stdout

        self.repo.phases.clear()
        return assess(event, self.repo, read_live=read_live, run_git=run_git)

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


if __name__ == '__main__':
    unittest.main()
