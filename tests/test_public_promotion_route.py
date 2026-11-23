"""The read-only route preflight must reject either protected-lane conflict."""
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

TOOL = Path(__file__).resolve().parents[1] / 'tools' / 'promotion_route.py'


class PromotionRoute(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Route Fixture')
        self.git('config', 'user.email', 'route-fixture@invalid')
        self.git('config', 'commit.gpgsign', 'false')
        self.base = self.change('Jenkinsfile', 'base\n')

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.repo), *args], check=True,
                              capture_output=True, text=True).stdout.strip()

    def change(self, file, text):
        (self.repo / file).write_text(text)
        self.git('add', '--', file)
        self.git('commit', '-qm', f'fixture: {file}')
        return self.git('rev-parse', 'HEAD')

    def fork(self, origin, file, text):
        self.git('switch', '--detach', '-q', origin)
        return self.change(file, text)

    def run_route(self, development, staging, main, *extra):
        refs = self.git('show-ref')
        current = self.git('rev-parse', 'HEAD')
        result = subprocess.run([
            sys.executable, str(TOOL), '--repository', str(self.repo),
            '--development', development, '--staging', staging, '--main', main, *extra,
        ], capture_output=True, text=True)
        self.assertEqual(self.git('show-ref'), refs)
        self.assertEqual(self.git('rev-parse', 'HEAD'), current)
        self.assertEqual(self.git('status', '--porcelain'), '')
        report = json.loads(result.stdout)
        self.assertIs(report['merge_authorized'], False)
        self.assertEqual(report['exit_code'], result.returncode)
        return result.returncode, report

    def test_clean_routes_include_trees_without_touching_refs_or_worktree(self):
        development = self.fork(self.base, 'app', 'release\n')
        staging = self.fork(self.base, 'stage', 'frozen\n')
        main = self.fork(self.base, 'live', 'preserve\n')
        code, report = self.run_route(development, staging, main)
        self.assertEqual(code, 0)
        self.assertEqual(report['result'], 'pass')
        self.assertEqual([p['lane'] for p in report['phases']], ['development-to-staging', 'staging-to-main'])
        candidate = report['phases'][-1]['tree']
        self.assertEqual(self.git('show', f'{candidate}:app'), 'release')
        self.assertEqual(self.git('show', f'{candidate}:live'), 'preserve')

    def test_does_not_attempt_main_if_the_staging_squash_conflicts(self):
        development = self.fork(self.base, 'Jenkinsfile', 'dev plan\n')
        staging = self.fork(self.base, 'Jenkinsfile', 'staging plan\n')
        code, report = self.run_route(development, staging, self.base)
        self.assertEqual(code, 1)
        self.assertEqual([(p['lane'], p['conflict_paths']) for p in report['phases']],
                         [('development-to-staging', ['Jenkinsfile'])])

    def test_successful_staging_squash_does_not_hide_main_conflict(self):
        staging = self.fork(self.base, 'Jenkinsfile', 'staging plan\n')
        development = self.fork(staging, 'app', 'release\n')
        main = self.fork(self.base, 'Jenkinsfile', 'main plan\n')
        code, report = self.run_route(development, staging, main)
        self.assertEqual(code, 1)
        self.assertEqual(report['phases'][0]['result'], 'clean')
        self.assertEqual(report['phases'][1]['conflict_paths'], ['Jenkinsfile'])

    def test_fix_can_conflict_with_development_before_any_promotion(self):
        development = self.fork(self.base, 'Jenkinsfile', 'dev plan\n')
        fix = self.fork(self.base, 'Jenkinsfile', 'fix plan\n')
        code, report = self.run_route(development, self.base, self.base, '--fix-head', fix)
        self.assertEqual(code, 1)
        self.assertEqual(report['phases'][0]['lane'], 'fix-to-development')
        self.assertEqual(len(report['phases']), 1)

    def test_requires_full_existing_commit_ids(self):
        for value in ('HEAD', 'f' * 40):
            with self.subTest(value=value):
                code, report = self.run_route(value, self.base, self.base)
                self.assertEqual(code, 2)
                self.assertEqual(report['phases'], [])
