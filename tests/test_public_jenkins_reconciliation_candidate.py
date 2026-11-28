"""Verify final reconciliation candidates against disposable, signed Git history.

Only a generated fixture key is used. No live repository, CI job, or owner key
is read or changed.
"""
import contextlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import jenkins_promotion_route as route


class ReconciliationCandidate(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.remote = self.root / 'remote'
        self.checkout = self.root / 'checkout'
        self.git(self.root, 'init', '-q', str(self.remote))
        self.git(self.remote, 'config', 'user.name', 'Candidate fixture')
        self.git(self.remote, 'config', 'user.email', 'candidate-fixture@invalid')
        self.git(self.remote, 'config', 'commit.gpgsign', 'false')
        self.common = self.commit('README.md', 'common\n')
        self.key = self.root / 'fixture-key'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
                        '-f', str(self.key)], check=True, capture_output=True, timeout=30)
        self.owner_key = self.key.with_suffix('.pub').read_text().strip()

    def git(self, cwd, *args):
        return subprocess.run(['git', '-C', str(cwd), *args], check=True,
                              capture_output=True, text=True, timeout=30).stdout.strip()

    def commit(self, path, content):
        target = self.remote / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        self.git(self.remote, 'add', '--', path)
        self.git(self.remote, 'commit', '-qm', path)
        return self.git(self.remote, 'rev-parse', 'HEAD')

    def candidate(self, *, versioned=False):
        for branch in ('main', 'staging', 'development'):
            self.git(self.remote, 'switch', '-qc', branch, self.common)
            self.commit('route.txt', branch + '\n')
        self.bases = {name: self.git(self.remote, 'rev-parse', name)
                      for name in route.BRANCHES}
        self.source = 'fix/candidate-fixture'
        self.git(self.remote, 'switch', '-qc', self.source, 'development')
        self.reviewed = self.commit('app.py', 'print("reviewed")\n')
        self.reviewed_tree = self.git(self.remote, 'rev-parse', 'HEAD^{tree}')
        body = dict(schema_version=1, pr='237', source_branch=self.source,
                    parent=self.bases['development'], reviewed_head=self.reviewed,
                    reviewed_tree=self.reviewed_tree, bases=self.bases,
                    conflict_paths=['route.txt'], run_id='disposable-candidate-fixture',
                    guard_files=['app.py'])
        signature = subprocess.run(
            ['ssh-keygen', '-Y', 'sign', '-f', str(self.key),
             '-n', route.SIGN_NAMESPACE, '-'],
            input=route.canonical_manifest(body), check=True,
            capture_output=True, timeout=30).stdout.decode()
        self.manifest_path = 'reconciliation/PR-237.json'
        self.receipt_path = 'receipts/ansible-validate.json'
        receipt_parent = self.commit(self.manifest_path, json.dumps(dict(body, signature=signature)) + '\n')
        if versioned:
            self.receipt_path = route.versioned_receipt_path(receipt_parent)
        # This synthetic receipt tests the path boundary, not Ansible admission.
        self.commit(self.receipt_path, '{"fixture": true}\n')

    @contextlib.contextmanager
    def gate_context(self, *, actions=True):
        self.head = self.git(self.remote, 'rev-parse', 'HEAD')
        self.tree = self.git(self.remote, 'rev-parse', 'HEAD^{tree}')
        self.git(self.root, 'clone', '-q', str(self.remote), str(self.checkout))
        if actions:
            self.git(self.checkout, 'switch', '--detach', '-q', 'origin/development')
        before = self.git(self.checkout, 'show-ref')
        previous = Path.cwd()
        try:
            os.chdir(self.checkout)
            with patch.object(route, 'OWNER_SSH_PUBLIC_KEY', self.owner_key), \
                 patch.dict(os.environ, {
                     'JOB_NAME': 'ragnarsec-hardened-images/PR-237',
                     'CHANGE_ID': '237', 'CHANGE_TARGET': 'development',
                     'CHANGE_FORK': '',
                 }):
                yield
        finally:
            os.chdir(previous)
            self.assertEqual(before, self.git(self.checkout, 'show-ref'))
            self.assertEqual(self.git(self.checkout, 'status', '--porcelain'), '')

    def check_gate(self, *, actions=True):
        if actions:
            return route.check(self.source, self.head, True, '237',
                               'yonrasgg/ragnarsec-hardened-images', self.head, '237')
        return route.check(self.source, None, True)

    def assert_current_candidate(self, *, actions):
        self.candidate()
        with self.gate_context(actions=actions):
            report = self.check_gate(actions=actions)
        self.assertEqual(report['result'], 'pass')
        self.assertFalse(report['merge_authorized'])
        self.assertNotEqual(self.tree, self.reviewed_tree)
        self.assertEqual(report['inputs']['fix_head'], self.head)
        self.assertEqual(report['reviewed_tree'], self.tree)
        self.assertEqual([phase['tree'] for phase in report['phases']], [self.tree] * 3)
        self.assertEqual(report['manifest_reviewed_head'], self.reviewed)
        self.assertEqual(report['manifest_reviewed_tree'], self.reviewed_tree)
        self.assertEqual(report['candidate_head'], self.head)
        self.assertEqual(report['candidate_tree'], self.tree)

    def test_actions_simulates_final_candidate_with_only_allowed_metadata(self):
        self.assert_current_candidate(actions=True)

    def test_jenkins_simulates_final_candidate_with_only_allowed_metadata(self):
        self.assert_current_candidate(actions=False)

    def assert_rejected(self, reason):
        with self.gate_context():
            with self.assertRaisesRegex(route.RouteUnavailable, reason):
                self.check_gate()

    def test_reconciliation_accepts_the_exact_versioned_receipt_path(self):
        self.candidate(versioned=True)
        with self.gate_context():
            report = self.check_gate()
        self.assertEqual(report['result'], 'pass')
        self.assertEqual(report['candidate_tree'], self.tree)

    def test_reconciliation_rejects_a_second_receipt(self):
        self.candidate(versioned=True)
        head = self.git(self.remote, 'rev-parse', 'HEAD')
        self.commit(route.versioned_receipt_path(head), '{}\n')
        self.assert_rejected('reconciliation-unreviewed-candidate-files')

    def test_rejects_added_code_after_signed_review(self):
        self.candidate()
        self.commit('extra.py', 'print("not reviewed")\n')
        self.assert_rejected('reconciliation-unreviewed-candidate-files')

    def test_rejects_modified_code_after_signed_review(self):
        self.candidate()
        self.commit('app.py', 'print("not reviewed")\n')
        self.assert_rejected('reconciliation-unreviewed-candidate-files')

    def test_rejects_code_mode_change_after_signed_review(self):
        self.candidate()
        self.git(self.remote, 'update-index', '--chmod=+x', 'app.py')
        self.git(self.remote, 'commit', '-qm', 'unreviewed executable bit')
        self.assert_rejected('reconciliation-unreviewed-candidate-files')

    def test_rejects_deleted_code_after_signed_review(self):
        self.candidate()
        self.git(self.remote, 'rm', '--', 'app.py')
        self.git(self.remote, 'commit', '-qm', 'unreviewed deletion')
        self.assert_rejected('reconciliation-unreviewed-candidate-files')

    def test_rejects_code_renamed_to_metadata_path(self):
        self.candidate()
        self.git(self.remote, 'rm', '--', self.receipt_path)
        (self.remote / self.receipt_path).parent.mkdir(exist_ok=True)
        self.git(self.remote, 'mv', 'app.py', self.receipt_path)
        self.git(self.remote, 'commit', '-qm', 'unreviewed rename')
        self.assert_rejected('reconciliation-unreviewed-candidate-files')

    def test_rejects_another_receipt_path(self):
        self.candidate()
        self.commit('receipts/extra.json', '{}\n')
        self.assert_rejected('reconciliation-unreviewed-candidate-files')

    def test_rejects_another_manifest_path(self):
        self.candidate()
        self.commit('reconciliation/PR-238.json', '{}\n')
        self.assert_rejected('reconciliation-unreviewed-candidate-files')

    def test_rejects_executable_receipt(self):
        self.candidate()
        self.git(self.remote, 'update-index', '--chmod=+x', self.receipt_path)
        self.git(self.remote, 'commit', '-qm', 'executable metadata')
        self.assert_rejected('reconciliation-candidate-metadata-not-regular')

    def test_rejects_symlink_receipt(self):
        self.candidate()
        target = self.remote / self.receipt_path
        target.unlink()
        target.symlink_to('../app.py')
        self.git(self.remote, 'add', '--', self.receipt_path)
        self.git(self.remote, 'commit', '-qm', 'symlink metadata')
        self.assert_rejected('reconciliation-candidate-metadata-not-regular')

    def test_rejects_deleted_receipt(self):
        self.candidate()
        self.git(self.remote, 'rm', '--', self.receipt_path)
        self.git(self.remote, 'commit', '-qm', 'missing metadata')
        self.assert_rejected('reconciliation-candidate-metadata-not-regular')

    def test_rejects_receipt_directory(self):
        self.candidate()
        (self.remote / self.receipt_path).unlink()
        self.commit(self.receipt_path + '/payload.json', '{}\n')
        self.assert_rejected('reconciliation-unreviewed-candidate-files')

    def test_rejects_gitlink_receipt(self):
        self.candidate()
        self.git(self.remote, 'rm', '--', self.receipt_path)
        self.git(self.remote, 'update-index', '--add', '--cacheinfo',
                 '160000,' + self.reviewed + ',' + self.receipt_path)
        self.git(self.remote, 'commit', '-qm', 'gitlink metadata')
        self.assert_rejected('reconciliation-candidate-metadata-not-regular')

    def test_rejects_external_gitlink_when_git_config_ignores_submodules(self):
        self.candidate()
        self.git(self.remote, 'update-index', '--add', '--cacheinfo',
                 '160000,' + self.reviewed + ',unreviewed-module')
        self.git(self.remote, 'commit', '-qm', 'unreviewed gitlink')
        with self.gate_context():
            self.git(self.checkout, 'config', 'diff.ignoreSubmodules', 'all')
            with self.assertRaisesRegex(
                    route.RouteUnavailable, 'reconciliation-unreviewed-candidate-files'):
                self.check_gate()

    def test_rejects_executable_manifest(self):
        self.candidate()
        self.git(self.remote, 'update-index', '--chmod=+x', self.manifest_path)
        self.git(self.remote, 'commit', '-qm', 'executable manifest')
        self.assert_rejected('reconciliation-candidate-metadata-not-regular')


if __name__ == '__main__':
    unittest.main()
