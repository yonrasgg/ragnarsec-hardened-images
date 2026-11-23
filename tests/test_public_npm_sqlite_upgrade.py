"""The local compatibility proof must not depend on an agent's scratch directory."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'nginx-proxy-manager/test-sqlite-upgrade.sh'
PREFIX = 'npm117-sqlite-upgrade.'
OLD, NEW = ('sha256:' + 'a' * 64, 'sha256:' + 'b' * 64)


class NpmSqliteUpgradeTempdir(unittest.TestCase):
    def assert_receipt_in(self, tmpdir, expected):
        with tempfile.TemporaryDirectory() as tools:
            docker = Path(tools) / 'docker'
            docker.write_text('#!/bin/sh\nexit 73\n', encoding='utf-8')
            docker.chmod(0o700)
            env = dict(os.environ, PATH=os.pathsep.join((tools, os.defpath)))
            env.pop('TMPDIR', None)
            if tmpdir is not None:
                env['TMPDIR'] = str(tmpdir)
            run = subprocess.run(['bash', str(SCRIPT), OLD, NEW], env=env, text=True,
                                 capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 73, run.stderr)
        self.assertTrue(run.stdout.startswith('Evidence directory: '), run.stdout)
        receipt = Path(run.stdout.removeprefix('Evidence directory: ').strip())
        self.assertTrue(receipt.name.startswith(PREFIX), receipt)
        self.addCleanup(receipt.rmdir)
        for f in ('seed.log', 'preimage.sqlite', 'image-ids.txt'):
            self.addCleanup((receipt / f).unlink, missing_ok=True)
        self.assertEqual(receipt.parent.resolve(), expected.resolve())
        self.assertEqual((receipt / 'image-ids.txt').read_text().splitlines(), [OLD, NEW])

    def test_respects_tmpdir_with_spaces(self):
        parent = tempfile.TemporaryDirectory(prefix='npm validation ')
        self.addCleanup(parent.cleanup)
        path = Path(parent.name)
        self.assert_receipt_in(path, path)

    def test_unset_tmpdir_uses_system_tmp(self):
        self.assert_receipt_in(None, Path('/tmp'))


if __name__ == '__main__':
    unittest.main()
