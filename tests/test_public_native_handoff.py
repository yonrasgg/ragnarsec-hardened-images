"""Contracts for the credential-free handoff from native CI validators."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import validation_handoff as handoff


class NativeHandoffPipeline(unittest.TestCase):
    def setUp(self):
        self.pipeline = (ROOT / 'Jenkinsfile').read_text()

    def test_only_one_amd64_agent_is_requested(self):
        self.assertEqual(self.pipeline.count("agent { label 'ragnarsec-linux' }"), 1)
        self.assertEqual(self.pipeline.count("agent { label 'ragnarsec-linux-arm64' }"), 1)

    def test_plan_is_accepted_by_the_jenkins_shell(self):
        plan = self.pipeline.split("stage('Plan')", 1)[1].split("stage('Validate')", 1)[0]
        block = re.search(r"\bsh\s+'''(.*?)'''", plan, re.S)
        self.assertIsNotNone(block)
        result = subprocess.run(['/bin/sh', '-n'], input=block[1], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_reused_workspaces_clean_review_reports_before_source_scan(self):
        contract = self.pipeline.split("stage('Contract')", 1)[1]
        before_scan = contract.split('python3 tools/publication_guard.py', 1)[0]
        self.assertIn("dir('ci-summary') { deleteDir() }", before_scan)

    def test_handoff_runs_on_promotion_without_registry_credentials(self):
        self.assertIn("stage('Verify native handoff')", self.pipeline)
        handoff = self.pipeline.split("stage('Verify native handoff')", 1)[1].split("stage('Publish')", 1)[0]
        self.assertNotIn('params.PUBLISH', handoff)
        self.assertNotRegex(handoff, r'withCredentials|docker login')
        self.assertIn('validation_handoff.py assemble', handoff)
        self.assertIn('tools/validation_summary.py', handoff)
        self.assertLess(handoff.index('archiveArtifacts'), handoff.index('cleanup {'))
        publish = self.pipeline.split("stage('Publish')", 1)[1]
        self.assertLess(publish.index('input message'), publish.index('withCredentials'))

    def test_publication_inspects_but_never_executes_foreign_images(self):
        publish = (ROOT / 'tools' / 'image_ci.py').read_text().split('def publish(', 1)[1]
        self.assertNotIn('require_platforms_available', publish)
        self.assertRegex(publish, r'\bverify_receipts\(')


class NativeHandoffReceipts(unittest.TestCase):
    image = 'ragnarsec-base-min'
    revision = 'a' * 40
    tag = f'sha-{revision}-42'

    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.root = Path(root.name)
        self.output = self.root / 'assembled'
        self.images = {}
        self.available = set()
        self.commands = []
        self.arm = self.root / 'arm64'
        self.amd = self.root / 'amd64'
        self.archive = self.arm / handoff.ARCHIVE
        self.manifest = self.arm / handoff.BUNDLE
        for platform, directory, image_id in (
                (handoff.AMD64, self.amd, 'sha256:' + '1' * 64),
                (handoff.ARM64, self.arm, 'sha256:' + '2' * 64)):
            directory.mkdir()
            arch = platform.split('/')[-1]
            ref = f'{handoff.ci.REGISTRY}{self.image}:{self.tag}-{arch}'
            sbom = f'{self.image}.{arch}.cdx.json'
            self.images[ref] = f'{image_id} {platform}'
            self.available.add(ref)
            (directory / sbom).write_bytes(b'{}')
            (directory / 'validate.log').write_text('validation fixture\n')
            (directory / 'validated.json').write_text(json.dumps([{
                'name': self.image, 'platform': platform, 'ref': ref, 'id': image_id,
                'sbom': sbom, 'sbom_sha256': hashlib.sha256(b'{}').hexdigest(),
            }]))
        self.arm_ref = next(ref for ref in self.available if ref.endswith('-arm64'))
        self.enterContext(patch.object(handoff.ci, 'command', side_effect=self.command))
        self.enterContext(patch.object(handoff.ci, 'require_platforms_available',
                                       side_effect=AssertionError('emulator check ran')))
        handoff.pack(self.image, self.tag, self.revision, self.arm)
        self.available.remove(self.arm_ref)
        self.commands.clear()

    def command(self, *args, capture=False):
        self.commands.append(args)
        stdout = ''
        if args == ('git', 'rev-parse', '--verify', 'HEAD'):
            stdout = self.revision
        elif args[:3] == ('docker', 'image', 'inspect'):
            self.assertIn(args[-1], self.available)
            stdout = self.images[args[-1]]
        elif args[:3] == ('docker', 'image', 'save'):
            self.assertEqual(args[3:], ('--platform', handoff.ARM64, '-o', str(self.archive), self.arm_ref))
            self.archive.write_bytes(b'archive fixture')
        elif args[:3] == ('docker', 'image', 'load'):
            self.assertEqual(args[3:], ('--platform', handoff.ARM64, '-i', str(self.archive)))
            self.available.add(self.arm_ref)
        else:
            self.fail(f'unexpected command {args}')
        return subprocess.CompletedProcess(args, 0, stdout=stdout)

    def assemble(self):
        handoff.assemble(self.image, self.tag, self.revision, self.root, self.output)

    def assert_no_load(self):
        self.assertFalse(any(args[:3] == ('docker', 'image', 'load') for args in self.commands))

    def test_loads_only_arm_and_checks_both_platforms(self):
        self.assemble()
        rows = json.loads((self.output / 'validated.json').read_text())
        self.assertEqual({r['platform'] for r in rows}, {handoff.AMD64, handoff.ARM64})
        self.assertIn(self.arm_ref, self.available)

    def test_changed_archive_is_rejected_before_load(self):
        self.archive.write_bytes(b'other archive')
        with self.assertRaisesRegex(ValueError, 'handoff-checksum-mismatch'):
            self.assemble()
        self.assert_no_load()

    def test_missing_archive_is_rejected_before_load(self):
        self.archive.unlink()
        with self.assertRaisesRegex(ValueError, 'missing-or-unsafe-handoff-file'):
            self.assemble()
        self.assert_no_load()

    def test_bundle_from_another_run_is_rejected_before_load(self):
        meta = json.loads(self.manifest.read_text())
        meta['tag'] = f'sha-{self.revision}-41'
        self.manifest.write_text(json.dumps(meta))
        with self.assertRaisesRegex(ValueError, 'handoff-identity-mismatch'):
            self.assemble()
        self.assert_no_load()

    def test_wrong_loaded_platform_fails_even_with_the_same_image_id(self):
        self.images[self.arm_ref] = self.images[self.arm_ref].replace(handoff.ARM64, handoff.AMD64)
        with self.assertRaisesRegex(ValueError, 'validated-image-changed'):
            self.assemble()


if __name__ == '__main__':
    unittest.main()
