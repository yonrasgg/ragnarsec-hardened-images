import importlib.util
import tempfile
import unittest
from unittest.mock import patch
import subprocess
from pathlib import Path

spec = importlib.util.spec_from_file_location('guard', Path(__file__).parents[1] / 'tools/publication_guard.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

class BoundaryTests(unittest.TestCase):
    def test_rfc1918_blocked_without_values(self):
        for parts in ([10, 22, 33, 44], [172, 16, 8, 9], [192, 168, 7, 8], [169, 254, 1, 2]):
            value = '.'.join(map(str, parts))
            output = guard.scan_text('host=' + value)
            self.assertEqual(output[0]['rule'], 'private-network')
            self.assertNotIn(value, str(output))

    def test_public_documentation_loopback_and_invalid_numbers(self):
        for value in ['127.0.0.1', '0.0.0.0', '192.0.2.1', '198.51.100.9', '203.0.113.5', '999.999.999.999']:
            self.assertEqual(guard.scan_text(value), [])

    def test_internal_domain(self):
        self.assertEqual(guard.scan_text('demo.' + 'internal')[0]['rule'], 'internal-domain')
        self.assertEqual(guard.scan_text('example.invalid'), [])

    def test_private_key_marker(self):
        self.assertEqual(guard.scan_text('-----BEGIN ' + 'PRIVATE KEY-----')[0]['rule'], 'private-key')

    def test_public_provenance_allowed(self):
        self.assertEqual(guard.scan_text('https://github.com/yonrasgg/ragnarsec-images'), [])

    def test_downstream_dispatch(self):
        self.assertEqual(guard.scan_text('api.github.com/' + 'repos/demo/downstream/dispatches')[0]['rule'], 'downstream-dispatch')

    def test_mac_address(self):
        self.assertEqual(guard.scan_text(':'.join(['ab'] * 6))[0]['rule'], 'hardware-address')

    def test_cloud_id(self):
        self.assertEqual(guard.scan_text('ocid1.' + 'instance.example')[0]['rule'], 'cloud-resource-id')

    def test_sensitive_filename_not_opened(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, '.env').write_text('example-placeholder')
            self.assertEqual(guard.scan_tree(tmp)['findings'][0]['rule'], 'sensitive-file-name')

    def test_symlink_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'link').symlink_to('/etc/hosts')
            self.assertEqual(guard.scan_tree(tmp)['findings'][0]['rule'], 'symlink-requires-review')

    def test_binary_and_large_files_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'blob').write_bytes(b'\0')
            Path(tmp, 'large').write_bytes(b'a' * (guard.MAX_BYTES + 1))
            self.assertEqual({x['rule'] for x in guard.scan_tree(tmp)['findings']}, {'binary-requires-review', 'oversized-requires-review'})

    def test_git_metadata_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, '.git').mkdir()
            Path(tmp, '.git', 'config').write_text('.'.join(map(str, [10, 1, 2, 3])))
            self.assertEqual(guard.scan_tree(tmp)['files'], 0)

    def test_directory_required(self):
        with self.assertRaises(ValueError):
            guard.scan_tree('/path/that/does/not/exist')

    def test_internal_context_paths_blocked_without_opening(self):
        for name in ['AGENTS.md', 'agents.md', 'AGENTS.override.md', 'context.json',
                     'routes.yml', '.github/copilot-instructions.md', '.github/agents/a.md',
                     '.agents/skills/demo/SKILL.md', '.codex/settings.json', 'CTX-ROU-001.md']:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                path=Path(tmp,name);path.parent.mkdir(parents=True,exist_ok=True);path.write_text('private-payload')
                findings=guard.scan_tree(tmp)['findings']
                self.assertTrue(any(f['rule']=='internal-metadata-not-public' for f in findings))
                self.assertNotIn('private-payload',str(findings))

    def test_historical_internal_file_is_rejected_after_deletion(self):
        replies=[subprocess.CompletedProcess([],0,stdout='false\n'),
                 subprocess.CompletedProcess([],0,stdout='.github/copilot-instructions.md\0README.md\0')]
        with patch.object(guard.subprocess,'run',side_effect=replies):
            self.assertEqual(guard.scan_history('/fixture')[0]['rule'],'internal-metadata-in-intended-history')

    def test_shallow_history_never_claims_success(self):
        with patch.object(guard.subprocess,'run',return_value=subprocess.CompletedProcess([],0,stdout='true\n')):
            with self.assertRaisesRegex(ValueError,'complete-history'):guard.scan_history('/fixture')

    def test_examples_and_container_home(self):
        self.assertEqual(guard.scan_text('/home/ragnarsec app.example.invalid password=${APP_PASSWORD}'), [])

if __name__ == '__main__':
    unittest.main()
