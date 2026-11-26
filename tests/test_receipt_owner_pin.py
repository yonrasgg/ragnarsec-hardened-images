"""Owner-pin tests for the tree-bound Ansible receipt gate.

The positive case uses a LOCALLY GENERATED test key — never the owner key.
Fail-closed negatives are preserved: an unpinned/mismatched signer, a tampered
payload and a wrong newline form are all rejected.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from ansible_receipt_gate import (  # noqa: E402
    EVIDENCE_ROOT, GENESIS, RECEIPT_PATH, SCHEMA, SIGNATURE_NAMESPACE, TRUST,
    canonical_bytes, git_tree_sha, reviewed_tree_sha, sha256_bytes, verify_receipt,
)

OWNER_PIN = 'd78b1c0c693978f42ca1e4c701e35c04789cd424b14f0bbf020628e3f5799066'
HEAD = '1' * 40
NOW = datetime(2026, 11, 26, 0, 0, tzinfo=timezone.utc)
VERSION = 'ansible [core 2.19.11]'


def clock(offset=0):
    return (NOW + timedelta(seconds=offset)).strftime('%Y-%m-%dT%H:%M:%SZ')


class OwnerPinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='owner-pin-test-')
        cls.root = Path(cls.tmp.name)
        key = cls.root / 'test-signer'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)],
                       check=True)
        cls.private = key
        # The public line WITH trailing newline is what the pin commits to.
        cls.public = (cls.root / 'test-signer.pub').read_text(encoding='utf-8')
        cls.local_trust = {
            'trusted_runners': [{
                'host_id': 'heimdall', 'actor': 'userone',
                'key_id': 'heimdall-userone-pilot-ed25519',
                'public_key_sha256': sha256_bytes(cls.public.encode('utf-8')),
            }],
            'chain': {'seq': 1, 'prev_receipt_sha256': GENESIS},
        }

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.entries = [
            {'path': 'README.md', 'mode': '100644', 'type': 'blob', 'sha': 'a' * 40},
            {'path': 'receipts', 'mode': '40000', 'type': 'tree', 'sha': 'c' * 40},
        ]
        self.head_tree = git_tree_sha(self.entries)
        self.bound = reviewed_tree_sha(self.entries, RECEIPT_PATH)
        self.evd = f'{EVIDENCE_ROOT}heimdall/run-pin/receipt.json'

    def receipt(self, public=None):
        def cmd(cid):
            return {
                'id': cid, 'argv': ['ansible-playbook', '--version' if cid == 'C1' else '--syntax-check'],
                'cwd': '/home/userone/staging/run-pin', 'rc': 0,
                'owner_gate': False, 'sudo_required': False,
                'started_at': clock(-60), 'finished_at': clock(-30),
                'stdout_sha256': 'd' * 64, 'stderr_sha256': 'e' * 64,
            }
        commands = [cmd('C1'), cmd('C2')]
        captures = [{'id': c['id'], 'rc': c['rc'], 'stdout_sha256': c['stdout_sha256'],
                     'stderr_sha256': c['stderr_sha256']} for c in commands]
        return {
            'schema': SCHEMA, 'run_id': 'run-pin',
            'target_tree_sha': self.bound, 'target_commit_sha': HEAD,
            'playbook_sha': '2' * 64, 'inventory_sha': '3' * 64,
            'commands': commands, 'outputs_sha256': sha256_bytes(canonical_bytes(captures)),
            'ansible_version': VERSION,
            'ansible_version_sha256': sha256_bytes(VERSION.encode('utf-8')),
            'host_id': 'heimdall', 'actor': 'userone', 'sudo_required': False,
            'observed_at': clock(-10), 'result': 'pass', 'validation_profile': 'syntax-v1',
            'tree_assertion': {'method': 'staged-manifest', 'observed': self.bound,
                               'expected': self.bound, 'source_ref': self.evd, 'match': True},
            'owner_gates': [], 'evidence_refs': [self.evd],
            'signer': {'key_id': 'heimdall-userone-pilot-ed25519',
                       'identity': 'heimdall:userone', 'mechanism': 'ed25519',
                       'public_key': public if public is not None else self.public},
            'signature': '', 'chain': {'seq': 1, 'prev_receipt_sha256': GENESIS},
            'supersedes': None,
        }

    def sign(self, receipt):
        work = Path(tempfile.mkdtemp(prefix='sign-pin-', dir=str(self.root)))
        payload = work / 'payload'
        unsigned = {k: v for k, v in receipt.items() if k != 'signature'}
        payload.write_bytes(canonical_bytes(unsigned))
        subprocess.run(['ssh-keygen', '-q', '-Y', 'sign', '-f', str(self.private),
                        '-n', SIGNATURE_NAMESPACE, str(payload)], check=True)
        receipt['signature'] = (work / 'payload.sig').read_text(encoding='utf-8')
        return canonical_bytes(receipt)

    def verify(self, raw, trust):
        return verify_receipt(raw, head_sha=HEAD, head_tree_sha=self.head_tree,
                              head_tree_entries=self.entries, trust=trust, now=NOW,
                              repo='yonrasgg/ragnarsec-hardened-images',
                              receipt_path=RECEIPT_PATH)

    def test_default_trust_pins_the_owner_public_key(self):
        self.assertEqual(TRUST['trusted_runners'][0]['public_key_sha256'], OWNER_PIN)

    def test_positive_local_test_key_is_accepted_with_its_own_pin(self):
        raw = self.sign(self.receipt())
        decision = self.verify(raw, self.local_trust)
        self.assertTrue(decision['ok'], decision['reason'])
        self.assertEqual(decision['step'], 15)

    def test_fail_closed_against_the_owner_pin_with_a_test_key(self):
        raw = self.sign(self.receipt())
        decision = self.verify(raw, TRUST)
        self.assertFalse(decision['ok'])
        self.assertIn('step-6', decision['reason'])

    def test_fail_closed_on_tampered_payload(self):
        receipt = self.receipt()
        raw = self.sign(receipt)
        tampered = json.loads(raw)
        tampered['result'] = 'partial'
        decision = self.verify(canonical_bytes(tampered), self.local_trust)
        self.assertFalse(decision['ok'])
        self.assertIn('step-6', decision['reason'])

    def test_fail_closed_when_public_key_omits_newline(self):
        receipt = self.receipt(public=self.public.rstrip('\n'))
        raw = self.sign(receipt)
        decision = self.verify(raw, self.local_trust)
        self.assertFalse(decision['ok'])
        self.assertIn('step-6', decision['reason'])


if __name__ == '__main__':
    unittest.main()
