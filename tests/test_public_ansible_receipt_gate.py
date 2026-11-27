"""Fail-closed GATE verification tests for the tree-bound Ansible receipt.

Every case builds real canonical JSON bytes and a real OpenSSH detached
signature, so a passing case proves the whole verification path (not a mock).
"""
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from ansible_receipt_gate import (  # noqa: E402
    EVIDENCE_ROOT, GENESIS, GIT_TREE_SCHEMA, RECEIPT_PATH, SCHEMA, SIGNATURE_NAMESPACE, TRUST,
    canonical_bytes, git_tree_sha, reviewed_tree_sha, sha256_bytes, verify_receipt,
)

HEAD = '1' * 40
PARENT = '2' * 40  # reviewed parent commit; the receipt lives inside HEAD
NOW = datetime(2026, 11, 26, 0, 0, tzinfo=timezone.utc)
VERSION = 'ansible [core 2.19.11]'


def clock(offset_seconds=0):
    return (NOW + timedelta(seconds=offset_seconds)).strftime('%Y-%m-%dT%H:%M:%SZ')


class ReceiptGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='gate-test-')
        cls.root = Path(cls.tmp.name)
        key = cls.root / 'signer'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)],
                       check=True)
        cls.public_key = (cls.root / 'signer.pub').read_text(encoding='utf-8').strip()
        cls.private_key = key
        cls.trust = {
            'trusted_runners': [dict(host_id='heimdall', actor='userone',
                                     key_id='heimdall-userone-pilot-ed25519',
                                     public_key_sha256=sha256_bytes(
                                         cls.public_key.encode('utf-8')))],
            'chain': {'seq': 1, 'prev_receipt_sha256': GENESIS},
        }

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.entries = [
            {'path': 'README.md', 'mode': '100644', 'type': 'blob', 'sha': 'a' * 40},
            {'path': 'tools', 'mode': '40000', 'type': 'tree', 'sha': 'b' * 40},
            {'path': 'receipts', 'mode': '40000', 'type': 'tree', 'sha': 'c' * 40},
        ]
        self.head_tree = git_tree_sha(self.entries)
        self.reviewed_tree = reviewed_tree_sha(self.entries, RECEIPT_PATH)
        self.evd = f'{EVIDENCE_ROOT}heimdall/run-1/receipt.json'

    def sign(self, receipt):
        unsigned = {k: v for k, v in receipt.items() if k != 'signature'}
        work = Path(tempfile.mkdtemp(prefix='sign-', dir=str(self.root)))
        payload = work / 'payload'
        payload.write_bytes(canonical_bytes(unsigned))
        subprocess.run(['ssh-keygen', '-q', '-Y', 'sign', '-f', str(self.private_key),
                        '-n', SIGNATURE_NAMESPACE, str(payload)], check=True)
        receipt['signature'] = (work / 'payload.sig').read_text(encoding='utf-8')
        return canonical_bytes(receipt)

    def receipt(self):
        cmd = lambda cid: {
            'id': cid,
            'argv': ['ansible-playbook', '--version' if cid == 'C1' else '--syntax-check'],
            'cwd': '/home/userone/validation-staging/run-1', 'rc': 0,
            'owner_gate': False, 'sudo_required': False,
            'started_at': clock(-60), 'finished_at': clock(-30),
            'stdout_sha256': 'd' * 64, 'stderr_sha256': 'e' * 64,
        }
        commands = [cmd('C1'), cmd('C2')]
        captures = [{'id': c['id'], 'rc': c['rc'],
                     'stdout_sha256': c['stdout_sha256'],
                     'stderr_sha256': c['stderr_sha256']} for c in commands]
        outputs_sha = sha256_bytes(canonical_bytes(captures))
        return {
            'schema': SCHEMA, 'run_id': 'run-1',
            'target_tree_sha': self.reviewed_tree, 'target_commit_sha': PARENT,
            'playbook_sha': '2' * 64, 'inventory_sha': '3' * 64,
            'commands': commands,
            'outputs_sha256': outputs_sha,
            'ansible_version': VERSION,
            'ansible_version_sha256': sha256_bytes(VERSION.encode('utf-8')),
            'host_id': 'heimdall', 'actor': 'userone', 'sudo_required': False,
            'observed_at': clock(-10), 'completed_at': clock(-5),
            'result': 'pass', 'validation_profile': 'syntax-v1',
            'tree_assertion': {'method': 'staged-manifest', 'observed': self.reviewed_tree,
                               'expected': self.reviewed_tree, 'source_ref': self.evd,
                               'match': True},
            'owner_gates': [], 'evidence_refs': [self.evd, self.evd.replace('receipt.json', 'SHA256SUMS')],
            'signer': {'key_id': 'heimdall-userone-pilot-ed25519',
                       'identity': 'heimdall:userone', 'mechanism': 'ed25519',
                       'public_key': self.public_key},
            'signature': '',
            'chain': {'seq': 1, 'prev_receipt_sha256': GENESIS},
            'supersedes': None,
        }

    def verify(self, raw, **overrides):
        kwargs = dict(head_sha=HEAD, parent_sha=PARENT, head_tree_sha=self.head_tree,
                      head_tree_entries=self.entries, trust=self.trust,
                      now=NOW, repo='yonrasgg/ragnarsec-hardened-images',
                      receipt_path=RECEIPT_PATH)
        kwargs.update(overrides)
        return verify_receipt(raw, **kwargs)

    def accepted(self, mutate=None):
        receipt = self.receipt()
        if mutate:
            mutate(receipt)
        raw = self.sign(receipt)
        return self.verify(raw), raw

    def test_positive_accepts_a_tree_bound_signed_receipt(self):
        decision, raw = self.accepted()
        self.assertTrue(decision['ok'], decision['reason'])
        self.assertEqual(decision['step'], 15)
        self.assertEqual(decision['external_id'], sha256_bytes(raw))
        self.assertEqual(decision['target_tree_sha'], self.reviewed_tree)
        self.assertEqual(decision['head_tree_sha'], self.head_tree)
        self.assertIn(f'receipt_sha256={sha256_bytes(raw)}', decision['text'])
        self.assertIn(f'target_tree_sha={self.reviewed_tree}', decision['text'])
        self.assertTrue(decision['details_url'].endswith(f'/blob/{HEAD}/{RECEIPT_PATH}'))

    def test_rejects_missing_or_invalid_receipt_bytes(self):
        for raw in (b'', b'not json', b'{}'):
            with self.subTest(raw=raw[:12]):
                decision = self.verify(raw)
                self.assertFalse(decision['ok'])
                self.assertLessEqual(decision['step'], 5)

    def test_rejects_unknown_schema(self):
        decision, _ = self.accepted(lambda r: r.update(schema='ragnarsec.validation-receipt/9.9'))
        self.assertFalse(decision['ok'])
        self.assertIn('step-5', decision['reason'])

    def test_rejects_plain_linkage_only_success_without_signature(self):
        receipt = self.receipt()
        receipt['signature'] = ''
        decision = self.verify(canonical_bytes(receipt))
        self.assertFalse(decision['ok'])
        self.assertIn('step-6', decision['reason'])

    def test_rejects_signer_not_in_registry(self):
        receipt = self.receipt()
        receipt['host_id'] = 'unauthorized-host'
        raw = self.sign(receipt)
        decision = self.verify(raw)
        self.assertFalse(decision['ok'])
        self.assertIn('step-6', decision['reason'])

    def test_rejects_unpinned_public_key(self):
        receipt = self.receipt()
        raw = self.sign(receipt)
        trust = json.loads(json.dumps(self.trust))
        trust['trusted_runners'][0]['public_key_sha256'] = None
        decision = self.verify(raw, trust=trust)
        self.assertFalse(decision['ok'])
        self.assertIn('signer-public-key-not-pinned', decision['reason'])

    def test_rejects_broken_hash_chain(self):
        decision, _ = self.accepted(lambda r: r['chain'].update(seq=2))
        self.assertFalse(decision['ok'])
        self.assertIn('step-7', decision['reason'])

    def test_rejects_tree_mismatched_receipt(self):
        decision, _ = self.accepted(lambda r: r.update(target_tree_sha='2' * 40))
        self.assertFalse(decision['ok'])
        self.assertIn('step-8', decision['reason'])

    def test_rejects_commit_mismatched_receipt(self):
        decision, _ = self.accepted(lambda r: r.update(target_commit_sha='3' * 40))
        self.assertFalse(decision['ok'])
        self.assertIn('step-9', decision['reason'])

    def test_rejects_receipt_bound_to_head_instead_of_reviewed_parent(self):
        decision, _ = self.accepted(lambda r: r.update(target_commit_sha=HEAD))
        self.assertFalse(decision['ok'])
        self.assertIn('step-9', decision['reason'])

    def test_rejects_missing_parent_context(self):
        receipt = self.receipt()
        raw = self.sign(receipt)
        decision = self.verify(raw, parent_sha=None)
        self.assertFalse(decision['ok'])
        self.assertIn('step-1', decision['reason'])

    def test_rejects_stale_and_future_dated_receipt(self):
        for offset in (-8 * 24 * 3600, 3600):
            with self.subTest(offset=offset):
                decision, _ = self.accepted(
                    lambda r, o=offset: r.update(observed_at=clock(o)))
                self.assertFalse(decision['ok'])
                self.assertIn('step-10', decision['reason'])

    def test_rejects_altered_hashes_and_unallowlisted_evidence(self):
        for mutate, expected in (
            (lambda r: r.update(outputs_sha256='1' * 64), 'step-11'),
            (lambda r: r.update(ansible_version='ansible [core 9.9.9]'), 'step-11'),
            (lambda r: r.update(evidence_refs=['tmp/leak/receipt.json']), 'step-11'),
        ):
            with self.subTest(expected=expected):
                decision, _ = self.accepted(mutate)
                self.assertFalse(decision['ok'])
                self.assertIn(expected, decision['reason'])

    def test_rejects_nonzero_rc_privileged_and_missing_commands(self):
        def recompute(receipt):
            captures = [{'id': c['id'], 'rc': c['rc'],
                         'stdout_sha256': c['stdout_sha256'],
                         'stderr_sha256': c['stderr_sha256']}
                        for c in receipt['commands']]
            receipt['outputs_sha256'] = sha256_bytes(canonical_bytes(captures))

        def change(index, **fields):
            def apply(receipt):
                receipt['commands'][index].update(fields)
                recompute(receipt)
            return apply

        def drop_second(receipt):
            receipt['commands'] = [receipt['commands'][0]]
            recompute(receipt)

        cases = (
            change(1, rc=1),
            change(0, sudo_required=True),
            change(0, owner_gate=True),
            drop_second,
            change(0, stdout_sha256=''),
        )
        for mutate in cases:
            with self.subTest():
                decision, _ = self.accepted(mutate)
                self.assertFalse(decision['ok'])
                self.assertIn('step-12', decision['reason'])

    def test_rejects_partial_owner_gate_and_false_tree_assertion(self):
        for mutate in (
            lambda r: r.update(result='partial'),
            lambda r: r.update(owner_gates=['vault-unlock']),
            lambda r: r['tree_assertion'].update(match=False),
        ):
            with self.subTest():
                decision, _ = self.accepted(mutate)
                self.assertFalse(decision['ok'])
                self.assertIn('step-13', decision['reason'])

    def test_reviewed_tree_excludes_the_evidence_path(self):
        self.assertNotEqual(self.head_tree, self.reviewed_tree)
        self.assertEqual(reviewed_tree_sha(self.entries, RECEIPT_PATH), self.reviewed_tree)

    def test_new_serialization_matches_git_and_binds_the_capture_manifest(self):
        with tempfile.TemporaryDirectory(dir=self.root) as tmp:
            checkout = Path(tmp)

            def git(*args):
                return subprocess.check_output(['git', '-C', str(checkout), *args]).strip()

            git('init', '-q', '--object-format=sha1')
            for name in ('tools/check', 'tools.txt', 'receipts/ansible-validate.json'):
                path = checkout / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('fixture\n')
            git('add', '.')
            full = git('write-tree').decode()
            entries = []
            for line in git('ls-tree', '-z', full).split(b'\0'):
                if line:
                    metadata, name = line.split(b'\t')
                    mode, kind, sha = metadata.decode().split()
                    entries.append(dict(path=name.decode(), mode=mode, type=kind, sha=sha))
            self.assertEqual(git_tree_sha(entries, schema=GIT_TREE_SCHEMA), full)
            self.assertNotEqual(git_tree_sha(entries), full)
            git('rm', '--cached', '-q', 'receipts/ansible-validate.json')
            reviewed = git('write-tree').decode()
            self.assertEqual(reviewed_tree_sha(entries, schema=GIT_TREE_SCHEMA), reviewed)

        receipt = self.receipt()
        reference = self.evd.replace('receipt.json', 'SHA256SUMS.captures')
        receipt.update(schema=GIT_TREE_SCHEMA, target_tree_sha=reviewed, evidence_refs=[reference])
        receipt['tree_assertion'].update(observed=reviewed, expected=reviewed)
        raw = self.sign(receipt)
        accepted = self.verify(raw, head_tree_sha=full, head_tree_entries=entries)
        self.assertTrue(accepted['ok'], accepted['reason'])
        self.assertIn(f'receipt_schema={GIT_TREE_SCHEMA}', accepted['text'])
        self.assertIn(f'receipt_ref={reference}', accepted['text'])
        self.assertEqual(self.verify(raw, head_tree_sha='0' * 40, head_tree_entries=entries)['reason'],
                         'step-8:head-tree-mismatch')
        receipt['evidence_refs'] = [self.evd]
        invalid = self.verify(self.sign(receipt), head_tree_sha=full, head_tree_entries=entries)
        self.assertEqual(invalid['reason'], 'step-11:canonical-evidence-ref-required')

if __name__ == '__main__':
    unittest.main()
