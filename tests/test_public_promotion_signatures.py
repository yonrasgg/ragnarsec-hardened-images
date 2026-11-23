"""A verified head does not excuse an unsigned commit in its incoming range."""
import unittest

from tools.promotion_signatures import Blocked, verify


HEAD, BASE, OTHER = ('1' * 40, '2' * 40, '3' * 40)


class PromotionSignatures(unittest.TestCase):
    def run_gate(self, *, unsigned=None, move=False, missing=False):
        reads = 0

        def api(path):
            nonlocal reads
            if path == 'git/ref/heads/fix/signed':
                reads += 1
                return {'object': {'sha': OTHER if move and reads > 1 else HEAD}}
            if path == 'git/ref/heads/staging':
                return {'object': {'sha': BASE}}
            sha = path.split('/')[-1]
            sig = None if missing else {'verified': sha != unsigned,
                                        'reason': 'unsigned' if sha == unsigned else 'valid'}
            return {'sha': sha, 'commit': {'verification': sig}}

        return verify('.', 'fix/signed', 'staging', HEAD, BASE, api=api,
                      incoming=lambda repo, base, head: [HEAD, OTHER])

    def test_pass_requires_every_incoming_commit_verified(self):
        self.assertEqual(self.run_gate(), [HEAD, OTHER])

    def test_unsigned_head_or_ancestor_blocks(self):
        for sha in (HEAD, OTHER):
            with self.subTest(sha=sha), self.assertRaisesRegex(Blocked, 'did not verify signature'):
                self.run_gate(unsigned=sha)

    def test_missing_verification_blocks(self):
        with self.assertRaisesRegex(Blocked, 'did not verify signature'):
            self.run_gate(missing=True)

    def test_branch_movement_after_checks_blocks(self):
        with self.assertRaisesRegex(Blocked, 'branch changed'):
            self.run_gate(move=True)


if __name__ == '__main__':
    unittest.main()
