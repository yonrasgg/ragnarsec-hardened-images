"""Offline contract for normalized promotion evidence. No network or merge calls."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import promotion_evidence as gate


class PromotionEvidence(unittest.TestCase):
    def setUp(self):
        self.binding = {
            'repository_id': 1426336836, 'pull_request': 7,
            'head_sha': 'a' * 40, 'base_sha': 'b' * 40,
            'candidate_sha': 'c' * 40, 'policy_sha': 'd' * 40,
        }
        self.live = dict(self.binding, source_repo_id=1426336836, source='staging',
                         target='main', state='open', draft=False)
        self.plan = {'nginx-proxy-manager': ['nginx-proxy-manager'],
                     'prometheus': ['base', 'prometheus']}
        self.checks = dict(binding=self.binding, app_id=5736684, source='success',
                           contract='success', secrets='success')
        self.receipts = [self.receipt(lane, index) for index, lane in enumerate(self.plan, 1)]

    def receipt(self, lane, index):
        return dict(binding=self.binding, app_id=5736684, lane=lane, run_id=index,
                    result='success', publish=False, summary_sha256='1' * 64,
                    rows=[dict(image=image, platform=platform, scan_enforced=True,
                               sbom_hash_ok=True, sbom_sha256='2' * 64)
                          for image in self.plan[lane] for platform in ('linux/amd64', 'linux/arm64')])

    def evaluate(self):
        return gate.evaluate(self.binding, self.live, self.plan, self.checks, self.receipts)

    def blocked(self, reason):
        self.assertEqual(self.evaluate(), {'ready': False, 'reason': reason, 'merge_authorized': False})

    def test_both_lanes_and_both_platforms_are_ready_for_review_only(self):
        self.assertEqual(self.evaluate(), {'ready': True, 'reason': 'complete-evidence',
                                           'merge_authorized': False})

    def test_one_green_of_two_does_not_pass(self):
        self.receipts.pop()
        self.blocked('incomplete-image-plan')

    def test_live_head_or_base_advancing_invalidates_the_candidate(self):
        for key in ('head_sha', 'base_sha', 'candidate_sha', 'policy_sha'):
            with self.subTest(key=key):
                self.live[key] = 'e' * 40
                self.blocked('live-binding-mismatch')
                self.live[key] = self.binding[key]

    def test_historical_green_on_same_head_other_base_is_rejected(self):
        self.receipts[0]['binding'] = dict(self.binding, base_sha='f' * 40)
        self.blocked('receipt-binding-mismatch')

    def test_prior_candidate_or_other_pr_cannot_supply_receipt(self):
        for change in ({'candidate_sha': 'f' * 40}, {'pull_request': 8}, {'head_sha': 'f' * 40}):
            with self.subTest(change=change):
                self.receipts[0]['binding'] = dict(self.binding, **change)
                self.blocked('receipt-binding-mismatch')

    def test_emitter_and_terminal_state_are_required_in_every_lane(self):
        for key, value in (('app_id', 27), ('result', 'pending'), ('result', 'neutral'),
                           ('publish', True), ('publish', 0), ('summary_sha256', '123')):
            with self.subTest(key=key, value=value):
                before = copy.copy(self.receipts[0])
                self.receipts[0][key] = value
                self.blocked('unverified-image-receipt')
                self.receipts[0] = before

    def test_wrong_target_fork_or_draft_is_not_eligible(self):
        for key, value in (('source', 'feature'), ('target', 'staging'), ('source_repo_id', 1),
                           ('state', 'closed'), ('draft', True)):
            with self.subTest(key=key):
                before = self.live[key]
                self.live[key] = value
                self.blocked('unsupported-promotion')
                self.live[key] = before

    def test_scan_and_verified_sbom_are_required_in_every_row(self):
        for key, value in (('scan_enforced', False), ('sbom_hash_ok', False),
                           ('sbom_sha256', 'x' * 64), ('platform', 'linux/s390x')):
            with self.subTest(key=key):
                row = self.receipts[0]['rows'][0]
                before = row[key]
                row[key] = value
                self.blocked('unverified-platform-receipt')
                row[key] = before

    def test_missing_or_duplicate_platform_never_completes_lane(self):
        self.receipts[1]['rows'].pop()
        self.blocked('incomplete-platform-receipts')
        self.receipts[1]['rows'].append(self.receipts[1]['rows'][0])
        self.blocked('duplicate-platform-receipt')

    def test_unknown_or_duplicate_lanes_and_shared_run_ids_block(self):
        duplicate = copy.deepcopy(self.receipts)
        self.receipts.append(duplicate[0])
        self.blocked('duplicate-image-receipt')
        self.receipts = duplicate
        self.receipts[1]['run_id'] = self.receipts[0]['run_id']
        self.blocked('duplicate-image-receipt')
        self.receipts[1]['run_id'] = 2
        self.receipts[1]['lane'] = 'not-planned'
        self.blocked('unexpected-image-receipt')

    def test_empty_image_plan_needs_bound_successful_control_checks(self):
        self.plan = {}
        self.receipts = []
        self.assertTrue(self.evaluate()['ready'])
        self.checks['contract'] = 'pending'
        self.blocked('unverified-control-checks')
        self.checks['contract'] = 'success'
        self.checks['binding'] = dict(self.binding, base_sha='f' * 40)
        self.blocked('unverified-control-checks')

    def test_invalid_input_is_fail_closed(self):
        self.plan = {'prometheus': []}
        self.blocked('invalid-image-plan')
        self.plan = {'prometheus': ['prometheus', 'prometheus']}
        self.blocked('invalid-image-plan')
        self.plan = {'prometheus': ['base']}
        self.blocked('invalid-image-plan')
        self.binding['base_sha'] = False
        self.blocked('invalid-reviewed-binding')


if __name__ == '__main__':
    unittest.main()
