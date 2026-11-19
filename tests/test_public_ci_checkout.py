"""Static contract for the explicit, agent-scoped Jenkins checkout."""
from pathlib import Path
import re
import unittest


class CheckoutContract(unittest.TestCase):
    def test_explicit_scm_checkout_precedes_provenance(self):
        pipeline = (Path(__file__).resolve().parents[1] / "Jenkinsfile").read_text()
        self.assertRegex(pipeline, r"options\s*\{\s*skipDefaultCheckout\(\)")
        entry = re.search(
            r"stages\s*\{\s*stage\('Checkout SCM'\)\s*\{\s*steps\s*\{\s*"
            r"checkout scm\s*\}\s*\}\s*stage\('Provenance'\)",
            pipeline,
        )
        self.assertIsNotNone(entry)

    def test_20261119_staging_sync_pins_route_and_single_parent(self):
        pipeline = (Path(__file__).resolve().parents[1] / "Jenkinsfile").read_text()
        branch = 'elif [ "$source" = "sync/development-to-staging-exact-20261119" ]; then'
        self.assertEqual(pipeline.count(branch), 1)
        lane = pipeline.split(branch, 1)[1].split("\n                else", 1)[0]
        self.assertIn("staging_tip=96e2cba1a818751d827ddda9397b8f14995c2c91", lane)
        self.assertIn('require_one_time_sync "$head" staging "$staging_tip" development', lane)
        self.assertIn(
            'test "$(git rev-list --parents -n 1 "$head")" = "$head $staging_tip"',
            lane,
        )
        self.assertIn('exit 2', lane)
