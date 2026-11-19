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
