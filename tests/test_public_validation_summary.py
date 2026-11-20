"""tools/validation_summary.py: deterministic reviewer summary from validation receipts."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vs = load('validation_summary')

LOG = """\
IMAGE_LAYER_BYTES ragnarsec-base-min linux/amd64 7340032
POLICY_WARN ragnarsec-demo no-healthcheck,root-user
Total: 3 (HIGH: 0, CRITICAL: 0)
Total: 0 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0)
"""


def fixture(tmp):
    out = Path(tmp) / 'validation'
    out.mkdir()
    sbom = out / 'ragnarsec-base-min.amd64.cdx.json'
    sbom.write_text(json.dumps({'components': [{'name': 'musl'}, {'name': 'busybox'}]}))
    receipts = [{'ref': 'ghcr.io/x/ragnarsec-base-min:t-amd64', 'name': 'ragnarsec-base-min',
                 'platform': 'linux/amd64', 'id': 'sha256:' + 'a' * 64, 'sbom': sbom.name,
                 'sbom_sha256': hashlib.sha256(sbom.read_bytes()).hexdigest()}]
    (out / 'validated.json').write_text(json.dumps(receipts))
    return out


class ValidationSummary(unittest.TestCase):
    def test_parses_sizes_warnings_and_trivy_totals(self):
        facts = vs.parse_log(LOG)
        self.assertEqual(facts['layer_bytes'][('ragnarsec-base-min', 'linux/amd64')], 7340032)
        self.assertEqual(facts['policy_warnings'], [{'image': 'ragnarsec-demo', 'problems': ['no-healthcheck', 'root-user']}])
        self.assertEqual((facts['trivy_tables'], facts['trivy_high'], facts['trivy_critical']), (2, 0, 0))

    def test_summary_checks_sbom_hash_and_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = fixture(tmp)
            s = vs.build_summary(out, LOG, 'abc123def456789', 'staging',
                                 budgets={'ragnarsec-base-min': 10485760})
            self.assertTrue(s['all_sbom_hashes_ok'])
            row = s['rows'][0]
            self.assertEqual(row['sbom_components'], 2)
            self.assertEqual(row['budget_pct'], 70.0)
            self.assertEqual(s['platforms'], ['linux/amd64'])

    def test_tampered_sbom_is_reported_not_hidden(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = fixture(tmp)
            (out / 'ragnarsec-base-min.amd64.cdx.json').write_text('{"components": []}')
            s = vs.build_summary(out, LOG, 'abc123def456789', 'staging', budgets={})
            self.assertFalse(s['all_sbom_hashes_ok'])
            self.assertIn('SBOM hashes match receipts: **NO**', vs.render_markdown(s))

    def test_markdown_is_deterministic_and_states_it_decides_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = fixture(tmp)
            s = vs.build_summary(out, LOG, 'abc123def456789', 'main', run_url='https://ci/job/1',
                                 budgets={'ragnarsec-base-min': 10485760})
            md1, md2 = vs.render_markdown(s), vs.render_markdown(s)
            self.assertEqual(md1, md2)
            self.assertIn('`abc123def456` -> `main`', md1)
            self.assertIn('| `ragnarsec-base-min` | `linux/amd64` | 7.0 MiB | 10.0 MiB (70.0%) | 2 |', md1)
            self.assertIn('does not merge, publish or waive anything', md1)
            self.assertIn('https://ci/job/1', md1)

    def test_trivy_high_or_critical_surface_in_headline(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = fixture(tmp)
            s = vs.build_summary(out, 'Total: 5 (HIGH: 3, CRITICAL: 2)\n', 'abc123def456789', 'staging', budgets={})
            self.assertIn('**3 / 2** over 1 result tables', vs.render_markdown(s))


if __name__ == '__main__':
    unittest.main()