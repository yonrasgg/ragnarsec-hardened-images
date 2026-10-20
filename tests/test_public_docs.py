import unittest
import json
from pathlib import Path

ROOT = Path(__file__).parents[1]
HEADINGS = ('Purpose', 'Build inputs', 'Hardening declared', 'Patching', 'Controls and evidence', 'Using the image', 'License')

class DocumentationContractTests(unittest.TestCase):
    def test_every_service_readme_has_a_reusable_contract(self):
        paths = list(ROOT.glob('*/README.md'))
        self.assertGreater(len(paths), 15)
        for path in paths:
            if not (path.parent / 'Dockerfile').is_file():
                continue
            text = path.read_text()
            for title in HEADINGS:
                self.assertIn('## ' + title, text, path.as_posix())

    def test_no_deployment_architecture_heading_or_diagram(self):
        for path in ROOT.rglob('*.md'):
            if '.git' in path.parts:
                continue
            text = path.read_text()
            self.assertNotIn('## Architecture', text)
            self.assertNotIn('```mermaid', text)
            self.assertNotIn('┌', text)

    def test_definitions_do_not_masquerade_as_image_passes(self):
        for path in ROOT.glob('*/README.md'):
            if (path.parent / 'Dockerfile').is_file():
                self.assertIn('No built-image pass', path.read_text())
        self.assertIn('Definitions are not proof', (ROOT / 'README.md').read_text())

    def test_controls_enforce_the_document_tests_too(self):
        for name in ['.githooks/pre-commit', 'Jenkinsfile']:
            self.assertIn('test_public*.py', (ROOT / name).read_text())

    def test_dependency_schedule_uses_a_neutral_timezone(self):
        config = json.loads((ROOT / 'renovate.json').read_text())
        self.assertEqual(config['timezone'], 'Etc/UTC')

    def test_branch_model_is_documented(self):
        for name in ('README.md', 'CONTRIBUTING.md'):
            text = (ROOT / name).read_text()
            for branch in ('development', 'staging', 'main'):
                self.assertIn(branch, text)
            self.assertNotIn('ci/bootstrap', text)
        self.assertNotIn('ci/bootstrap', (ROOT / 'Jenkinsfile').read_text())

    def test_promotion_order_is_fixed_and_failures_return_to_sender(self):
        text = ' '.join((ROOT / 'CONTRIBUTING.md').read_text().split())
        self.assertIn('`main` | Repository default and release', text)
        self.assertIn('`development` -> `staging` -> `main`', text)
        self.assertIn('never skipped', text)
        self.assertIn('closed unmerged and returned to the sender', text)
        self.assertIn('Squash, fast-forward or rebase', text)
        self.assertNotIn('fast-forward from `staging` only', text)
        self.assertNotIn('fast-forward from `development` only', text)
        readme = ' '.join((ROOT / 'README.md').read_text().split())
        self.assertIn('`main` is the repository default branch', readme)

if __name__ == '__main__':
    unittest.main()
