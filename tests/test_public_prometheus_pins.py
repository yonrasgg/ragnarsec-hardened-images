"""Keep the Prometheus recipe aligned with its reviewed Alpine package manifest."""
import json
from pathlib import Path
import re
import shlex
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import image_policy as policy


class PrometheusPins(unittest.TestCase):
    def setUp(self):
        self.dockerfile = ROOT / 'prometheus/Dockerfile'
        self.instructions = list(policy._logical_instructions(self.dockerfile.read_text()))
        self.versions = json.loads((ROOT / 'versions.json').read_text())

    def test_install_matches_reviewed_pins_including_inherited_security_packages(self):
        installed = re.findall(r'\bapk\s+add\s+--no-cache\s+([^&;]+)',
                               ' '.join(line for line in self.instructions if line.startswith('RUN ')))
        self.assertEqual(len(installed), 1)
        tokens = shlex.split(installed[0])
        self.assertTrue(all('=' in token for token in tokens), tokens)
        packages = dict(token.split('=', 1) for token in tokens)
        self.assertEqual(len(tokens), len(packages))
        self.assertEqual(set(packages), {'prometheus', 'libcrypto3', 'libssl3', 'zlib', 'apk-tools', 'libapk'})
        self.assertEqual(packages, self.versions['ragnarsec-prometheus']['packages'])
        self.assertEqual(packages['apk-tools'], packages['libapk'])
        self.assertEqual(packages['libcrypto3'], packages['libssl3'])

    def test_recipe_has_no_unreviewed_upgrade_or_child_entrypoint(self):
        self.assertNotRegex('\n'.join(self.instructions), r'\bapk\s+upgrade\b')
        self.assertFalse(any(line.startswith('ENTRYPOINT ') for line in self.instructions))
        self.assertNotIn('hadolint ignore=DL3018', self.dockerfile.read_text())


if __name__ == '__main__':
    unittest.main()
