"""Regression contracts for the reviewed nginx recipe and configuration."""
import json
from pathlib import Path
import re
import shlex
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import image_policy as policy


class NginxHardening(unittest.TestCase):
    def test_nginx_dockerfile_is_policy_clean(self):
        self.assertEqual(policy.check_dockerfile(ROOT / 'nginx/Dockerfile'), [])

    def test_nginx_policy_is_enforced_not_advisory(self):
        config = json.loads((ROOT / 'policy.json').read_text())
        self.assertIn('ragnarsec-nginx', config['enforce'])

    def test_nginx_direct_packages_match_version_manifest(self):
        versions = json.loads((ROOT / 'versions.json').read_text())
        self.assertIn('ragnarsec-nginx', versions)
        expected = versions['ragnarsec-nginx']['packages']
        self.assertEqual(set(expected), {'nginx', 'openssl', 'pcre2'})
        dockerfile = (ROOT / 'nginx/Dockerfile').read_text()
        instructions = ' '.join(policy._logical_instructions(dockerfile))
        installs = re.findall(r'\bapk\s+add\s+--no-cache\s+([^&;]+?)(?=\s+(?:RUN|COPY|USER|EXPOSE|CMD)\b|$)',
                              instructions)
        self.assertEqual(len(installs), 1)
        tokens = shlex.split(installs[0])
        self.assertTrue(all('=' in token for token in tokens), tokens)
        self.assertEqual(dict(token.split('=', 1) for token in tokens), expected)

    def test_nginx_does_not_suppress_package_pin_lint(self):
        dockerfile = (ROOT / 'nginx/Dockerfile').read_text()
        self.assertNotIn('hadolint ignore=DL3018', dockerfile)

    def test_http2_uses_supported_separate_directive(self):
        config = (ROOT / 'nginx/conf/conf.d/ragnarsec.conf').read_text()
        self.assertRegex(config, r'(?m)^\s*listen\s+8443\s+ssl\s*;')
        self.assertRegex(config, r'(?m)^\s*http2\s+on\s*;')
        self.assertNotRegex(config, r'(?m)^\s*listen\s+[^;]*\bhttp2\b')

    def test_tls_protocol_floor_is_preserved(self):
        config = (ROOT / 'nginx/conf/conf.d/ragnarsec.conf').read_text()
        self.assertIn('ssl_protocols TLSv1.2 TLSv1.3;', config)

    def test_runtime_config_check_rejects_deprecation_warnings(self):
        tests = (ROOT / 'tests/ragnarsec-nginx.yaml').read_text()
        config_test = tests.split("- name: 'Nginx Config Test'", 1)[1]
        self.assertIn("excludedError: ['deprecated']", config_test)


if __name__ == '__main__':
    unittest.main()
