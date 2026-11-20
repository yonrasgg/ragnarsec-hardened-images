"""Build-egress pre-flight: every host a recipe may contact must be declared in
tools/build-egress.json, mirroring the exact-host allowlist of the agents' Squid."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ci = load('image_ci')


class BuildEgressManifest(unittest.TestCase):
    def test_manifest_has_exact_hosts_only(self):
        manifest = json.loads((ROOT / 'tools' / 'build-egress.json').read_text())
        for host in manifest['allowed_hosts']:
            self.assertRegex(host, r'^[a-z0-9.-]+\.[a-z]{2,}$', host)
            self.assertNotIn('*', host)
        self.assertEqual(len(set(manifest['allowed_hosts'])), len(manifest['allowed_hosts']))

    def test_every_catalog_image_is_allowlisted(self):
        ci.check_build_egress(list(ci.catalog().values()))

    def test_npm_source_build_declares_its_origins(self):
        hosts = set(ci.build_egress_hosts(ci.catalog()['ragnarsec-nginx-proxy-manager']))
        for expected in ('codeload.github.com', 'raw.githubusercontent.com', 'openresty.org',
                         'registry.npmjs.org', 'registry.yarnpkg.com', 'pypi.org',
                         'files.pythonhosted.org', 'dl-cdn.alpinelinux.org'):
            self.assertIn(expected, hosts)

    def test_unlisted_origin_fails_plan_before_any_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'demo').mkdir()
            (root / 'demo' / 'Dockerfile').write_text(
                'FROM alpine:3.24.3@sha256:' + 'a' * 64 + '\n'
                'COPY fetch.sh ./\nRUN sh fetch.sh\n')
            (root / 'demo' / 'fetch.sh').write_text(
                'curl --fail https://example.invalid/pkg.tgz -o pkg.tgz\n')
            image = {'name': 'ragnarsec-demo', 'context': 'demo', 'dockerfile': 'demo/Dockerfile', 'parents': []}
            with patch.object(ci, 'ROOT', root), \
                    patch.object(ci, 'EGRESS_MANIFEST', ROOT / 'tools' / 'build-egress.json'):
                hosts = ci.build_egress_hosts(image)
                self.assertIn('example.invalid', hosts)
                self.assertIn('dl-cdn.alpinelinux.org', hosts)  # implicit from alpine base
                with self.assertRaisesRegex(ValueError, r'build-egress-not-allowlisted:.*example\.invalid'):
                    ci.check_build_egress([image])

    def test_wildcard_in_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / 'build-egress.json'
            bad.write_text(json.dumps({'allowed_hosts': ['*.github.com'], 'implicit_by_base': {}}))
            with patch.object(ci, 'EGRESS_MANIFEST', bad):
                with self.assertRaisesRegex(ValueError, 'build-egress-manifest-requires-exact-hosts'):
                    ci.check_build_egress([])

    def test_plan_cli_runs_the_egress_gate(self):
        pipeline = (ROOT / 'tools' / 'image_ci.py').read_text()
        self.assertIn("check_build_egress(ordered)", pipeline.split("if args.action == 'plan':", 1)[1][:300])


if __name__ == '__main__':
    unittest.main()
