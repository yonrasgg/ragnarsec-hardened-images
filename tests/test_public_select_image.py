"""tools/select_image.py: infer the single catalog image a change request touches."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sel = load('select_image')
CATALOG = load('image_ci').catalog()


class SelectImage(unittest.TestCase):
    def test_explicit_parameter_wins(self):
        self.assertEqual(sel.select('ragnarsec-nginx', ['nginx-proxy-manager/Dockerfile'], CATALOG),
                         ('ragnarsec-nginx', 'explicit'))

    def test_explicit_unknown_image_fails(self):
        with self.assertRaisesRegex(ValueError, 'unknown-image:ragnarsec-nope'):
            sel.select('ragnarsec-nope', [], CATALOG)

    def test_single_recipe_is_inferred_from_any_file_in_its_context(self):
        paths = ['nginx-proxy-manager/layout.cjs', 'nginx-proxy-manager/README.md',
                 'tests/ragnarsec-nginx-proxy-manager.yaml']
        self.assertEqual(sel.select('', paths, CATALOG), ('ragnarsec-nginx-proxy-manager', 'inferred-from-diff'))

    def test_two_recipes_in_one_change_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'multiple-images-changed:ragnarsec-nginx,ragnarsec-nginx-proxy-manager'):
            sel.select('', ['nginx/Dockerfile', 'nginx-proxy-manager/start.sh'], CATALOG)

    def test_shared_only_change_falls_back_to_smallest_base(self):
        self.assertEqual(sel.select('', ['tools/image_ci.py', 'Jenkinsfile', 'tests/test_public_ci.py'], CATALOG),
                         ('ragnarsec-base-min', 'fallback-shared-change'))

    def test_fallback_image_exists_in_catalog(self):
        self.assertIn(sel.FALLBACK_IMAGE, CATALOG)

    def test_nested_plane_context_maps_to_plane_image(self):
        plane = [n for n in CATALOG if n.startswith('ragnarsec-plane-')]
        if not plane:
            self.skipTest('no plane/ recipes in catalog')
        name = plane[0]
        ctx = CATALOG[name]['dockerfile'].rsplit('/', 1)[0]
        self.assertEqual(sel.select('', [ctx + '/Dockerfile'], CATALOG), (name, 'inferred-from-diff'))


if __name__ == '__main__':
    unittest.main()