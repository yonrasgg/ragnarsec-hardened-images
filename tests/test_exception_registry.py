import datetime
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
TODAY = datetime.date(2026, 11, 10)


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


policy = load('image_policy')

ENTRY = {
    'image': 'ragnarsec-python-pdf',
    'cve': 'CVE-2026-12345',
    'justification': 'not reachable in the shipped entrypoint',
    'owner': 'geovanny',
    'expires': '2027-01-15',
    'evidence': 'vex/ragnarsec-python-pdf.openvex.json',
}


class ExceptionRegistryTest(unittest.TestCase):
    def write(self, entries):
        handle = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False)
        json.dump({'exceptions': entries}, handle)
        handle.close()
        self.addCleanup(Path(handle.name).unlink)
        return Path(handle.name)

    def test_valid_exception_passes(self):
        self.assertEqual(policy.check_exceptions(self.write([ENTRY]), today=TODAY), [])

    def test_expired_exception_fails(self):
        bad = dict(ENTRY, expires='2026-11-09')
        self.assertIn('exception-expired:CVE-2026-12345',
                      policy.check_exceptions(self.write([bad]), today=TODAY))

    def test_missing_field_fails(self):
        bad = dict(ENTRY)
        bad.pop('owner')
        problems = policy.check_exceptions(self.write([bad]), today=TODAY)
        self.assertTrue(any(p.startswith('exception-missing-field:CVE-2026-12345:') for p in problems))

    def test_long_expiry_fails(self):
        bad = dict(ENTRY, expires='2027-06-01')
        self.assertIn('exception-too-long:CVE-2026-12345',
                      policy.check_exceptions(self.write([bad]), today=TODAY))

    def test_duplicate_fails(self):
        self.assertIn('exception-duplicate:CVE-2026-12345',
                      policy.check_exceptions(self.write([ENTRY, ENTRY]), today=TODAY))

    def test_missing_registry_means_no_enforcement(self):
        self.assertEqual(policy.check_exceptions(Path('/nonexistent/exceptions.json'), today=TODAY), [])

    def test_invalid_registry_fails(self):
        bad = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False)
        bad.write('{not json')
        bad.close()
        self.addCleanup(Path(bad.name).unlink)
        self.assertEqual(policy.check_exceptions(Path(bad.name), today=TODAY),
                         ['exception-registry-invalid'])

    def test_unregistered_vex_statement_fails(self):
        vex = tempfile.NamedTemporaryFile('w', suffix='.openvex.json', delete=False)
        json.dump({'statements': [{'vulnerability': {'name': 'CVE-2026-77777'}}]}, vex)
        vex.close()
        self.addCleanup(Path(vex.name).unlink)
        registry = self.write([])
        self.assertEqual(policy.unregistered_vex_statements(vex.name, registry), ['CVE-2026-77777'])

    def test_registered_vex_statement_passes(self):
        vex = tempfile.NamedTemporaryFile('w', suffix='.openvex.json', delete=False)
        json.dump({'statements': [{'vulnerability': {'name': ENTRY['cve']}}]}, vex)
        vex.close()
        # El nombre del archivo define la imagen; debe coincidir con la entrada.
        named = Path(vex.name).with_name('ragnarsec-python-pdf.openvex.json')
        Path(vex.name).rename(named)
        self.addCleanup(named.unlink)
        self.assertEqual(policy.unregistered_vex_statements(named, self.write([ENTRY])), [])


if __name__ == '__main__':
    unittest.main()
