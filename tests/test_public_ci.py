import gzip
import hashlib
import importlib.util
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

# Publication subprocesses are mocked here; the key gate has separate tests.
def setUpModule():
    guard = patch("release_signing_guard.verify_signing_key")
    guard.start()
    unittest.addModuleCleanup(guard.stop)


MIGRATED = (
    'promotion-route-preflight.yml',
    'check-promotion-candidate.yml',
    'prepare-staging-draft.yml',
    # CI-004 corrective: untrusted half of the automatic-draft split.
    'staging-draft-merge-trigger.yml',
    'publish-ansible-check.yml',
)


ROOT = Path(__file__).parents[1]
def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT/'tools'/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
ci, install = load('image_ci'), load('install_ci_tools')
policy = load('image_policy')

class NpmRuntimeSbom(unittest.TestCase):
    def _verify(self, valid):
        snapshot = {'metadata': {'component': {'bom-ref': 'image'}},
                    'components': [], 'dependencies': [{'ref': 'image', 'dependsOn': []}]}
        source = json.loads((ROOT / 'nginx-proxy-manager/runtime-components.json').read_text())
        paths = [component['path'] for component in source]
        digest = 'a' * 64
        output = ''.join(f'{digest}  {p}\n' for p in (paths if valid else paths[:-1]))
        with tempfile.TemporaryDirectory() as tmp:
            sbom = Path(tmp) / 'sbom.cdx.json'
            sbom.write_text(json.dumps(snapshot))
            with patch.object(ci, 'command', return_value=SimpleNamespace(stdout=output)):
                if not valid:
                    with self.assertRaisesRegex(ValueError, 'incomplete-npm-component-hashes'):
                        ci.add_npm_runtime_components('sha256:' + digest, sbom)
                    self.assertEqual(json.loads(sbom.read_text()), snapshot)
                    return
                ci.add_npm_runtime_components('sha256:' + digest, sbom)
            document = json.loads(sbom.read_text())
            self.assertEqual(len(document['components']), 4)
            for component in document['components']:
                self.assertIn(component['bom-ref'], document['dependencies'][0]['dependsOn'])
                self.assertEqual(component['hashes'], [{'alg': 'SHA-256', 'content': digest}])

    def test_npm_declared_binaries_are_linked_to_exact_image_sbom(self):
        self._verify(valid=True)

    def test_npm_missing_binary_fails_without_writing_partial_sbom(self):
        self._verify(valid=False)


class ImageSizeBudget(unittest.TestCase):
    def archive(self, path, layer, *, compressed, diff_id=None, arch='arm64'):
        digest = diff_id or 'sha256:' + hashlib.sha256(layer).hexdigest()
        manifest = [{'Config': 'config.json', 'Layers': ['layer.tar']}]
        config = {'os': 'linux', 'architecture': arch,
                  'rootfs': {'type': 'layers', 'diff_ids': [digest]}}
        with tarfile.open(path, 'w') as tar:
            for name, data in (
                ('manifest.json', json.dumps(manifest).encode()),
                ('config.json', json.dumps(config).encode()),
                ('layer.tar', gzip.compress(layer) if compressed else layer),
            ):
                member = tarfile.TarInfo(name)
                member.size = len(data)
                tar.addfile(member, io.BytesIO(data))

    def test_same_layer_bytes_for_compressed_and_plain_exports(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'image.tar'
            layer = b'layer contents' * 8192
            for compressed in (False, True):
                with self.subTest(compressed=compressed):
                    self.archive(path, layer, compressed=compressed)
                    with path.open('rb') as f:
                        self.assertEqual(ci.archive_layer_bytes(f, 'linux/arm64'), len(layer))

    def test_rejects_mismatched_image_platform_or_layer_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'image.tar'
            for options, error in (
                ({'arch': 'amd64'}, 'budget-image-platform-mismatch'),
                ({'diff_id': 'sha256:' + '0' * 64}, 'budget-layer-digest-mismatch'),
            ):
                with self.subTest(error=error):
                    self.archive(path, b'layer', compressed=True, **options)
                    with path.open('rb') as f, self.assertRaisesRegex(ValueError, error):
                        ci.archive_layer_bytes(f, 'linux/arm64')


class ImagePlanning(unittest.TestCase):
    def test_foreign_platform_uses_qemu_registration_name(self):
        with patch.object(ci.os, 'uname', return_value=type('Uname', (), {'machine': 'x86_64'})()), \
             patch.object(ci.Path, 'exists', autospec=True,
                          side_effect=lambda path: path.name == 'qemu-aarch64'):
            ci.require_platforms_available(['linux/arm64'])

    def test_aarch64_uses_native_platform_without_binfmt(self):
        with patch.object(ci.os, 'uname', return_value=type('Uname', (), {'machine': 'aarch64'})()), \
             patch.object(ci.Path, 'exists', side_effect=AssertionError('binfmt checked')):
            ci.require_platforms_available(['linux/arm64'])
            for targets in (['linux/amd64'], ['linux/arm64', 'linux/amd64']):
                with self.assertRaisesRegex(ValueError, 'native-arm64-runner-requires-linux-arm64'):
                    ci.require_platforms_available(targets)

    def test_foreign_platform_without_handler_fails(self):
        with patch.object(ci.os, 'uname', return_value=type('Uname', (), {'machine': 'x86_64'})()), \
             patch.object(ci.Path, 'exists', return_value=False):
            with self.assertRaisesRegex(ValueError, 'platform-not-native-and-not-emulated:linux/arm64'):
                ci.require_platforms_available(['linux/arm64'])

    def test_native_platform_needs_no_qemu_handler(self):
        with patch.object(ci.os, 'uname', return_value=type('Uname', (), {'machine': 'x86_64'})()), \
             patch.object(ci.Path, 'exists', side_effect=AssertionError('native checked binfmt')):
            ci.require_platforms_available(['linux/amd64'])

    def test_all_recipes_and_multistage_parents_have_closed_plans(self):
        images = ci.catalog()
        self.assertEqual(len(images),24)
        self.assertNotIn('ragnarsec-zap', images)
        for selected in images:
            seen = set()
            for image in ci.plan(selected):
                self.assertTrue(set(image['parents']) <= seen)
                self.assertNotIn(image['name'],seen)
                self.assertTrue((ROOT/'tests'/(image['name']+'.yaml')).is_file())
                seen.add(image['name'])
            self.assertEqual(ci.plan(selected)[-1]['name'],selected)
    def test_standalone_does_not_rebuild_base(self):
        self.assertEqual([x['name'] for x in ci.plan('ragnarsec-postgres')],['ragnarsec-postgres'])
    def test_two_parent_recipe_deduplicates_ancestors(self):
        graph = {
            'ragnarsec-leaf': {'name': 'ragnarsec-leaf', 'parents': ['ragnarsec-left', 'ragnarsec-right']},
            'ragnarsec-left': {'name': 'ragnarsec-left', 'parents': ['ragnarsec-common']},
            'ragnarsec-right': {'name': 'ragnarsec-right', 'parents': ['ragnarsec-common']},
            'ragnarsec-common': {'name': 'ragnarsec-common', 'parents': []},
        }
        names = [x['name'] for x in ci.plan('ragnarsec-leaf', graph)]
        self.assertEqual(names, ['ragnarsec-common', 'ragnarsec-left', 'ragnarsec-right', 'ragnarsec-leaf'])
        self.assertEqual(len(names), len(set(names)))
    def test_unknown_or_injection_input_rejected(self):
        for name in ['all','../base','ragnarsec-base; echo bad']:
            with self.assertRaises(ValueError): ci.plan(name)
    def test_missing_parent_and_cycle_fail(self):
        for graph in [{'a':{'parents':['b']}},{'a':{'parents':['a']}}]:
            with self.assertRaises(ValueError): ci.plan('a',graph)
    def test_invalid_tag_never_starts_docker(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(ci,'command') as cmd:
            with self.assertRaises(ValueError): ci.validate('ragnarsec-base','../bad',Path(tmp)/'out')
            cmd.assert_not_called()
    def test_container_builder_rejected_before_parent_build(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.dict(ci.os.environ, {'PLATFORMS': 'linux/amd64'}), \
             patch.object(ci, 'require_platforms_available'), \
             patch.object(ci, 'command', return_value=subprocess.CompletedProcess(
                 [], 0, stdout='Name: remote\nDriver: docker-container\n')) as cmd:
            output = Path(tmp) / 'out'
            with self.assertRaisesRegex(ValueError, 'builder-must-use-docker-driver'):
                ci.validate('ragnarsec-alertmanager', 'test', output)
            self.assertFalse(output.exists())
            self.assertFalse(any(call.args[:3] == ('docker', 'buildx', 'build')
                                 for call in cmd.call_args_list))

    def test_docker_driver_allows_local_parent_workflow(self):
        with patch.object(ci, 'command', return_value=subprocess.CompletedProcess(
                [], 0, stdout='Name: default\nDriver: docker\n')) as cmd:
            ci.require_local_parent_builder()
            cmd.assert_called_once_with('docker', 'buildx', 'inspect', capture=True)

    def test_validation_builds_single_platform_manifests_without_buildx_attestations(self):
        for platform in ('linux/amd64', 'linux/arm64'):
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as tmp, \
                 patch.dict(ci.os.environ, {'PLATFORMS': platform,
                                             'RAGNARSEC_REQUIRE_STAGE_EGRESS': '1'}), \
                 patch.object(ci, 'build_proxy_args', return_value=()), \
                 patch.object(ci, 'require_platforms_available'), \
                 patch.object(ci, 'require_local_parent_builder'), \
                 patch.object(ci, 'image_layer_bytes', return_value=1024) as measure:
                output = Path(tmp) / 'validated'

                def fake(*args, capture=False):
                    if args[:3] == ('docker', 'image', 'inspect'):
                        self.assertEqual(args[3], '--format={{.Id}}')
                        return subprocess.CompletedProcess([], 0, stdout='sha256:local-image-id')
                    if args[:2] == ('trivy', 'image') and '--output' in args:
                        Path(args[args.index('--output') + 1]).write_text('{}')
                    return subprocess.CompletedProcess([], 0, stdout='')

                with patch.object(ci, 'command', side_effect=fake) as cmd:
                    ci.validate('ragnarsec-base', 'test', output)
                builds = [call.args for call in cmd.call_args_list
                          if call.args[:3] == ('docker', 'buildx', 'build')]
                self.assertEqual(len(builds), 1)
                measure.assert_called_once_with(builds[0][builds[0].index('-t') + 1], platform, output)
                self.assertEqual(builds[0][builds[0].index('--platform') + 1], platform)
                self.assertIn('--provenance=false', builds[0])
                self.assertIn('--sbom=false', builds[0])
                scans = [call.args for call in cmd.call_args_list
                          if call.args[:2] == ('trivy', 'image') and '--severity' in call.args]
                trivy_commands = [call.args for call in cmd.call_args_list
                                  if call.args[:2] == ('trivy', 'image')]
                self.assertEqual(len(trivy_commands), 3)
                for args in trivy_commands:
                    self.assertIn('--java-db-repository', args)
                    self.assertEqual(args[args.index('--java-db-repository') + 1],
                                     'ghcr.io/aquasecurity/trivy-java-db:1')
                self.assertEqual(len(scans), 1)
                self.assertEqual(scans[0][scans[0].index('--exit-on-eol') + 1], '1')
                structure_tests = [call.args for call in cmd.call_args_list
                                   if call.args[:2] == ('container-structure-test', 'test')]
                self.assertEqual(len(structure_tests), 1)
                self.assertEqual(
                    structure_tests[0][structure_tests[0].index('--platform') + 1],
                    platform)
                self.assertTrue((output / 'validated.json').is_file())

    def test_base_min_sbom_requires_only_shipped_apk_packages(self):
        expected = ci.BASE_MIN_APK_PACKAGES
        components = [{'name': 'alpine', 'version': '3.21.9'}] + [
            {'name': name, 'version': '1-r0',
             'purl': 'pkg:apk/alpine/' + name + '@1-r0?arch=x86_64&distro=3.21.9'}
            for name in sorted(expected)]
        with tempfile.TemporaryDirectory() as tmp:
            sbom = Path(tmp) / 'base-min.cdx.json'
            for records, rejected in (
                (components, False),
                ([c for c in components if c['name'] != 'musl'], True),
                (components + [{'name': 'apk-tools', 'version': '1-r0',
                                'purl': 'pkg:apk/alpine/apk-tools@1-r0'}], True),
                ([c for c in components if c['name'] != 'alpine'], True),
            ):
                with self.subTest(packages=[c['name'] for c in records]):
                    sbom.write_text(json.dumps({'components': records}))
                    if rejected:
                        with self.assertRaisesRegex(ValueError, 'base-min-sbom-package-inventory-mismatch'):
                            ci.require_base_min_inventory(sbom)
                    else:
                        ci.require_base_min_inventory(sbom)

    @patch.object(ci.os, 'uname', lambda: SimpleNamespace(machine='x86_64'))
    def test_failed_validation_never_writes_success_receipt(self):
        env = {'PLATFORMS': 'linux/amd64'}
        with tempfile.TemporaryDirectory() as tmp, patch.dict(ci.os.environ, env),                 patch.object(ci, 'command', side_effect=subprocess.CalledProcessError(1, 'hadolint')):
            p = Path(tmp) / 'out'
            with self.assertRaises(subprocess.CalledProcessError):
                ci.validate('ragnarsec-base', 'test', p)
            self.assertFalse((p / 'validated.json').exists())
    def test_publish_disabled_without_enablement(self):
        with patch.dict(ci.os.environ,{},clear=True),patch.object(ci,'command') as cmd:
            with self.assertRaises(ValueError): ci.publish('ragnarsec-base','test',Path('/not/read'))
            cmd.assert_not_called()
    def _receipt(self, repository, platform, image_id='expected'):
        suffix = 'arm64' if platform.endswith('arm64') else 'amd64'
        return {'ref': repository + ':test-' + suffix, 'name': 'ragnarsec-base',
                'platform': platform, 'id': image_id, 'sbom': 'sbom.json',
                'sbom_sha256': hashlib.sha256(b'{}').hexdigest()}

    @patch.object(ci.os, 'uname', lambda: SimpleNamespace(machine='x86_64'))
    def test_publication_rejects_receipt_with_wrong_tag_or_repository_before_push(self):
        repository = ci.REGISTRY + 'ragnarsec-base'
        for ref, tag in (
            (repository + ':validated-amd64', 'other'),
            ('ghcr.io/other/ragnarsec-base:test-amd64', 'test'),
        ):
            with self.subTest(ref=ref, tag=tag), tempfile.TemporaryDirectory() as tmp:
                p = Path(tmp)
                (p / 'cosign.key').write_text('key')
                (p / 'sbom.json').write_text('{}')
                receipt = self._receipt(repository, 'linux/amd64')
                receipt['ref'] = ref
                (p / 'validated.json').write_text(json.dumps([receipt]))

                def fake(*args, capture=False):
                    if args[:2] == ('cosign', 'public-key'):
                        Path(args[args.index('--outfile') + 1]).write_text('pub')
                    if args[:3] == ('docker', 'image', 'inspect'):
                        return subprocess.CompletedProcess([], 0, stdout='expected linux/amd64')
                    return subprocess.CompletedProcess([], 0, stdout='')

                env = {'PUBLICATION_ENABLED': 'true', 'COSIGN_KEY': str(p / 'cosign.key'),
                       'PLATFORMS': 'linux/amd64'}
                with patch.dict(ci.os.environ, env), patch.object(ci, 'command', side_effect=fake) as cmd:
                    with self.assertRaisesRegex(ValueError, 'validation-receipt-mismatch'):
                        ci.publish('ragnarsec-base', tag, p)
                    self.assertFalse(any(call.args[:2] == ('docker', 'push') for call in cmd.call_args_list))

    @patch.object(ci.os, 'uname', lambda: SimpleNamespace(machine='x86_64'))
    def test_tampered_image_never_pushed(self):
        repository = ci.REGISTRY + 'ragnarsec-base'
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'sbom.json').write_text('{}')
            (p / 'cosign.key').write_text('key')
            (p / 'validated.json').write_text(json.dumps([self._receipt(repository, 'linux/amd64')]))

            def fake(*args, capture=False):
                if args[:2] == ('cosign', 'public-key'):
                    Path(args[args.index('--outfile') + 1]).write_text('pub')
                    return subprocess.CompletedProcess([], 0, stdout='')
                if args[:3] == ('docker', 'image', 'inspect'):
                    return subprocess.CompletedProcess([], 0, stdout='changed')
                return subprocess.CompletedProcess([], 0, stdout='')

            env = {'PUBLICATION_ENABLED': 'true', 'COSIGN_KEY': str(p / 'cosign.key'),
                   'PLATFORMS': 'linux/amd64'}
            with patch.dict(ci.os.environ, env), patch.object(ci, 'command', side_effect=fake) as cmd:
                with self.assertRaisesRegex(ValueError, 'image-changed'):
                    ci.publish('ragnarsec-base', 'test', p)
                self.assertFalse(any(c.args[:2] == ('docker', 'push') for c in cmd.call_args_list))

    @patch.object(ci.os, 'uname', lambda: SimpleNamespace(machine='x86_64'))
    def test_publication_promotes_validated_images_and_signs_platforms(self):
        repository = ci.REGISTRY + 'ragnarsec-base'
        index_digest = 'sha256:' + 'a' * 64
        platform_digest = 'sha256:' + 'b' * 64
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'sbom.json').write_text('{}')
            (p / 'cosign.key').write_text('key')
            (p / 'validated.json').write_text(json.dumps([self._receipt(repository, 'linux/amd64')]))

            def fake(*args, capture=False):
                if args[:2] == ('cosign', 'public-key'):
                    Path(args[args.index('--outfile') + 1]).write_text('pub')
                    return subprocess.CompletedProcess([], 0, stdout='')
                if args[:3] == ('docker', 'image', 'inspect'):
                    if args[3].startswith('--format={{json .RepoDigests}}'):
                        return subprocess.CompletedProcess([], 0, stdout=json.dumps([repository + '@' + platform_digest]))
                    return subprocess.CompletedProcess([], 0, stdout='expected linux/amd64')
                if args[:4] == ('docker', 'buildx', 'imagetools', 'inspect'):
                    manifest = {'digest': index_digest,
                                'manifests': [{'platform': {'os': 'linux', 'architecture': 'amd64'},
                                               'digest': platform_digest}]}
                    return subprocess.CompletedProcess([], 0, stdout=json.dumps(manifest))
                return subprocess.CompletedProcess([], 0, stdout='')

            env = {'PUBLICATION_ENABLED': 'true', 'COSIGN_KEY': str(p / 'cosign.key'),
                   'PLATFORMS': 'linux/amd64'}
            with patch.dict(ci.os.environ, env), patch.object(ci, 'command', side_effect=fake) as cmd:
                ci.publish('ragnarsec-base', 'test', p)

            calls = [c.args for c in cmd.call_args_list]
            self.assertFalse(any(a[:3] == ('docker', 'buildx', 'build') for a in calls))
            self.assertTrue(any(a[:2] == ('docker', 'push') for a in calls))
            signed = [a[-1] for a in calls if a[:2] == ('cosign', 'sign')]
            self.assertIn(repository + '@' + platform_digest, signed)
            self.assertIn(repository + '@' + index_digest, signed)
            for a in calls:
                if a[:2] in (('cosign', 'sign'), ('cosign', 'attest')):
                    self.assertEqual(a[a.index('--key') + 1], str(p / 'cosign.key'))

class VexPolicy(unittest.TestCase):
    def _valid(self):
        return {
            '@context': 'https://openvex.dev/ns/v0.2.0',
            '@id': 'https://github.com/yonrasgg/ragnarsec-hardened-images/vex/test',
            'author': 'RagnarSec',
            'timestamp': '2026-11-03T00:00:00Z',
            'version': 1,
            'statements': [{
                'vulnerability': {'name': 'CVE-2025-47273'},
                'products': [{'@id': 'pkg:pypi/setuptools@70.3.0'}],
                'status': 'not_affected',
                'justification': 'vulnerable_code_not_present',
                'impact_statement': 'Only pkg_resources is vendored; the vulnerable module is absent.',
            }],
        }

    def test_repository_vex_files_match_catalog_images(self):
        files = sorted((ROOT / 'vex').glob('*.openvex.json'))
        self.assertTrue(files)
        images = ci.catalog()
        for path in files:
            name = path.name.removesuffix('.openvex.json')
            with self.subTest(path=path.name):
                self.assertIn(name, images)
                ci.require_vex(path)

    def test_accepts_scoped_exact_npm_product(self):
        doc = self._valid()
        doc['statements'][0]['products'][0]['@id'] = 'pkg:npm/%40npmcli/arborist@7.0.0'
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'ragnarsec-builder.openvex.json'
            path.write_text(json.dumps(doc))
            ci.require_vex(path)

    def test_python_base_guard_rejects_non_vendored_setuptools_70(self):
        config = (ROOT / 'tests' / 'ragnarsec-python-base.yaml').read_text()
        self.assertIn('setuptools-70.3.0.dist-info', config)
        self.assertIn('setuptools-70.3.0.egg-info', config)
        self.assertIn('pip/_vendor', config)
        self.assertIn('package_index.py', config)
        self.assertIn('setuptools==70.3.0', config)

    def test_vex_rejects_unscoped_or_incomplete_statements(self):
        cases = {
            'empty-statements': lambda d: d.update(statements=[]),
            'missing-author': lambda d: d.pop('author'),
            'bad-timestamp': lambda d: d.update(timestamp='yesterday'),
            'bad-vulnerability': lambda d: d['statements'][0]['vulnerability'].update(name='CVE-2025'),
            'product-without-purl': lambda d: d['statements'][0]['products'][0].update({'@id': 'setuptools@70.3.0'}),
            'product-with-range': lambda d: d['statements'][0]['products'][0].update({'@id': 'pkg:npm/example@^1.2.3'}),
            'product-with-empty-version': lambda d: d['statements'][0]['products'][0].update({'@id': 'pkg:pypi/setuptools@'}),
            'product-with-encoded-wildcard': lambda d: d['statements'][0]['products'][0].update({'@id': 'pkg:pypi/setuptools@%2A'}),
            'product-with-wildcard-name': lambda d: d['statements'][0]['products'][0].update({'@id': 'pkg:pypi/*@70.3.0'}),
            'product-with-qualifiers': lambda d: d['statements'][0]['products'][0].update({'@id': 'pkg:pypi/setuptools@70.3.0?arch=amd64'}),
            'multiple-products': lambda d: d['statements'][0].update(products=[
                {'@id': 'pkg:pypi/setuptools@70.3.0'},
                {'@id': 'pkg:pypi/pip@26.3'}]),
            'missing-justification': lambda d: d['statements'][0].pop('justification'),
            'bad-justification': lambda d: d['statements'][0].update(justification='because'),
            'missing-impact': lambda d: d['statements'][0].pop('impact_statement'),
            'empty-impact': lambda d: d['statements'][0].update(impact_statement=' '),
            'bad-status': lambda d: d['statements'][0].update(status='probably-fine'),
        }
        for name, mutate in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as tmp:
                doc = self._valid()
                mutate(doc)
                path = Path(tmp) / 'ragnarsec-base.openvex.json'
                path.write_text(json.dumps(doc))
                with self.assertRaises(ValueError):
                    ci.require_vex(path)

    def test_validate_applies_vex_only_to_the_matching_image(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.dict(ci.os.environ, {'PLATFORMS': 'linux/amd64'}), \
             patch.object(ci, 'require_platforms_available'), \
             patch.object(ci, 'require_local_parent_builder'), \
             patch.object(ci, 'image_layer_bytes', return_value=1024):
            output = Path(tmp) / 'validated'

            def fake(*args, capture=False):
                if args[:3] == ('docker', 'image', 'inspect'):
                    return subprocess.CompletedProcess([], 0, stdout='sha256:local-image-id')
                if args[:2] == ('trivy', 'image') and '--output' in args:
                    Path(args[args.index('--output') + 1]).write_text('{}')
                return subprocess.CompletedProcess([], 0, stdout='')

            with patch.object(ci, 'command', side_effect=fake) as cmd:
                ci.validate('ragnarsec-python-base', 'test', output)
            scans = [call.args for call in cmd.call_args_list
                     if call.args[:2] == ('trivy', 'image')
                     and '--severity' in call.args
                     and '--exit-on-eol' in call.args]
            self.assertEqual(len(scans), 2)
            vexed = [args for args in scans if '--vex' in args]
            self.assertEqual(len(vexed), 1)
            snapshot = Path(vexed[0][vexed[0].index('--vex') + 1])
            self.assertEqual(snapshot.parent, output)
            self.assertEqual(snapshot.name, 'ragnarsec-python-base.openvex.json')
            self.assertEqual(
                snapshot.read_bytes(),
                (ROOT / 'vex/ragnarsec-python-base.openvex.json').read_bytes())
            receipts = json.loads((output / 'validated.json').read_text())
            by_name = {r['name']: r for r in receipts}
            self.assertNotIn('vex', by_name['ragnarsec-base'])
            self.assertEqual(by_name['ragnarsec-python-base']['vex'],
                             'vex/ragnarsec-python-base.openvex.json')
            self.assertEqual(
                by_name['ragnarsec-python-base']['vex_sha256'],
                hashlib.sha256(snapshot.read_bytes()).hexdigest())

    def test_vex_path_cannot_escape_repository_vex_directory(self):
        for name in ('../ragnarsec-base', 'ragnarsec-base/../../x', 'unknown'):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    ci.vex_path(name)

    @patch.object(ci.os, 'uname', lambda: SimpleNamespace(machine='x86_64'))
    def test_publish_rejects_changed_vex_before_push(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'sbom.json').write_text('{}')
            (p / 'cosign.key').write_text('key')
            receipts = []
            for name, platform in (('ragnarsec-base', 'linux/amd64'),
                                   ('ragnarsec-python-base', 'linux/amd64')):
                receipt = {'ref': ci.REGISTRY + name + ':test-amd64',
                           'name': name, 'platform': platform,
                           'id': 'sha256:local-image-id', 'sbom': 'sbom.json',
                           'sbom_sha256': hashlib.sha256(b'{}').hexdigest()}
                if name == 'ragnarsec-python-base':
                    receipt['vex'] = 'vex/ragnarsec-python-base.openvex.json'
                    receipt['vex_sha256'] = '0' * 64
                receipts.append(receipt)
            (p / 'validated.json').write_text(json.dumps(receipts))

            def fake(*args, capture=False):
                if args[:2] == ('cosign', 'public-key'):
                    Path(args[args.index('--outfile') + 1]).write_text('pub')
                if args[:3] == ('docker', 'image', 'inspect'):
                    return subprocess.CompletedProcess([], 0, stdout='sha256:local-image-id linux/amd64')
                return subprocess.CompletedProcess([], 0, stdout='')

            env = {'PUBLICATION_ENABLED': 'true', 'COSIGN_KEY': str(p / 'cosign.key'),
                   'PLATFORMS': 'linux/amd64'}
            with patch.dict(ci.os.environ, env), patch.object(ci, 'command', side_effect=fake) as cmd:
                with self.assertRaisesRegex(ValueError, 'vex-changed'):
                    ci.publish('ragnarsec-python-base', 'test', p)
                self.assertFalse(any(c.args[:2] == ('docker', 'push') for c in cmd.call_args_list))


class DockerfilePolicy(unittest.TestCase):
    def test_npm_resolver_is_readable_independent_of_the_checkout_umask(self):
        dockerfile = (ROOT / 'nginx-proxy-manager' / 'Dockerfile').read_text()
        self.assertIn('COPY --chmod=0444 render-resolver.cjs /usr/local/lib/npm-render-resolver.cjs',
                      dockerfile.splitlines())

    def test_npm_resolver_structure_check_does_not_expand_shell_variables(self):
        config = (ROOT / 'tests' / 'ragnarsec-nginx-proxy-manager.yaml').read_text()
        check = config.split("  - name: 'Resolver helper is root-owned and readable as UID 1000'", 1)[1]
        check = check.split('\n  - name:', 1)[0]
        # container-structure-test substitutes image environment variables in
        # every argument before starting the command, not shell-local values.
        self.assertNotRegex(check, r'\$(?:[A-Za-z_][A-Za-z_0-9]*|\{)')

    def test_shared_base_uses_supported_alpine_pin_and_matching_manifest(self):
        base = (ROOT / 'base' / 'Dockerfile').read_text()
        versions = json.loads((ROOT / 'versions.json').read_text())
        digest = 'sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a'
        self.assertIn('FROM alpine:3.24.3@' + digest, base)
        self.assertEqual(versions['ragnarsec-base']['alpine_digest'], digest)
        self.assertEqual(versions['ragnarsec-base-min']['alpine_digest'], digest)
        for name, version in versions['ragnarsec-base']['packages'].items():
            self.assertIn(name + '=' + version, base)

    def test_base_consumers_do_not_advertise_obsolete_alpine_release(self):
        for name in ('nginx', 'python-base'):
            with self.subTest(name=name):
                self.assertNotIn('Alpine 3.21', (ROOT / name / 'Dockerfile').read_text())

    def test_base_consumers_use_the_inherited_alpine_repositories(self):
        for name in ('minio', 'rabbitmq'):
            with self.subTest(name=name):
                dockerfile = (ROOT / name / 'Dockerfile').read_text()
                self.assertNotIn('/v3.21/community', dockerfile)
                self.assertNotIn('>> /etc/apk/repositories', dockerfile)
                self.assertIn('apk add --no-cache', dockerfile)

    def test_spliced_upgrade_without_separator_is_detected(self):
        for command in ('apk', 'apt-get', 'apt'):
            with self.subTest(command=command), tempfile.TemporaryDirectory() as tmp:
                dockerfile = Path(tmp) / 'Dockerfile'
                dockerfile.write_text('FROM alpine:3.24\nRUN ' + command + ' up\\\ngrade\nUSER 1000\n')
                self.assertIn('forbidden-upgrade-instruction', policy.check_dockerfile(dockerfile))

    def test_spliced_word_is_not_reported_as_upgrade(self):
        with tempfile.TemporaryDirectory() as tmp:
            dockerfile = Path(tmp) / 'Dockerfile'
            dockerfile.write_text('FROM alpine:3.24\nRUN echo apk\\\nupgrade\nUSER 1000\n')
            self.assertEqual(policy.check_dockerfile(dockerfile), [])

    def test_continued_upgrade_command_cannot_bypass_policy(self):
        for command in ('apk', 'apt-get', 'apt'):
            with self.subTest(command=command), tempfile.TemporaryDirectory() as tmp:
                dockerfile = Path(tmp) / 'Dockerfile'
                dockerfile.write_text('FROM alpine:3.24\nRUN ' + command + ' \\\n upgrade\nUSER 1000\n')
                self.assertIn('forbidden-upgrade-instruction', policy.check_dockerfile(dockerfile))

    def test_heredoc_upgrade_command_remains_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            dockerfile = Path(tmp) / 'Dockerfile'
            dockerfile.write_text('FROM alpine:3.24\nRUN <<EOF\napk upgrade\nEOF\nUSER 1000\n')
            self.assertIn('forbidden-upgrade-instruction', policy.check_dockerfile(dockerfile))

    def test_heredoc_text_is_not_an_add_or_from_instruction(self):
        for body in ('add table inet filter', 'from alpine:latest'):
            with self.subTest(body=body), tempfile.TemporaryDirectory() as tmp:
                dockerfile = Path(tmp) / 'Dockerfile'
                dockerfile.write_text('FROM alpine:3.24\nRUN <<EOF\n' + body + '\nEOF\nUSER 1000\n')
                self.assertEqual(policy.check_dockerfile(dockerfile), [])

    def test_quoted_actual_heredoc_delimiter_still_hides_its_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            dockerfile = Path(tmp) / 'Dockerfile'
            dockerfile.write_text(
                "FROM alpine:3.24\nRUN <<'EOF'\nADD payload /payload\n"
                'FROM alpine:latest\nEOF\nUSER 1000\n')
            self.assertEqual(policy.check_dockerfile(dockerfile), [])

    def test_real_instructions_after_heredoc_still_trigger(self):
        with tempfile.TemporaryDirectory() as tmp:
            dockerfile = Path(tmp) / 'Dockerfile'
            dockerfile.write_text('FROM alpine:3.24\nRUN <<EOF\nadd table inet filter\nEOF\n'
                                  'aDd payload /payload\nfRoM alpine:latest\nUSER 1000\n')
            self.assertIn('add-instead-of-copy', policy.check_dockerfile(dockerfile))
            self.assertIn('latest-tag-in-from', policy.check_dockerfile(dockerfile))

    def test_quoted_heredoc_text_cannot_hide_later_instructions(self):
        for quoted_text in (
                'RUN echo "<<EOF"',
                'RUN ["echo", "<<EOF"]',
                'RUN echo "$(echo "<<EOF")"',
                'SHELL ["/bin/bash", "-c"]\nRUN cat <<<EOF'):
            with self.subTest(quoted_text=quoted_text), tempfile.TemporaryDirectory() as tmp:
                dockerfile = Path(tmp) / 'Dockerfile'
                dockerfile.write_text(
                    'FROM alpine:3.24\n' + quoted_text + '\n'
                    'ADD payload /payload\nFROM alpine:latest\n'
                    'RUN <<EOF\nreal heredoc body\nEOF\nUSER 1000\n')
                problems = policy.check_dockerfile(dockerfile)
                self.assertIn('add-instead-of-copy', problems)
                self.assertIn('latest-tag-in-from', problems)

    def test_mixed_case_dockerfile_opcodes_cannot_bypass_policy(self):
        for dockerfile_text, violation in (
            ('fRoM alpine:3.21\nUsEr 1000\nuSeR root\n', 'root-final-user'),
            ('FROM alpine:3.21\naDd file /file\nUSER 1000\n', 'add-instead-of-copy'),
            ('fRoM alpine:latest\nUSER 1000\n', 'latest-tag-in-from'),
        ):
            with self.subTest(violation=violation), tempfile.TemporaryDirectory() as tmp:
                dockerfile = Path(tmp) / 'Dockerfile'
                dockerfile.write_text(dockerfile_text)
                self.assertIn(violation, policy.check_dockerfile(dockerfile))

    def test_platform_qualified_from_latest_is_rejected_not_heredoc_text(self):
        for instruction in ('FROM --platform=$TARGETPLATFORM alpine:latest',
                            'fRoM --platform=linux/amd64 alpine:latest AS build'):
            with self.subTest(instruction=instruction), tempfile.TemporaryDirectory() as tmp:
                dockerfile = Path(tmp) / 'Dockerfile'
                dockerfile.write_text(instruction + '\nUSER 1000\n')
                self.assertIn('latest-tag-in-from', policy.check_dockerfile(dockerfile))
                dockerfile.write_text('FROM alpine:3.24\nRUN <<EOF\n' + instruction + '\nEOF\nUSER 1000\n')
                self.assertNotIn('latest-tag-in-from', policy.check_dockerfile(dockerfile))

    def test_root_user_with_group_requires_exception(self):
        for user in ('0:0', 'root:root', '0:1000', 'root:1000'):
            with self.subTest(user=user), tempfile.TemporaryDirectory() as tmp:
                dockerfile = Path(tmp) / 'Dockerfile'
                dockerfile.write_text('FROM alpine:3.21\nUSER ' + user + '\n')
                self.assertIn('root-final-user', policy.check_dockerfile(dockerfile))
                dockerfile.write_text('# policy: allow-root upstream requirement\n'
                                      'FROM alpine:3.21\nUSER ' + user + '\n')
                self.assertNotIn('root-final-user', policy.check_dockerfile(dockerfile))

    def test_final_stage_does_not_inherit_user_from_unrelated_builder(self):
        with tempfile.TemporaryDirectory() as tmp:
            dockerfile = Path(tmp) / 'Dockerfile'
            dockerfile.write_text('FROM alpine:3.21 AS builder\nUSER 1000:1000\n'
                                  'FROM scratch\nCOPY --from=builder /app /app\n')
            self.assertIn('missing-final-user', policy.check_dockerfile(dockerfile))

    def test_final_stage_inherits_user_from_named_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            dockerfile = Path(tmp) / 'Dockerfile'
            dockerfile.write_text('FROM --platform=$BUILDPLATFORM alpine:3.21 AS builder\n'
                                  'USER 1000:1000\nFROM builder AS runtime\n')
            self.assertNotIn('missing-final-user', policy.check_dockerfile(dockerfile))
            dockerfile.write_text('FROM alpine:3.21 AS builder\nUSER 0:0\n'
                                  'FROM builder AS runtime\n')
            self.assertIn('root-final-user', policy.check_dockerfile(dockerfile))

    def test_run_continuation_cannot_spoof_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            dockerfile = Path(tmp) / 'Dockerfile'
            dockerfile.write_text('FROM alpine:3.21 AS safe\nUSER 1000:1000\n'
                                  'FROM scratch AS runtime\nUSER root\n'
                                  "RUN printf '%s' \\\nFROM safe\n")
            self.assertIn('root-final-user', policy.check_dockerfile(dockerfile))

    def test_heredoc_cannot_spoof_stage_or_user(self):
        with tempfile.TemporaryDirectory() as tmp:
            dockerfile = Path(tmp) / 'Dockerfile'
            dockerfile.write_text('FROM alpine:3.21 AS safe\nUSER 1000:1000\n'
                                  'FROM scratch AS runtime\nUSER root\n'
                                  'RUN <<EOF\nFROM safe\nUSER 1000:1000\nEOF\n')
            self.assertIn('root-final-user', policy.check_dockerfile(dockerfile))
            dockerfile.write_text('FROM scratch\nRUN <<-"SCRIPT"\n'
                                  'USER 1000:1000\n\tSCRIPT\n')
            self.assertIn('missing-final-user', policy.check_dockerfile(dockerfile))

    def test_continued_from_inherits_local_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            dockerfile = Path(tmp) / 'Dockerfile'
            dockerfile.write_text('FROM alpine:3.21 AS builder\nUSER 1000:1000\n'
                                  'FROM --platform=$BUILDPLATFORM \\\n builder AS runtime\n')
            self.assertNotIn('missing-final-user', policy.check_dockerfile(dockerfile))

    def test_escape_directive_continuation_cannot_spoof_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            dockerfile = Path(tmp) / 'Dockerfile'
            dockerfile.write_text('# escape=`\nFROM alpine:3.21 AS safe\nUSER 1000\n'
                                  'FROM scratch\nUSER root\nRUN echo `\nFROM safe\n')
            self.assertIn('root-final-user', policy.check_dockerfile(dockerfile))

    def test_final_stage_user_overrides_inherited_user(self):
        with tempfile.TemporaryDirectory() as tmp:
            dockerfile = Path(tmp) / 'Dockerfile'
            dockerfile.write_text('FROM alpine:3.21 AS builder\nUSER 1000:1000\n'
                                  'FROM builder AS runtime\nUSER root:root\n')
            self.assertIn('root-final-user', policy.check_dockerfile(dockerfile))

    def test_non_root_user_with_group_is_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            dockerfile = Path(tmp) / 'Dockerfile'
            dockerfile.write_text('FROM alpine:3.21\nUSER 1000:0\n')
            self.assertNotIn('root-final-user', policy.check_dockerfile(dockerfile))

class ToolCustody(unittest.TestCase):
    def test_native_arm64_uses_pinned_arm64_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / 'tools'
            with patch('sys.argv', ['install_ci_tools.py', str(destination)]), \
                 patch.object(install.os, 'uname', return_value=type('Uname', (), {'machine': 'aarch64'})()), \
                 patch.object(install.urllib.request, 'urlopen', return_value=io.BytesIO(b'wrong')) as download:
                with self.assertRaisesRegex(ValueError, 'tool-checksum-mismatch'):
                    install.main()
                self.assertTrue(download.call_args.args[0].endswith('/container-structure-test-linux-arm64'))
                self.assertEqual(list(destination.iterdir()), [])

    def test_installer_rejects_unknown_arch_before_directory_or_download(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / 'tools'
            with patch('sys.argv', ['install_ci_tools.py', str(destination)]), \
                 patch('os.uname', return_value=type('Uname', (), {'machine': 'riscv64'})()), \
                 patch.object(install.urllib.request, 'urlopen', side_effect=AssertionError('download attempted')):
                with self.assertRaisesRegex(ValueError, 'unsupported-ci-host-arch:riscv64'):
                    install.main()
            self.assertFalse(destination.exists())

    def test_checksum_mismatch_rejects_executable(self):
        with self.assertRaisesRegex(ValueError,'checksum'):install.payload(b'modified',{'sha256':'0'*64})
    def test_archive_member_is_read_without_extracting_paths(self):
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w:gz') as t:
            a=tarfile.TarInfo('trivy');a.size=2;t.addfile(a,io.BytesIO(b'ok'))
        data=stream.getvalue()
        self.assertEqual(install.payload(data,{'sha256':hashlib.sha256(data).hexdigest(),'member':'trivy'}),b'ok')
    def test_pins_are_versioned_sha256_public_releases(self):
        pins=json.loads((ROOT/'tools/ci-tools.json').read_text())
        for pin in pins.values():
            self.assertRegex(pin['sha256'],r'^[0-9a-f]{64}$')
            self.assertIn('/releases/download/'+pin['version']+'/',pin['url'])


class JenkinsBoundaries(unittest.TestCase):
    def setUp(self):
        self.pipeline=(ROOT/'Jenkinsfile').read_text()
    def test_jenkins_does_not_depend_on_github_actions(self):
        for forbidden in ('actions/checkout','secrets.GITHUB_TOKEN','GITHUB_ACTIONS','workflow_dispatch','ubuntu-24.04'):
            self.assertNotIn(forbidden,self.pipeline)

    def test_only_reviewed_read_only_workflows_are_allowed(self):
        workflows = ROOT / '.github/workflows'
        reviewed = {
            'check-promotion-candidate.yml': '2192483f591dd4f587eba81bc99c84fdd9b0578f18db0365ddbc3255c328ef3a',
            'jenkins-observer.yml': 'c228368c3ce269964eca70739ab10b2ccfd6f0e28367d24e942084f8d28322be',
            'prepare-staging-draft.yml': 'd21ce465574b2cf1f2581f1a0fafb61a883c7cd61e4707003b4bf932cb824141',
            'promotion-route-preflight.yml': '96332ab904393044443589a67569979a283a6076f0010cbd0cf5c71261517205',
            'publish-ansible-check.yml': '50350767e9bb71a66a95647486c25a7912c1badf09e081eb83cf468a3ad48352',
            'staging-draft-merge-trigger.yml': '904d30bc54ac515e11e659c4e8c630428950a1c6c43d2f75ee336b79c6ad3f5c',
            'prepare-main-draft.yml': '33911f73642efb5aebdb377c6f8a680e5db96645ea865ebf77d00cce84920624',
            'staging-promotion-notification.yml': '12d5c588b0688cdc2ae9a67e016232fd33887dab037758b44abb9434e298275b',
        }
        self.assertEqual(sorted(path.name for path in workflows.iterdir()), sorted(reviewed))
        for name, digest in reviewed.items():
            path = workflows / name
            self.assertTrue(path.is_file() and not path.is_symlink())
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)


    def test_validation_and_publication_are_separate(self):
        validation=self.pipeline.split("stage('Plan')",1)[1].split("stage('Publish')",1)[0]
        self.assertNotIn('docker login',validation)
        self.assertNotIn('withCredentials',validation)
        matrix=self.pipeline.split('def validatePlatform()',1)[1]
        self.assertNotIn('docker login',matrix)
        self.assertNotIn('withCredentials',matrix)
        publication=self.pipeline.split("stage('Publish')",1)[1].split('def validatePlatform()',1)[0]
        self.assertIn('params.PUBLISH',publication)
        self.assertIn("env.BRANCH_NAME == 'main'",publication)
        self.assertIn('input message',publication)
        self.assertIn('withCredentials',publication)
        self.assertIn('ragnarsec-registry',publication)
    def test_choice_catalog_matches_all_recipes(self):
        for name in ci.catalog():self.assertIn(name,self.pipeline)
        self.assertIn('defaultValue: false',self.pipeline)
    def test_secret_scanner_runs_before_build_and_no_fallback_ignores(self):
        self.assertLess(self.pipeline.index('gitleaks dir'),self.pipeline.index('image_ci.py validate'))
        self.assertNotIn('|| true',(ROOT/'tools/image_ci.py').read_text())
        self.assertNotIn('--ignore-unfixed',(ROOT/'tools/image_ci.py').read_text())

    def test_promotion_provenance_is_enforced(self):
        provenance=self.pipeline.split("stage('Provenance')",1)[1].split("stage('Contract')",1)[0]
        self.assertIn('CHANGE_TARGET',provenance)
        self.assertIn('require_traceable development',provenance)
        self.assertIn('require_traceable staging',provenance)
        self.assertIn('origin/${branch}',provenance)
        self.assertIn('merge-base --is-ancestor',provenance)
        self.assertIn('%T',provenance)
        self.assertIn('grep -x "$tree" >/dev/null', provenance)
        self.assertNotIn('grep -qx "$tree"', provenance)
        self.assertIn('HEAD^2',provenance)


    def test_every_promotion_pr_uses_the_protected_policy_adapter(self):
        provenance = self.pipeline.split("stage('Provenance')", 1)[1].split("stage('Contract')", 1)[0]
        route = self.pipeline.split("stage('Promotion route')", 1)[1].split("stage('Tools')", 1)[0]
        self.assertIn('staging|main)', provenance)
        self.assertIn('bash tools/verify_protected_promotion.sh "$source" "$target" "$head"', provenance)
        self.assertIn('bash tools/verify_protected_promotion.sh', route)
        self.assertIn('development "$(git rev-parse --verify HEAD)"', route)
        for obsolete in ('require_one_time_sync', 'require_scoped_sync', 'require_linear_arm64_sync'):
            self.assertNotIn(obsolete, self.pipeline)

    def test_development_is_plan_only(self):
        plan=self.pipeline.split("stage('Plan')",1)[1].split("stage('Validate')",1)[0]
        self.assertIn('image_ci.py plan',plan)
        self.assertNotIn('image_ci.py validate',plan)
        self.assertIn('if [ "$target" = "development" ]',plan)
        validate=self.pipeline.split("stage('Validate')",1)[1].split("stage('Publish')",1)[0]
        self.assertNotIn("== 'development'",validate)
        self.assertIn('image_ci.py validate',self.pipeline.split('def validatePlatform()',1)[1])
    def test_build_root_is_recreated_and_removed(self):
        tools=self.pipeline.split("stage('Tools')",1)[1].split("stage('Secret scan')",1)[0]
        self.assertIn(': "${CI_ROOT:?}"',tools)
        self.assertIn('rm -rf "$CI_ROOT"',tools)
        self.assertLess(tools.index('rm -rf "$CI_ROOT"'),tools.index('install_ci_tools.py'))
        post=self.pipeline.split('post {',1)[1]
        self.assertIn('rm -rf "$CI_ROOT"',post)

    def test_jenkins_checks_selected_runner_before_tool_installation(self):
        tools = self.pipeline.split("stage('Tools')", 1)[1].split("stage('Secret scan')", 1)[0]
        guard = 'test "$(uname -m)" = x86_64'
        self.assertLess(tools.index(guard), tools.index('install_ci_tools.py'))
        self.assertLess(tools.index(guard), tools.index('rm -rf "$CI_ROOT"'))

    def test_jenkins_validates_both_platforms_in_parallel_on_native_agents(self):
        validate = self.pipeline.split("stage('Validate')", 1)[1].split("stage('Publish')", 1)[0]
        self.assertIn('parallel {', validate)
        self.assertIn("stage('Validate linux/amd64')", validate)
        self.assertIn("stage('Validate linux/arm64')", validate)
        self.assertNotIn("agent { label 'ragnarsec-linux' }", validate)
        self.assertIn("agent { label 'ragnarsec-linux-arm64' }", validate)
        self.assertIn("== 'staging'", validate)
        self.assertIn("== 'main'", validate)
        func = self.pipeline.split('def validatePlatform()', 1)[1]
        self.assertIn('amd64:x86_64|arm64:aarch64', func)
        self.assertIn('RAGNARSEC_REQUIRE_STAGE_EGRESS=1', func)
        self.assertIn('image_ci.py validate', func)

    def test_jenkins_plan_stage_infers_image_and_runs_egress_gate(self):
        plan = self.pipeline.split("stage('Plan')", 1)[1].split("stage('Validate')", 1)[0]
        self.assertIn('tools/select_image.py --image "${IMAGE:-}"', plan)
        self.assertIn('[ -z "${IMAGE:-}" ]', plan)
        self.assertLess(plan.index('select_image.py'), plan.index('image_ci.py plan'))
        self.assertIn('env.CI_VALIDATION_IMAGE', plan)
        self.assertIn('select IMAGE explicitly for a branch build', plan)
        self.assertIn('promotion requires both native platforms', plan)
        self.assertIn('Development build: plan only', plan)

    def test_jenkins_exports_the_declared_image_parameter(self):
        environment = self.pipeline.split('  environment {', 1)[1].split('  stages {', 1)[0]
        self.assertIn('IMAGE = "${params.IMAGE ?: \'\'}"', environment)



    def test_affected_workflows_never_use_pull_request_target(self):
        workflows = ROOT / '.github/workflows'
        for name in MIGRATED:
            text = (workflows / name).read_text()
            self.assertNotIn('pull_request_target', text, name)

    def test_ansible_publisher_resolves_the_pr_before_getting_the_app_token(self):
        workflow = (ROOT / '.github/workflows/publish-ansible-check.yml').read_text()
        self.assertIn('  workflow_run:', workflow)
        self.assertIn('workflows: ["Preflight the protected promotion route"]', workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn('ref: ${{ github.sha }}', workflow)
        self.assertIn('environment: ansible-ci', workflow)
        self.assertIn('secrets.RAGNARSEC_ANSIBLE_PROTECTED_APP_PRIVATE_KEY', workflow)
        self.assertIn('permission-checks: write', workflow)
        self.assertNotIn('  pull_request:', workflow)
        self.assertNotIn('download-artifact', workflow)
        self.assertLess(workflow.index('tools/ansible_receipt_gate.py'),
                        workflow.index('private-key:'))
        self.assertIn('tools/resolve_ansible_check.py | cmp - "$binding"', workflow)

    def test_ansible_publisher_queues_multiple_pending_runs(self):
        workflow = (ROOT / '.github/workflows/publish-ansible-check.yml').read_text()
        concurrency = workflow.split('\nconcurrency:\n', 1)[1].split('\n\n', 1)[0]
        self.assertIn('  group: ansible-check-publisher\n', concurrency)
        self.assertIn('  queue: max\n', concurrency)
        self.assertIn('  cancel-in-progress: false', concurrency)

    def test_preflight_reads_signed_manifest_from_protected_base(self):
        # CI-004: `pull_request` runs in the untrusted PR context, so the
        # verifier must be checked out from base.sha and the PR read only as
        # Git objects. The legacy bare invocation reports a direct route
        # conflict for every reconciliation-admitted PR; it must not return.
        workflow = (ROOT / '.github/workflows/promotion-route-preflight.yml').read_text()
        self.assertIn('  pull_request:', workflow)
        self.assertNotIn('pull_request_target', workflow)
        self.assertIn('branches: [development]', workflow)
        self.assertIn('ref: ${{ github.event.pull_request.base.sha }}', workflow)
        self.assertNotIn('ref: ${{ github.event.pull_request.head.sha }}', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('--change-id "$PR_NUMBER"', workflow)
        self.assertIn('--repo "$REPO"', workflow)
        self.assertIn('--pr "$PR_NUMBER"', workflow)
        self.assertIn('--manifest-from-pr "$PR_HEAD_SHA"', workflow)
        self.assertIn('--reviewed-head "$PR_HEAD_SHA"', workflow)
        self.assertIn('--allow-manifest-reconciliation', workflow)
        self.assertIn('python3 -B tools/jenkins_promotion_route.py "$@"', workflow)
        self.assertNotIn(
            'python3 -B tools/jenkins_promotion_route.py --source "$SOURCE_BRANCH" '
            '--reviewed-head "$PR_HEAD_SHA"',
            workflow,
        )
        self.assertIn('permissions:\n  contents: read', workflow)
        self.assertNotIn('secrets.', workflow)
        self.assertNotIn('pull-requests: write', workflow)

    def test_candidate_uses_protected_base_checkout_and_read_only_token(self):
        workflow = (ROOT / '.github/workflows/check-promotion-candidate.yml').read_text()
        self.assertIn('  pull_request:', workflow)
        self.assertNotIn('pull_request_target', workflow)
        self.assertIn('branches: [staging, main]', workflow)
        self.assertIn('ref: ${{ github.event.pull_request.base.sha }}', workflow)
        self.assertNotIn('ref: ${{ github.event.pull_request.head.sha }}', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('python3 -B tools/promotion_candidate.py "$GITHUB_EVENT_PATH"', workflow)
        self.assertIn('permissions:\n  contents: read', workflow)
        self.assertNotIn('secrets.', workflow)
        self.assertNotIn('pull-requests: write', workflow)

    def test_staging_draft_is_automatic_with_owner_app_token_and_manual_squash(self):
        # CI-004 corrective: draft creation is AUTOMATIC via a protected-base
        # workflow_run; the squash remains manual. The privileged file must
        # never be triggered by an untrusted PR event, and the App token stays
        # confined to the draft POST job.
        workflow = (ROOT / '.github/workflows/prepare-staging-draft.yml').read_text()
        self.assertNotIn('pull_request_target', workflow)
        self.assertNotIn('  pull_request:', workflow)
        self.assertIn('  workflow_dispatch:', workflow)  # owner path retained
        self.assertIn('      integrated_pr:', workflow)
        self.assertIn('  workflow_run:', workflow)
        self.assertIn('workflows: ["Staging draft merge trigger"]', workflow)
        self.assertIn('types: [completed]', workflow)
        self.assertIn("github.event_name != 'workflow_dispatch' || github.ref == 'refs/heads/main'",
                      workflow)
        self.assertIn('ref: refs/heads/main', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('environment: ansible-ci', workflow)
        self.assertIn('secrets.RAGNARSEC_ANSIBLE_PROTECTED_APP_PRIVATE_KEY', workflow)
        self.assertIn('steps.app-token.outputs.token', workflow)
        self.assertIn('pull-requests: write', workflow)
        self.assertIn("vars.RAGNARSEC_CREATE_STAGING_DRAFTS == 'true'", workflow)
        self.assertIn('python3 -B tools/prepare_staging_draft.py --create-plan "$PLAN"', workflow)
        # Manual squash gate: the tool creates draft:true and prints the
        # human-review result; no publication or bypass marker is present.
        self.assertIn('draft', workflow)  # documented in the trust boundary
        self.assertNotIn('PUBLISH', workflow)
        self.assertNotIn('--admin', workflow)
        self.assertNotIn('auto-merge', workflow)

    def test_staging_draft_trigger_is_untrusted_and_secret_free(self):
        # The automatic trigger runs on the untrusted PR event and must never
        # hold a credential or a write scope.
        workflow = (ROOT / '.github/workflows/staging-draft-merge-trigger.yml').read_text()
        self.assertIn('  pull_request:', workflow)
        self.assertNotIn('pull_request_target', workflow)
        self.assertIn('branches: [development]', workflow)
        self.assertIn('types: [closed]', workflow)
        self.assertIn('permissions: {}', workflow)
        self.assertNotIn('secrets.', workflow)
        self.assertNotIn('pull-requests: write', workflow)
        self.assertNotIn('actions/create-github-app-token', workflow)
        self.assertNotIn('GITHUB_OUTPUT', workflow)  # emits no trusted outputs
        self.assertNotIn('  workflow_run:', workflow)  # it is the trigger, not the watcher

    def test_workflow_run_number_is_never_taken_from_untrusted_outputs(self):
        # The privileged workflow must derive integrated_pr only from GitHub-
        # populated workflow_run metadata or a signed-head API lookup, and must
        # pass it through the trusted resolver output.
        workflow = (ROOT / '.github/workflows/prepare-staging-draft.yml').read_text()
        self.assertIn('INTEGRATED_PR: ${{ needs.resolve-integrated-pr.outputs.number }}', workflow)
        self.assertIn('RUN_HEAD_REPO_ID: ${{ github.event.workflow_run.head_repository.id }}',
                      workflow)
        self.assertIn('RUN_PR_NUMBER: ${{ github.event.workflow_run.pull_requests[0].number }}',
                      workflow)
        self.assertIn("[[ \"$RUN_EVENT\" == 'pull_request' ]]", workflow)
        self.assertIn("[[ \"$RUN_HEAD_REPO_ID\" == '1426336836' ]]", workflow)
        self.assertNotIn('needs.note-merge.outputs', workflow)
        self.assertNotIn('needs.staging-draft-merge-trigger.outputs', workflow)

    def test_main_draft_only_uses_protected_policy_and_a_scoped_post(self):
        workflows = ROOT / '.github/workflows'
        trigger = (workflows / 'staging-promotion-notification.yml').read_text()
        self.assertIn('branches: [staging]', trigger)
        self.assertIn('permissions: {}', trigger)
        for forbidden in ('actions/checkout', 'secrets.', 'GITHUB_OUTPUT', 'workflow_run:'):
            self.assertNotIn(forbidden, trigger)
        draft = (workflows / 'prepare-main-draft.yml').read_text()
        self.assertIn('workflows: ["Staging promotion notification"]', draft)
        self.assertIn("github.ref == 'refs/heads/main'", draft)
        self.assertEqual(draft.count('ref: ${{ github.sha }}'), 2)
        self.assertIn("vars.RAGNARSEC_CREATE_MAIN_DRAFTS == 'true'", draft)
        self.assertIn('environment: ansible-ci', draft)
        self.assertIn('permission-pull-requests: write', draft)
        for forbidden in ('contents: write', 'permission-checks: write', 'pull_request_target',
                          'download-artifact', 'gh pr merge'):
            self.assertNotIn(forbidden, draft)

    def test_no_insecure_transport_or_pr_tree_verifier(self):
        # ADR-010:70: no -k acceptance, no proxy_ssl_verify off. A verifier
        # checked out from the PR tree would defeat the protected-base model.
        for name in MIGRATED:
            text = (ROOT / '.github/workflows' / name).read_text()
            for forbidden in ('curl -k', '--insecure', 'GIT_SSL_NO_VERIFY',
                              'proxy_ssl_verify off', 'http://'):
                self.assertNotIn(forbidden, text, (name, forbidden))



if __name__=='__main__':unittest.main()
