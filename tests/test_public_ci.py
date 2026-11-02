import hashlib
import importlib.util
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parents[1]
def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT/'tools'/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
ci, install = load('image_ci'), load('install_ci_tools')
policy = load('image_policy')

class ImagePlanning(unittest.TestCase):
    def test_foreign_platform_uses_qemu_registration_name(self):
        for native, foreign, handler in (
            ('x86_64', 'linux/arm64', 'qemu-aarch64'),
            ('aarch64', 'linux/amd64', 'qemu-x86_64'),
        ):
            with self.subTest(native=native, foreign=foreign):
                with patch.object(ci.os, 'uname', return_value=type('Uname', (), {'machine': native})()), \
                     patch.object(ci.Path, 'exists', autospec=True,
                                  side_effect=lambda path: path.name == handler):
                    ci.require_platforms_available([foreign])

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
        self.assertEqual(len(images),22)
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
        with tempfile.TemporaryDirectory() as tmp, \
             patch.dict(ci.os.environ, {'PLATFORMS': 'linux/amd64'}), \
             patch.object(ci, 'require_platforms_available'), \
             patch.object(ci, 'require_local_parent_builder'):
            output = Path(tmp) / 'validated'

            def fake(*args, capture=False):
                if args[:3] == ('docker', 'image', 'inspect'):
                    value = '1024' if args[3] == '--format={{.Size}}' else 'sha256:local-image-id'
                    return subprocess.CompletedProcess([], 0, stdout=value)
                if args[:2] == ('trivy', 'image') and '--output' in args:
                    Path(args[args.index('--output') + 1]).write_text('{}')
                return subprocess.CompletedProcess([], 0, stdout='')

            with patch.object(ci, 'command', side_effect=fake) as cmd:
                ci.validate('ragnarsec-base', 'test', output)
            builds = [call.args for call in cmd.call_args_list
                      if call.args[:3] == ('docker', 'buildx', 'build')]
            self.assertEqual(len(builds), 1)
            self.assertIn('--provenance=false', builds[0])
            self.assertIn('--sbom=false', builds[0])
            scans = [call.args for call in cmd.call_args_list
                     if call.args[:2] == ('trivy', 'image') and '--severity' in call.args]
            self.assertEqual(len(scans), 1)
            self.assertEqual(scans[0][scans[0].index('--exit-on-eol') + 1], '1')
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
                        return subprocess.CompletedProcess([], 0, stdout='expected')
                    return subprocess.CompletedProcess([], 0, stdout='')

                env = {'PUBLICATION_ENABLED': 'true', 'COSIGN_KEY': str(p / 'cosign.key'),
                       'PLATFORMS': 'linux/amd64'}
                with patch.dict(ci.os.environ, env), patch.object(ci, 'command', side_effect=fake) as cmd:
                    with self.assertRaisesRegex(ValueError, 'validation-receipt-mismatch'):
                        ci.publish('ragnarsec-base', tag, p)
                    self.assertFalse(any(call.args[:2] == ('docker', 'push') for call in cmd.call_args_list))

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
                    return subprocess.CompletedProcess([], 0, stdout='expected')
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

class DockerfilePolicy(unittest.TestCase):
    def test_shared_base_uses_supported_alpine_pin_and_matching_manifest(self):
        base = (ROOT / 'base' / 'Dockerfile').read_text()
        versions = json.loads((ROOT / 'versions.json').read_text())
        digest = 'sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a'
        self.assertIn('FROM alpine:3.24.3@' + digest, base)
        self.assertEqual(versions['ragnarsec-base']['alpine_digest'], digest)
        self.assertEqual(versions['ragnarsec-base-min']['alpine_digest'], digest)
        for name, version in versions['ragnarsec-base']['packages'].items():
            self.assertIn(name + '=' + version, base)

    def test_heredoc_text_is_not_an_add_or_from_instruction(self):
        for body in ('add table inet filter', 'from alpine:latest'):
            with self.subTest(body=body), tempfile.TemporaryDirectory() as tmp:
                dockerfile = Path(tmp) / 'Dockerfile'
                dockerfile.write_text('FROM alpine:3.24\nRUN <<EOF\n' + body + '\nEOF\nUSER 1000\n')
                self.assertEqual(policy.check_dockerfile(dockerfile), [])

    def test_real_instructions_after_heredoc_still_trigger(self):
        with tempfile.TemporaryDirectory() as tmp:
            dockerfile = Path(tmp) / 'Dockerfile'
            dockerfile.write_text('FROM alpine:3.24\nRUN <<EOF\nadd table inet filter\nEOF\n'
                                  'aDd payload /payload\nfRoM alpine:latest\nUSER 1000\n')
            self.assertIn('add-instead-of-copy', policy.check_dockerfile(dockerfile))
            self.assertIn('latest-tag-in-from', policy.check_dockerfile(dockerfile))

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
    def test_no_github_actions_workflow_or_checkout(self):
        self.assertFalse((ROOT/'.github/workflows').exists())
        for forbidden in ('actions/checkout','secrets.GITHUB_TOKEN','GITHUB_ACTIONS','workflow_dispatch','ubuntu-24.04'):
            self.assertNotIn(forbidden,self.pipeline)
    def test_validation_and_publication_are_separate(self):
        validation=self.pipeline.split("stage('Plan and validate')",1)[1].split("stage('Publish')",1)[0]
        self.assertNotIn('docker login',validation)
        self.assertNotIn('withCredentials',validation)
        publication=self.pipeline.split("stage('Publish')",1)[1]
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
        self.assertIn('grep -qx',provenance)
        self.assertIn('HEAD^2',provenance)
    def test_one_time_syncs_require_exact_trees_and_frozen_bases(self):
        provenance=self.pipeline.split("stage('Provenance')",1)[1].split("stage('Contract')",1)[0]
        self.assertIn('sync/development-to-staging-zap-retirement-20261101',provenance)
        self.assertIn('5db2589b44f996329168255958ecf3eb321eff1b',provenance)
        self.assertIn('sync/staging-to-main-20261101',provenance)
        self.assertIn('ec651145b1e4571e946fe84bcaf1ef38aabdc172',provenance)
        self.assertIn('git merge-base --is-ancestor "origin/$base" "$commit"',provenance)
        self.assertIn('origin/${source_branch}^{tree}',provenance)
        self.assertIn('require_one_time_sync "$head" staging',provenance)
        self.assertIn('require_one_time_sync "$head" main',provenance)

    def test_development_is_plan_only(self):
        validation=self.pipeline.split("stage('Plan and validate')",1)[1].split("stage('Publish')",1)[0]
        before,after=validation.split('if [ "$target" = "development" ]',1)
        self.assertIn('image_ci.py plan',before)
        self.assertNotIn('image_ci.py validate',before)
        self.assertIn('else',after)
        self.assertIn('image_ci.py validate',after)
    def test_build_root_is_recreated_and_removed(self):
        tools=self.pipeline.split("stage('Tools')",1)[1].split("stage('Secret scan')",1)[0]
        self.assertIn(': "${CI_ROOT:?}"',tools)
        self.assertIn('rm -rf "$CI_ROOT"',tools)
        self.assertLess(tools.index('rm -rf "$CI_ROOT"'),tools.index('install_ci_tools.py'))
        post=self.pipeline.split('post {',1)[1]
        self.assertIn('rm -rf "$CI_ROOT"',post)

if __name__=='__main__':unittest.main()
