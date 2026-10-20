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

class ImagePlanning(unittest.TestCase):
    def test_all_recipes_and_multistage_parents_have_closed_plans(self):
        images = ci.catalog()
        self.assertEqual(len(images),27)
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
        names = [x['name'] for x in ci.plan('ragnarsec-plane-admin')]
        self.assertEqual(len(names),len(set(names)))
        self.assertIn('ragnarsec-builder',names)
        self.assertIn('ragnarsec-nginx',names)
        self.assertNotIn('ragnarsec-postgres',names)
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
    def test_failed_validation_never_writes_success_receipt(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(ci,'command',side_effect=subprocess.CalledProcessError(1,'hadolint')):
            p=Path(tmp)/'out'
            with self.assertRaises(subprocess.CalledProcessError): ci.validate('ragnarsec-base','test',p)
            self.assertFalse((p/'validated.json').exists())
    def test_publish_disabled_without_enablement(self):
        with patch.dict(ci.os.environ,{},clear=True),patch.object(ci,'command') as cmd:
            with self.assertRaises(ValueError): ci.publish('ragnarsec-base','test',Path('/not/read'))
            cmd.assert_not_called()
    def test_tampered_image_never_pushed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);(p/'sbom.json').write_text('{}');(p/'cosign.key').write_text('key')
            (p/'validated.json').write_text(json.dumps([{'ref':ci.REGISTRY+'ragnarsec-base:test','id':'expected','sbom':'sbom.json','sbom_sha256':hashlib.sha256(b'{}').hexdigest()}]))
            with patch.dict(ci.os.environ,{'PUBLICATION_ENABLED':'true','COSIGN_KEY':str(p/'cosign.key')}),patch.object(ci,'command',return_value=subprocess.CompletedProcess([],0,stdout='changed')) as cmd:
                with self.assertRaisesRegex(ValueError,'image-changed'):ci.publish('ragnarsec-base','test',p)
                self.assertFalse(any(c.args[:2]==('docker','push') for c in cmd.call_args_list))

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
        self.assertIn('require_ancestor development',provenance)
        self.assertIn('require_ancestor staging',provenance)
        self.assertIn('origin/${branch}',provenance)
        self.assertIn('merge-base --is-ancestor',provenance)
        self.assertIn('HEAD^2',provenance)
    def test_development_is_plan_only(self):
        validation=self.pipeline.split("stage('Plan and validate')",1)[1].split("stage('Publish')",1)[0]
        before,after=validation.split('if [ "$target" = "development" ]',1)
        self.assertIn('image_ci.py plan',before)
        self.assertNotIn('image_ci.py validate',before)
        self.assertIn('else',after)
        self.assertIn('image_ci.py validate',after)

if __name__=='__main__':unittest.main()
