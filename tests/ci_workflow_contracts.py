"""Discover the existing CI contracts and the current Actions allowlist."""
import hashlib

import test_public_ci as suite


setUpModule = suite.setUpModule
NpmRuntimeSbom = suite.NpmRuntimeSbom
ImageSizeBudget = suite.ImageSizeBudget
ImagePlanning = suite.ImagePlanning
VexPolicy = suite.VexPolicy
DockerfilePolicy = suite.DockerfilePolicy
ToolCustody = suite.ToolCustody


class JenkinsBoundaries(suite.JenkinsBoundaries):
    def test_only_reviewed_read_only_workflows_are_allowed(self):
        workflows = suite.ROOT / '.github/workflows'
        reviewed = {
            'check-promotion-candidate.yml': '71463c1026006a436c0f4b40f963e36c54e0abaaca109e3bdf3f9ccc3020f7cd',
            'jenkins-observer.yml': 'c228368c3ce269964eca70739ab10b2ccfd6f0e28367d24e942084f8d28322be',
            'prepare-staging-draft.yml': '084a22360f2ff264c3b4d4b7f25aa8481cf49db05d7d14481416f08803b0b56f',
            'promotion-route-preflight.yml': '85ae25042bed4bc1cc81f058b69a557a1e98a1ba2abefae3ddafb82f7e722ae7',
            'publish-ansible-check.yml': '86f9bb6b76089aed9b6425ed0350653fcf754a130b9a675616c78ddf30d65123',
        }
        self.assertEqual(sorted(path.name for path in workflows.iterdir()), sorted(reviewed))
        for name, digest in reviewed.items():
            path = workflows / name
            self.assertTrue(path.is_file() and not path.is_symlink())
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
