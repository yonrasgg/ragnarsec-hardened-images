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
            'prepare-staging-draft.yml': '5d0e77b986eb341c5f9b4a67d25d86002237d39adfc07b8e3f53bb53377df963',
            'promotion-route-preflight.yml': '32922887ac1b9d3649045388d2eff30b0463c0a237331758de44ef825014b2e6',
            'publish-ansible-check.yml': '45ded2de71591648fe7f38e179fe0967e585b43ee1855679eebd38a74d87001a',
        }
        self.assertEqual(sorted(path.name for path in workflows.iterdir()), sorted(reviewed))
        for name, digest in reviewed.items():
            path = workflows / name
            self.assertTrue(path.is_file() and not path.is_symlink())
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
