"""Discover the existing CI contracts and the current Actions allowlist."""
import hashlib

import ci_contracts as suite


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
            'jenkins-observer.yml': 'c228368c3ce269964eca70739ab10b2ccfd6f0e28367d24e942084f8d28322be',
            'prepare-staging-draft.yml': '084a22360f2ff264c3b4d4b7f25aa8481cf49db05d7d14481416f08803b0b56f',
            'promotion-route-preflight.yml': 'aab6c64704aa019bf81a21e6b6e79340e91dc727bd91feddee6a1f543dac1629',
        }
        self.assertEqual(sorted(path.name for path in workflows.iterdir()), sorted(reviewed))
        for name, digest in reviewed.items():
            path = workflows / name
            self.assertTrue(path.is_file() and not path.is_symlink())
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
