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
            'promotion-route-preflight.yml': '32922887ac1b9d3649045388d2eff30b0463c0a237331758de44ef825014b2e6',
        }
        self.assertEqual(sorted(path.name for path in workflows.iterdir()), sorted(reviewed))
        for name, digest in reviewed.items():
            path = workflows / name
            self.assertTrue(path.is_file() and not path.is_symlink())
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_preflight_reads_signed_manifest_from_trusted_default_branch(self):
        # pull_request_target resolves this file from the default branch (main),
        # never from the PR head. The legacy bare invocation reports a direct
        # route conflict for every reconciliation-admitted PR; it must not be
        # restored. The base checkout and owner-signed manifest flags stay.
        workflow = (suite.ROOT / '.github/workflows/promotion-route-preflight.yml').read_text()
        self.assertIn('pull_request_target:', workflow)
        self.assertIn('ref: ${{ github.event.pull_request.base.sha }}', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('--change-id "$PR_NUMBER"', workflow)
        self.assertIn('--repo "$REPO"', workflow)
        self.assertIn('--pr "$PR_NUMBER"', workflow)
        self.assertIn('--manifest-from-pr "$PR_HEAD_SHA"', workflow)
        self.assertIn('--allow-manifest-reconciliation', workflow)
        self.assertIn('python3 -B tools/jenkins_promotion_route.py "$@"', workflow)
        self.assertNotIn(
            'python3 -B tools/jenkins_promotion_route.py --source "$SOURCE_BRANCH" '
            '--reviewed-head "$PR_HEAD_SHA"',
            workflow,
        )
