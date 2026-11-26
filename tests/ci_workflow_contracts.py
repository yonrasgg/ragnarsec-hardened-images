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

# CI-004: the three workflows that used `pull_request_target` and now use a
# safe event. Their verifiers must come from a protected ref; PR bytes are data.
MIGRATED = (
    'promotion-route-preflight.yml',
    'check-promotion-candidate.yml',
    'prepare-staging-draft.yml',
)


class JenkinsBoundaries(suite.JenkinsBoundaries):
    def test_only_reviewed_read_only_workflows_are_allowed(self):
        workflows = suite.ROOT / '.github/workflows'
        reviewed = {
            'check-promotion-candidate.yml': '2192483f591dd4f587eba81bc99c84fdd9b0578f18db0365ddbc3255c328ef3a',
            'jenkins-observer.yml': 'c228368c3ce269964eca70739ab10b2ccfd6f0e28367d24e942084f8d28322be',
            'prepare-staging-draft.yml': '265e1876e01d3552b4ca337e547b450db78a5bf1b57735a1ab42582f8ad0186d',
            'promotion-route-preflight.yml': '96332ab904393044443589a67569979a283a6076f0010cbd0cf5c71261517205',
            'publish-ansible-check.yml': '28e73414e4e202c9aea34c5f0470d97d7b42e9ea48b12ba73ac0afd7e2bb03be',
        }
        self.assertEqual(sorted(path.name for path in workflows.iterdir()), sorted(reviewed))
        for name, digest in reviewed.items():
            path = workflows / name
            self.assertTrue(path.is_file() and not path.is_symlink())
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_affected_workflows_never_use_pull_request_target(self):
        workflows = suite.ROOT / '.github/workflows'
        for name in MIGRATED:
            text = (workflows / name).read_text()
            self.assertNotIn('pull_request_target', text, name)
        # The publisher gate was already on the untrusted event; CI-004 does
        # not change it. Its own verifier tree is assessed separately (CI-008).
        self.assertIn('  pull_request:', (workflows / 'publish-ansible-check.yml').read_text())

    def test_preflight_reads_signed_manifest_from_protected_base(self):
        # CI-004: `pull_request` runs in the untrusted PR context, so the
        # verifier must be checked out from base.sha and the PR read only as
        # Git objects. The legacy bare invocation reports a direct route
        # conflict for every reconciliation-admitted PR; it must not return.
        workflow = (suite.ROOT / '.github/workflows/promotion-route-preflight.yml').read_text()
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
        workflow = (suite.ROOT / '.github/workflows/check-promotion-candidate.yml').read_text()
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

    def test_staging_draft_is_dispatch_only_with_owner_app_token(self):
        # The privileged draft/POST workflow must be owner-triggered on the
        # protected ref; it must never consume a pull_request_target event.
        workflow = (suite.ROOT / '.github/workflows/prepare-staging-draft.yml').read_text()
        self.assertNotIn('pull_request_target', workflow)
        self.assertIn('  workflow_dispatch:', workflow)
        self.assertIn('      integrated_pr:', workflow)
        self.assertIn("github.event_name == 'workflow_dispatch'", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn('ref: refs/heads/main', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('secrets.RAGNARSEC_ANSIBLE_APP_PRIVATE_KEY', workflow)
        self.assertIn('steps.app-token.outputs.token', workflow)
        self.assertIn('pull-requests: write', workflow)
        self.assertIn("vars.RAGNARSEC_CREATE_STAGING_DRAFTS == 'true'", workflow)
        self.assertIn('python3 -B tools/prepare_staging_draft.py --create-plan "$PLAN"', workflow)
        self.assertNotIn('PUBLISH', workflow)
        self.assertNotIn('--admin', workflow)

    def test_no_insecure_transport_or_pr_tree_verifier(self):
        # ADR-010:70: no -k acceptance, no proxy_ssl_verify off. A verifier
        # checked out from the PR tree would defeat the protected-base model.
        for name in MIGRATED:
            text = (suite.ROOT / '.github/workflows' / name).read_text()
            for forbidden in ('curl -k', '--insecure', 'GIT_SSL_NO_VERIFY',
                              'proxy_ssl_verify off', 'http://'):
                self.assertNotIn(forbidden, text, (name, forbidden))
