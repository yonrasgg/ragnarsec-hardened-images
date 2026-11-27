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
    # CI-004 corrective: untrusted half of the automatic-draft split.
    'staging-draft-merge-trigger.yml',
    'publish-ansible-check.yml',
)


class JenkinsBoundaries(suite.JenkinsBoundaries):
    def test_only_reviewed_read_only_workflows_are_allowed(self):
        workflows = suite.ROOT / '.github/workflows'
        reviewed = {
            'check-promotion-candidate.yml': '2192483f591dd4f587eba81bc99c84fdd9b0578f18db0365ddbc3255c328ef3a',
            'jenkins-observer.yml': 'c228368c3ce269964eca70739ab10b2ccfd6f0e28367d24e942084f8d28322be',
            'prepare-staging-draft.yml': '1cd4962b0c1e2c41197d79fa0acbd07fd35825911a641de16b1bb3e775dc7f26',
            'promotion-route-preflight.yml': '96332ab904393044443589a67569979a283a6076f0010cbd0cf5c71261517205',
            'publish-ansible-check.yml': 'e9e73fad5094f36ac9dd2566a8790e2769f56d85dd0a4c2266892b6b58f7830f',
            'staging-draft-merge-trigger.yml': '904d30bc54ac515e11e659c4e8c630428950a1c6c43d2f75ee336b79c6ad3f5c',
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

    def test_ansible_publisher_resolves_the_pr_before_getting_the_app_token(self):
        workflow = (suite.ROOT / '.github/workflows/publish-ansible-check.yml').read_text()
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

    def test_staging_draft_is_automatic_with_owner_app_token_and_manual_squash(self):
        # CI-004 corrective: draft creation is AUTOMATIC via a protected-base
        # workflow_run; the squash remains manual. The privileged file must
        # never be triggered by an untrusted PR event, and the App token stays
        # confined to the draft POST job.
        workflow = (suite.ROOT / '.github/workflows/prepare-staging-draft.yml').read_text()
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
        workflow = (suite.ROOT / '.github/workflows/staging-draft-merge-trigger.yml').read_text()
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
        workflow = (suite.ROOT / '.github/workflows/prepare-staging-draft.yml').read_text()
        self.assertIn('INTEGRATED_PR: ${{ needs.resolve-integrated-pr.outputs.number }}', workflow)
        self.assertIn('RUN_HEAD_REPO_ID: ${{ github.event.workflow_run.head_repository.id }}',
                      workflow)
        self.assertIn('RUN_PR_NUMBER: ${{ github.event.workflow_run.pull_requests[0].number }}',
                      workflow)
        self.assertIn("[[ \"$RUN_EVENT\" == 'pull_request' ]]", workflow)
        self.assertIn("[[ \"$RUN_HEAD_REPO_ID\" == '1426336836' ]]", workflow)
        self.assertNotIn('needs.note-merge.outputs', workflow)
        self.assertNotIn('needs.staging-draft-merge-trigger.outputs', workflow)

    def test_no_insecure_transport_or_pr_tree_verifier(self):
        # ADR-010:70: no -k acceptance, no proxy_ssl_verify off. A verifier
        # checked out from the PR tree would defeat the protected-base model.
        for name in MIGRATED:
            text = (suite.ROOT / '.github/workflows' / name).read_text()
            for forbidden in ('curl -k', '--insecure', 'GIT_SSL_NO_VERIFY',
                              'proxy_ssl_verify off', 'http://'):
                self.assertNotIn(forbidden, text, (name, forbidden))
