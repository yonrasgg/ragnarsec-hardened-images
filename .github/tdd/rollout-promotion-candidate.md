# Protected promotion policy: activation and acceptance

This runbook describes reusable policy and the observations needed to activate
it. A patch or a local test run is not evidence that GitHub or Jenkins enforces
the policy. Keep `PUBLISH=false` during qualification.

## Executable responsibilities

| Component | Responsibility | Authority it does not provide |
|---|---|---|
| `tools/promotion_candidate.py` | Verify the exact ordinary or signed reconciliation candidate against protected target policy and live refs. | No signature, push, merge or release. |
| `tools/verify_protected_promotion.sh` | Check Jenkins PR context and exact checkout; load the evaluator from the protected target in an isolated worktree. | No proof that an untrusted PR cannot omit the adapter. |
| `tools/prepare_staging_draft.py` | Bind an integration to its Ansible evidence and prepare one staging draft. | No staging merge or fabricated receipt. |
| `tools/prepare_main_draft.py` | Verify owner staging review, Actions/Jenkins evidence and inherited Ansible provenance; prepare one ordinary main draft. | No reconciliation signature, automatic main merge or publication. |
| `tools/promotion_evidence.py` | Evaluate a supplied multi-image evidence contract offline. | No authenticated collector or server-side merge enforcement. |

The same evaluator handles a reconciliation with the name and signed trailer
defined in [CONTRIBUTING](../../CONTRIBUTING.md#reusable-reconciliation-contract).
It requires a real ordinary conflict, the exact upstream tree, a single parent
at the current target and the pinned owner SSH signature. The source, target and
candidate refs are rechecked. A normal clean route cannot use this exception.

## Activate the protected policy

1. Record fresh `development`, `staging` and `main` SHAs and the intended patch
   hash. Keep candidate work in an isolated checkout. Enter code changes through
   `fix/*` and qualify the exact revision with the existing Ansible, Actions and
   Jenkins controls. A receipt for an earlier tree cannot attest the new one.
2. Determine how the currently enforced policy can admit its own update. If it
   rejects the required reconciliation, stop only that protected write and give
   the owner the exact files, before/after hashes, current policy rejection,
   rollback and proposed activation path. Do not claim an earlier bootstrap
   authorization, weaken required checks, or execute the new PR evaluator to
   make its own privileged check green. The activation decision must identify
   the authorized mechanism and writer before applying it.
3. Verify the reviewed evaluator and all imports at each protected target that
   will execute it. Enable neither the new Jenkins call nor draft creation on a
   target that still has an incompatible evaluator. An unsupported CLI or old
   policy is a visible failure, not a fallback to candidate code.
4. Qualify GitHub and Jenkins on the same real PR head and current target. Keep
   candidate bytes out of privileged publishing contexts. The Jenkins job or a
   protected controller must independently require the adapter and authenticate
   the resulting exact-head evidence; a call inside the PR Jenkinsfile alone
   does not establish that trust boundary.
5. Configure stable PR discovery for the approved repository and supported
   routes through reviewed Jenkins configuration. Validate one allowed and one
   rejected PR before removing per-PR discovery entries. Do not widen a live
   filter blindly or start a build merely because a branch was discovered.

## Negative acceptance cases

Run isolated local fixtures first, then the applicable controlled CI checks.
Keep each receipt's head, base, candidate tree, policy revision and emitter.

| Case | Required observation |
|---|---|
| Ordinary route has no changes, a conflict, or a different resulting tree | Candidate evaluation fails; no merge is authorized. |
| Reconciliation has wrong parent, tree, source trailer or signing key | Both evaluators fail on the same inputs. |
| Source, target or candidate moves during evaluation | Evidence becomes stale and the attempt fails. |
| PR replaces its own verifier or workflow | Protected evaluator is still used; draft provenance rejects a changed workflow definition. |
| Latest Actions attempt or Jenkins status is pending/failed | An older successful result cannot create the main draft. |
| Ansible receipt/check belongs to a different integration | Main draft remains held; no replacement receipt is fabricated. |
| Main PR already exists or refs change before creation | No duplicate or outdated draft is created. |
| Only one platform or one image is validated | The full native multi-image plan remains incomplete. |

Enable `RAGNARSEC_CREATE_MAIN_DRAFTS` only after its read-only preflight and draft
permissions have been observed with real metadata. For Ansible, distinguish the
accepted `fix/*` integration evidence from a new check on a promotion head. If
every promotion head must carry a separate `ansible/validate`, define and qualify
that protected publisher contract explicitly; this draft verifier does not
invent that check.

## Complete automation and release

Keep the owner review and squash to staging. Automated main merge additionally
needs the authenticated collector and server-side stale-base protection described
in [the evidence gate contract](promotion-evidence-gate.md). A head-only compare
does not prevent the base moving after a check. Required emitters, all native
image lanes, SBOM/scan receipts and any merge-candidate integration must be
proven against the real services before enabling automatic merge.

Publication is a separate approved run on the final verified main commit. It
must use the validated digests and signatures; a green development test suite
or a signed reconciliation is not release admission. Destination admission,
deployment, functional checks and recovery remain per-service operations.

## Maintenance

Keep this runbook independent of PR numbers, dates and temporary host paths.
Keep operational logs in approved custody. Remove completed manifests from the
tip according to [their lifecycle](../../reconciliation/README.md), preserving
immutable provenance. Retain reusable policy and negative tests, including the
offline evidence contract, until an explicitly reviewed successor replaces them.
