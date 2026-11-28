# Adding and maintaining an image

1. State its reusable purpose without naming deployed hosts, tenants or clients.
2. Record upstream project, source version/digest and applicable license notices.
3. Review FROM/COPY/ADD, build context, downloads and architecture support. Never
   assume an upstream tag or advertised feature proves a verified binary.
4. Add meaningful startup, security and persistence tests. Prefer non-root,
   minimal capabilities and no embedded credentials. Record exact tested digests.
5. Check examples use reserved documentation identifiers; keep runtime secrets,
   TLS material, inventories and environment files outside this repository.
6. Run `python3 -m unittest discover -s tests -p 'test_public*.py'`,
   `python3 tools/publication_guard.py .`, and a pinned full secret/history scan.
   The Jenkins pipeline runs the same checks; a green build is required before merge.
7. Review build and vulnerability results before merging. Publication and deployment
   are separate approvals; no automated downstream dispatch is configured.

## Branch and promotion model

Long-lived branches:

| Branch | Purpose | Accepts | Publishes |
|---|---|---|---|
| `main` | Repository default and release | reviewed `staging` tree | yes, with `PUBLISH` and approval |
| `staging` | Full validation and human review | reviewed `development` tree | no |
| `development` | Integration | short-lived branches by pull request | no |

The order is fixed: `development` -> `staging` -> `main`. It is never skipped,
reversed or shortened, including for urgent fixes and AI-agent work. `main` is
the repository default branch, so a new pull request must have its base changed
to `development` before it can be reviewed.

Short-lived branches: `feat/<slug>`, `fix/<slug>`, `chore/<slug>`, `docs/<slug>`
and `agent/<slug>`. Branch from `development`, open a pull request back to
`development`, and delete the branch after merge.

Promotion is linear:

1. Pull request to `development`: contract tests, secret scan and image plan;
   squash after required checks pass. If validation fails, keep the PR open for
   review and repair it there.
2. Draft pull request `development` -> `staging`: qualify the exact candidate
   for every image in the plan on native AMD64 and ARM64 with `PUBLISH=false`.
   After human review, the owner performs the protected squash and verifies the
   resulting commit signature and expected tree.
3. Draft pull request `staging` -> `main`: recheck the actual `staging` head and
   current `main` base and qualify the exact candidate again. The protected
   squash to `main` is intended to be automatic only after required GitHub
   enforcement is proven to reject stale or incomplete evidence for that route.
   Until then, leave automation disabled rather than weakening protection.
   Publication is a separate run on the approved `main` revision with `PUBLISH`
   and the Jenkins approval step; deployment is not part of either squash.

A PR with a confirmed promotion failure is closed unmerged and returned to the
sender for a fix in `development`. Missing, pending, or stale evidence blocks the promotion without
being treated as a failed validation. Never waive a check to preserve a schedule.

Jenkins rejects a `staging` build whose commit is not traceable to
`development`, and a `main` build whose commit is not traceable to `staging`.
A squash changes the commit SHA; its exact tree must still match the validated
source tree for provenance. Merge commits are disabled. Direct pushes, force
pushes and branch deletion are blocked on the three long-lived branches;
`staging` and `main` additionally require signed commits.

The ordinary PR source is the upstream protected branch. If its ordinary merge
has a reproducible content conflict, the protected evaluator can qualify a
signed reconciliation carrying the exact same upstream tree. This is a route
to review, not permission to merge or a way to omit a required check.

`development` accepts unsigned commits from short-lived branches, but only
through a pull request; the squash commit is created and signed by GitHub.
Feature pull requests must use **Squash and merge**; do not rebase unsigned
commits into `development`. Do not use GitHub Rebase and Merge as a substitute
for the verified signature required on a promotion.

Only the owner reviews and squash-merges into `staging`; automation prepares
that draft and its validation, never its merge.

Bootstrap exception: the initial catalog was reviewed and signed by the owner
before the first promotion; subsequent changes follow the full flow.

A clean scan is scoped evidence, not a guarantee. Report potential sensitive
material privately through the repository owner's GitHub profile contact options;
never open an issue containing a credential or confidential reproduction.

### Promotion preflight

Before opening any pull request into `staging` or `main`, verify the published
source and target tips and every incoming commit's GitHub signature. An
unsigned or unverifiable commit blocks draft creation and Jenkins dispatch.
Recheck the exact SHAs before validation. Signing or replacing a commit changes
its SHA and requires new checks; a successful check never transfers to it.
For the standard `development` to `staging` transition after fetching:

```sh
python3 tools/promotion_signatures.py --source development --target staging \
  --head "$(git rev-parse refs/remotes/origin/development)" \
  --base "$(git rev-parse refs/remotes/origin/staging)"
```

Run the [route checker](tools/promotion_route.py) with Git 2.38 or newer from a
trusted, complete checkout. Fetch the three branch tips together, simulate both
squashes, and record the JSON receipt:

```sh
git fetch --atomic --no-tags origin \
  refs/heads/development:refs/remotes/origin/development \
  refs/heads/staging:refs/remotes/origin/staging \
  refs/heads/main:refs/remotes/origin/main
python3 tools/promotion_route.py \
  --development "$(git rev-parse refs/remotes/origin/development)" \
  --staging "$(git rev-parse refs/remotes/origin/staging)" \
  --main "$(git rev-parse refs/remotes/origin/main)"
```

Adding `--fix-head` with an exact PR head from the same clone also simulates the
integration squash before both promotions. Run the full check before staging a
batch, including changes that only affect shared pipeline code. After the staging
squash, fetch again, compare the actual tree with the expected one and re-run the
direct check with `--staging-to-main-only` and only the actual staging and main
SHAs. If any participating ref moves, recompute the candidate and obtain fresh
evidence. Review the changed paths and compare the simulated tree with the
candidate reported by GitHub before relying on the receipt. If a promotion
phase reports `source_tree_matches: false`, stop: a clean Git merge can still
include target-only changes and differ from the reviewed source tree.

Exit `1` reports a content conflict with paths; exit `2` reports an incomplete
check. Exit `0` only shows that the input commits can merge cleanly. The checker
does not move refs, sign commits, or authorize a merge. Jenkins evidence must
still cover every planned image against the exact head, base, candidate, and
trusted policy. One image's successful status cannot approve a multi-image
promotion. Formal deployment additionally requires signed digests, a batch
preflight, and per-service acceptance and rollback checks.

### Reusable reconciliation contract

For a genuinely conflicting ordinary route, the only supported reconciliation
name is `sync/<source>-to-<target>-<full-source-sha>`. The candidate must have one
parent equal to the current target, the exact protected source tree, and the
owner SSH signature over this trailer:

```text
RagnarSec-Promotion-Source: <source>@<full-source-sha> -> <target>
```

Actions loads `tools/promotion_candidate.py` from the protected target. Jenkins
uses `tools/verify_protected_promotion.sh` to load that evaluator from the same
live target; the adapter rejects a synthetic merge checkout and an unexpected
job, repository, fork or PR context. Both verify refs before and after the
simulation. Do not add another date, PR number or one-time branch exception to
`Jenkinsfile`. No candidate or receipt is signed by this evaluator.

The target must already contain the reviewed policy. A new evaluator in a PR
cannot install or authorize itself under an older target policy. Likewise,
calling the adapter from a PR's Jenkinsfile does not prove that Jenkins enforces
it independently of PR code. The
[activation and enforcement runbook](.github/tdd/rollout-promotion-candidate.md)
separates those live acceptance steps from local tests.

## Local commit gate

After reviewing the hook, enable it with `git config core.hooksPath .githooks`.
Provide a verified Gitleaks binary on PATH or through GITLEAKS_BIN. The hook
checks the worktree boundary, regression tests and staged secret diff. A full
history/ref scan remains required for release. The Jenkins build is an additional
check; making it a required status check is a separate repository setting.

## Documentation contract

Keep public documentation limited to image purpose, public build inputs, usage,
hardening, patching, test definitions and verifiable control results. Do not add
organization architecture, deployment maps, host/customer identities, inventories,
capacity plans, operational decisions or private evidence. A workflow definition
must not be described as a passed control; a receipt needs the exact image digest,
run, tool versions and declared exclusions. See the per-image README structure.

## Publication scope

Keep assistant instructions, agent definitions, context/routing metadata,
operational handoffs and deployment architecture outside this repository.
Ignore rules are preventive only: the publication guard also checks files
that were force-added or already tracked. Do not bypass that guard.

## Local validation and CI

Run `python3 -m unittest discover -s tests -p 'test_public*.py'` and
`python3 tools/publication_guard.py .` before submitting changes. Use the
same portable commands in another CI engine rather than duplicating policy.
`python3 tools/image_ci.py plan --image ragnarsec-base` is a read-only build
plan; `validate` requires a disposable AMD64 build environment and pinned tools.
Never run image builds against a production Docker engine.

Pull requests run read-only publication checks. Image validation is manual,
limited to a selected recipe and required parents, with a timeout and serialized
runs. Publication additionally requires owner enablement and approval through
the protected environment. No persistent Actions artifact uploads or cross-run
caches are configured. Cost/billing settings are managed outside this catalog;
workflow limits alone do not prove an account spending cap.

### Automated drafts and Ansible provenance

Every correction starts on `fix/*` and enters `development` only after the
approved Ansible checks pass. Jenkins image checks do not replace Ansible.
The promotion order and owner-operated staging squash remain as defined above.

The `prepare-staging-draft` workflow has a read-only preflight and an opt-in
draft-only job, with no contents write permission. Before setting
`RAGNARSEC_CREATE_STAGING_DRAFTS=true`, configure the approved `RAGNARSEC_ANSIBLE_APP_ID`
and `RAGNARSEC_ANSIBLE_CHECK_NAME`, verify GitHub requires that strict check on
`development`, and qualify GitHub's permission to create drafts. The trusted
Ansible check output must contain `pr=<number>;base=<sha>;head=<sha>` on the
reviewed head and complete before its squash. The workflow does not generate
or attest this proof itself. Existing staging PRs are left untouched.

The opt-in `prepare-main-draft` workflow runs from protected `main` after a
staging notification. It requires the owner's signed staging squash, the exact
tree and parent, successful pre-merge Actions and Jenkins evidence, and the
Ansible receipt from the corresponding integrated `fix/*` PR. The Actions proof
is bound to its workflow, issuer, latest run and attempt, and a workflow
definition matching protected policy. The report labels Ansible as integration
provenance; it is not a new Ansible run or check on a promotion head.

The main draft is created only if the ordinary `staging` to `main` simulation
is clean and exact, the live refs still match, no main PR exists and
`RAGNARSEC_CREATE_MAIN_DRAFTS=true` is enabled. A conflict produces the pinned
refs and conflict paths for a reviewed correction or policy activation. The
workflow does not invent a signature, retry the same failure indefinitely,
merge, publish or alter Jenkins job discovery. Its read-only preflight can run
without enabling draft creation.

For new receipt histories, add `receipts/ansible/<reviewed-parent-sha>.json`
in a commit whose only change is that signed receipt. The verifier derives the
path from the exact parent and checks that removing the file reconstructs the
parent tree, including previously recorded receipts. The legacy singleton
layout remains supported on commits that predate the versioned directory.

### Repository hygiene

Keep reusable build tools, policy, tests and current PR manifests here. Remove a
completed operation's manifest from the tip only after checking its consumers
and immutable Git history; see [manifest lifecycle](reconciliation/README.md).
Do not delete a signed receipt merely because its PR merged. Operational
captures, draft evidence, credentials and host-specific handoffs belong in their
approved external custody, not in the public image catalog.

Python contract tests use `tests/test_public*.py`, the pattern used by the local
hook and Jenkins. Preserve reusable negative cases for signatures, provenance,
concurrency, scan policy and native image evidence. Consolidate duplicate test
loaders and remove assertions for retired one-time branch names when equivalent
behavioral coverage exists; test count alone is not the maintenance target.

Before promotion, also run `python3 tools/publication_guard.py . --history`
against a complete checkout. Deleting an internal file at the tip is insufficient
if it remains in the history being published. A shallow checkout cannot pass
that history-path check. The separate secret scanner must still inspect the
intended history; neither control replaces the other.
