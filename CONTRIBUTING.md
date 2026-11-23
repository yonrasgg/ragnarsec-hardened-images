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
| `main` | Repository default and release | pull request from `staging` only | yes, with `PUBLISH` and approval |
| `staging` | Full validation and human review | pull request from `development` only | no |
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

### Promotion order

1. Every correction starts on `fix/*` and enters `development` only after the
   approved Ansible checks pass. Jenkins image checks do not replace Ansible.
2. After integration, Actions can open a `development → staging` **draft**.
   A human reviews the checks, marks it ready and performs **Squash and merge**.
3. Jenkins validates the exact staged changes. Only complete, current and
   enforced Jenkins evidence may drive automatic promotion to `main`. The
   staging draft workflow does not perform that promotion or Publish.
4. A confirmed failed gate sends the correction through a new `fix/*` branch
   into `development`; pending, stale or missing evidence holds the process.

The `prepare-staging-draft` workflow has a read-only preflight and an opt-in
draft-only job, with no contents write permission. Before setting
`RAGNARSEC_CREATE_STAGING_DRAFTS=true`, configure the approved `RAGNARSEC_ANSIBLE_APP_ID`
and `RAGNARSEC_ANSIBLE_CHECK_NAME`, verify GitHub requires that strict check on
`development`, and qualify GitHub's permission to create drafts. The trusted
Ansible check output must contain `pr=<number>;base=<sha>;head=<sha>` on the
reviewed head and complete before its squash. The workflow does not generate
or attest this proof itself. Existing staging PRs are left untouched.

Before promotion, also run `python3 tools/publication_guard.py . --history`
against a complete checkout. Deleting an internal file at the tip is insufficient
if it remains in the history being published. A shallow checkout cannot pass
that history-path check. The separate secret scanner must still inspect the
intended history; neither control replaces the other.
