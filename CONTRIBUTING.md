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
| `development` | Integration (default) | short-lived branches by pull request | no |
| `staging` | Full validation and human review | fast-forward from `development` | no |
| `main` | Release | fast-forward from `staging` | yes, with `PUBLISH` and approval |

Short-lived branches: `feat/<slug>`, `fix/<slug>`, `chore/<slug>`, `docs/<slug>`
and `agent/<slug>`. Branch from `development`, open a pull request back to
`development`, and delete the branch after merge.

Promotion is linear:

1. Pull request to `development`: contract tests, secret scan and image plan;
   squash merge. GitHub creates and signs the squash commit.
2. Pull request `development` -> `staging`: full image validation (build, scan,
   SBOM and signature verification) and human review. Fast-forward or rebase;
   no publication.
3. Pull request `staging` -> `main`: only for a commit already validated in
   `staging`; human approval, fast-forward, signed tag `vX.Y.Z`, then publication
   with `PUBLISH` and the Jenkins approval step.

Jenkins fails a `staging` build whose commit is not contained in `development`,
and a `main` build whose commit is not contained in `staging`. Direct pushes,
force pushes and branch deletion are blocked on the three long-lived branches;
`staging` and `main` additionally require signed commits.

`development` accepts unsigned commits from short-lived branches, but only
through a pull request; the squash commit is created and signed by GitHub.
Feature pull requests must use **Squash and merge**; do not rebase unsigned
commits into `development`. Promotion pull requests carry only the signed squash
commits already present in `development`.

Until a machine identity exists, the repository owner is the only merger to
`staging` and `main`; automation opens pull requests but does not merge them.

Bootstrap exception: the initial catalog was reviewed and signed by the owner
before the first promotion; subsequent changes follow the full flow.

A clean scan is scoped evidence, not a guarantee. Report potential sensitive
material privately through the repository owner's GitHub profile contact options;
never open an issue containing a credential or confidential reproduction.

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

Before promotion, also run `python3 tools/publication_guard.py . --history`
against a complete checkout. Deleting an internal file at the tip is insufficient
if it remains in the history being published. A shallow checkout cannot pass
that history-path check. The separate secret scanner must still inspect the
intended history; neither control replaces the other.
