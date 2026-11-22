# Promotion evidence gate: offline contract

This is the **decision-only** portion of the `staging → main` gate. It has no
network access, is not called by the observer or Jenkins, cannot post a status
and cannot authorize a merge. A complete evaluation always reports
`merge_authorized: false`. Do not configure it as a required check yet.

## Trust and data contract

| Input | Trusted producer and binding |
|---|---|
| `expected` | Controller resolves repository ID, PR number, reviewed head, actual base, evaluated candidate, and trusted policy revision. |
| `live` | Fresh GitHub PR and ref reads plus the active candidate/policy, including source repository, source/target branches, open state, and draft flag. |
| `plan` | Controller computes exact required image lanes and all build dependencies from the evaluated candidate and base. It may be empty only after proving no image validation is needed. PR metadata and `IMAGE` cannot shrink it. |
| `checks` | Current successful Jenkins source, contract and secret checks, bound to the same identity as `expected`. |
| `receipts` | Current authenticated Jenkins run per lane, explicit `PUBLISH=false`, verified run and summary SHA-256, and confirmed enforcing scan and matching SBOM for every planned AMD64/ARM64 pair. |

The evaluator checks consistency, not authentication. A positive `app_id` or
`scan_enforced` in an arbitrary payload proves nothing. The collector must
authenticate the GitHub App and the private Jenkins run independently of PR
content. It must not follow a status `target_url`, equate repeated status names
with multiple receipts, or use the Trivy license-severity tally as a security
verdict. A failed or pending replacement cannot be hidden by selecting an old
success. Do not derive the policy revision from untrusted PR code.

## Runtime acceptance still required

1. Compare a live Actions `status` observation to an authentic exact-head Jenkins
   result. It remains non-authorizing.
2. Implement the trusted collector and assert the negative cases against real
   GitHub/Jenkins metadata. Bind receipts to the base used when validating, not
   to whichever ref is live after Jenkins finishes.
3. Prove server-side invalidation when the base moves between verification and
   merge. `--match-head-commit` only protects the head. A merge queue is a
   candidate: GitHub needs required checks also on the `merge_group` candidate,
   and third-party Jenkins must qualify that candidate, not reuse the PR head
   status. Verify squash/signature behavior in an approved test lane first.
4. Only then review any protected ruleset and permission change. Owner still
   operates `staging`. Keep publishing and deployment separate.

Reference: [GitHub merge queue CI requirements](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue#configuring-continuous-integration-ci-workflows-for-merge-queues).

## Test evidence

- RED: `python3 -m unittest discover -s tests -p 'test_public_promotion_evidence.py'`
  failed at the missing module, before implementation.
- GREEN: the same command passed 12 tests. Coverage via Python's standard
  `trace` module was 96.5% of executable evaluator lines; it is not branch or
  live enforcement coverage.
- Full `test_public*.py` suite: 182 passed, one existing skip. Negative cases
  include one green out of two, wrong base with the same head, a stale candidate
  or policy, wrong PR/issuer, missing or duplicate native receipts, and
  unsuccessful or publication-enabled runs.
