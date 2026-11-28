"""Prepare a main promotion draft from a verified, owner-reviewed staging squash."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import urlencode

from jenkins_promotion_route import RouteUnavailable
from prepare_staging_draft import (
    Hold, REPO, REPO_ID, api, before_merge, fingerprint, local_repo, oid,
    receipt_binding, require, verify_jenkins_status,
)
from promotion_candidate import SYNC_TRAILER, assess, sync_revision
from promotion_route import PreflightError, Repository


OWNER_ID = 87682163
OPEN_MAIN = 'pulls?state=open&base=main&per_page=100'
ACTIONS_APP_ID = 15368
ACTIONS_CHECK = 'Verify exact promotion candidate (Actions)'
ACTIONS_WORKFLOW = 'check-promotion-candidate.yml'
ANSIBLE_APP_ID = 5929884
ANSIBLE_CHECK = 'ansible/validate'


class MainRouteHold(Hold):
    """A genuine route failure with pinned inputs, never permission to retry blindly."""

    def __init__(self, reason, staging, main, phases):
        super().__init__(f'ordinary-main-route-{reason}')
        self.details = dict(staging=staging, main=main,
                            conflict_paths=sorted({path for phase in phases
                                                   for path in phase.get('conflict_paths', [])}),
                            next_action='prepare-reviewed-correction-or-protected-policy-update')


def latest_check(get, head, name, app_id):
    query = urlencode(dict(check_name=name, filter='latest', per_page=100))
    response = get(f'commits/{head}/check-runs?{query}')
    require(response.get('total_count', 100) < 100, 'incomplete-check-list')
    checks = [check for check in response.get('check_runs', [])
              if check.get('name') == name and check.get('head_sha') == head
              and (check.get('app') or {}).get('id') == app_id]
    require(len(checks) == 1 and type(checks[0].get('id')) is int and checks[0]['id'] > 0,
            'missing-or-ambiguous-trusted-check')
    return checks[0]


def verify_actions(get, number, head, parent, merged_at):
    """Require the latest real run, not a name-only or PR-defined success."""
    check = latest_check(get, head, ACTIONS_CHECK, ACTIONS_APP_ID)
    require(check.get('status') == 'completed' and check.get('conclusion') == 'success'
            and before_merge(check, merged_at), 'actions-missing-pre-merge-success')
    workflow = get(f'actions/workflows/{ACTIONS_WORKFLOW}')
    workflow_id = workflow.get('id')
    require(type(workflow_id) is int and workflow_id > 0, 'actions-workflow-unavailable')
    query = urlencode(dict(head_sha=head, event='pull_request', per_page=100))
    response = get(f'actions/workflows/{workflow_id}/runs?{query}')
    runs = response.get('workflow_runs')
    require(response.get('total_count', 100) < 100 and isinstance(runs, list) and runs,
            'actions-runs-missing-or-incomplete')
    # GitHub lists workflow runs newest first. A pending replacement must hold
    # even while an earlier successful check remains visible.
    latest = runs[0]
    run_id = latest.get('id')
    require(type(run_id) is int and run_id > 0, 'actions-latest-run-unavailable')
    run = get(f'actions/runs/{run_id}')
    associated = run.get('pull_requests') or []
    require(run.get('id') == run_id and run.get('workflow_id') == workflow_id
            and run.get('path') == f'.github/workflows/{ACTIONS_WORKFLOW}'
            and run.get('event') == 'pull_request' and run.get('head_sha') == head
            and run.get('status') == 'completed' and run.get('conclusion') == 'success'
            and local_repo(run.get('repository')) and local_repo(run.get('head_repository'))
            and type(run.get('check_suite_id')) is int
            and run['check_suite_id'] == (check.get('check_suite') or {}).get('id')
            and any(pr.get('number') == number and (pr.get('head') or {}).get('sha') == head
                    and (pr.get('base') or {}).get('sha') == parent for pr in associated),
            'actions-run-not-bound-to-staging-review')
    attempt = run.get('run_attempt')
    require(type(attempt) is int and attempt > 0, 'actions-run-attempt-unavailable')
    response = get(f'actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100')
    jobs = response.get('jobs') or []
    require(response.get('total_count', 100) < 100, 'actions-jobs-incomplete')
    linked = [job for job in jobs
              if job.get('check_run_url') ==
              f'https://api.github.com/repos/{REPO}/check-runs/{check["id"]}']
    require(len(linked) == 1 and linked[0].get('name') == ACTIONS_CHECK
            and linked[0].get('status') == 'completed' and linked[0].get('conclusion') == 'success'
            and before_merge(linked[0], merged_at), 'actions-check-not-from-latest-attempt')
    # The workflow is supplied by the PR event. Matching the protected base
    # definition prevents a PR from replacing the verifier with a green job.
    path = f'.github/workflows/{ACTIONS_WORKFLOW}'
    protected = get(f'contents/{path}?ref={parent}')
    candidate = get(f'contents/{path}?ref={head}')
    require(protected.get('type') == candidate.get('type') == 'file'
            and oid(protected.get('sha')) and protected['sha'] == candidate.get('sha'),
            'actions-workflow-differs-from-protected-base')
    return dict(check=check['id'], run=run_id, attempt=attempt, policy=parent,
                workflow_blob=protected['sha'])


def staging_upstream(get, source, parent, tree):
    """Recover the immutable reviewed development commit, not its live tip."""
    name, head = source['ref'], source['sha']
    if name == 'development':
        return head
    upstream = sync_revision(name, 'staging')
    require(upstream is not None, 'unsupported-staging-source')
    candidate = get(f'git/commits/{head}')
    verification = candidate.get('verification') or {}
    trailers = (candidate.get('message') or '').rstrip('\n').split('\n\n')[-1].splitlines()
    values = [line.partition(':')[2].strip() for line in trailers
              if line.partition(':')[0] == SYNC_TRAILER]
    require(candidate.get('sha') == head
            and [p.get('sha') for p in candidate.get('parents', [])] == [parent]
            and verification.get('verified') is True and verification.get('reason') == 'valid'
            and (verification.get('signature') or '').startswith('-----BEGIN SSH SIGNATURE-----')
            and values == [f'development@{upstream} -> staging']
            and get(f'git/commits/{upstream}')['tree']['sha'] == tree,
            'reconciled-staging-source-not-bound')
    # The exact-head Actions proof separately verifies this SSH signature with
    # the owner key pinned in protected target policy. No new signature is made.
    return upstream


def inherited_ansible(get, upstream, tree, staging_merged_at):
    """Trace the accepted integration receipt; do not emit a promotion check."""
    associated = get(f'commits/{upstream}/pulls?per_page=100')
    require(len(associated) < 100, 'incomplete-development-pr-associations')
    merged = [pr for pr in associated if pr.get('merge_commit_sha') == upstream
              and (pr.get('base') or {}).get('ref') == 'development'
              and pr.get('state') == 'closed' and pr.get('merged_at')]
    require(len(merged) == 1, 'missing-or-ambiguous-development-pr')
    number = merged[0].get('number')
    require(type(number) is int and number > 0, 'invalid-development-pr-number')
    pr = get(f'pulls/{number}')
    source, target = pr.get('head') or {}, pr.get('base') or {}
    head, base = source.get('sha'), target.get('sha')
    require(pr.get('number') == number and pr.get('merged') is True
            and pr.get('state') == 'closed' and pr.get('merge_commit_sha') == upstream
            and target.get('ref') == 'development'
            and re.fullmatch(r'fix/[A-Za-z0-9][A-Za-z0-9._-]*', source.get('ref', ''))
            and all(local_repo(side.get('repo')) for side in (source, target))
            and oid(head) and oid(base)
            and before_merge({'completed_at': pr.get('merged_at')}, staging_merged_at),
            'ansible-origin-is-not-an-integrated-fix')
    integrated = get(f'git/commits/{upstream}')
    signature = integrated.get('verification') or {}
    receipt_head = get(f'git/commits/{head}')
    parents = [p.get('sha') for p in receipt_head.get('parents', [])]
    require(integrated.get('sha') == upstream
            and signature.get('verified') is True and signature.get('reason') == 'valid'
            and [p.get('sha') for p in integrated.get('parents', [])] == [base]
            and (integrated.get('tree') or {}).get('sha') == tree
            and (receipt_head.get('tree') or {}).get('sha') == tree
            and len(parents) == 1 and oid(parents[0]), 'ansible-origin-tree-or-parent-mismatch')
    check = latest_check(get, head, ANSIBLE_CHECK, ANSIBLE_APP_ID)
    require(check.get('status') == 'completed' and check.get('conclusion') == 'success'
            and before_merge(check, pr.get('merged_at'))
            and (check.get('output') or {}).get('summary') == f'pr={number};base={base};head={head}',
            'ansible-missing-bound-pre-merge-success')
    response = get(f'git/trees/{tree}')
    entries = response.get('tree')
    require(response.get('truncated') is not True and isinstance(entries, list),
            'ansible-origin-tree-unreadable')
    receipt = receipt_binding(check, tree, entries)
    require(receipt is not None and receipt['target_commit_sha'] == parents[0],
            'ansible-origin-receipt-not-bound')
    return dict(mode='verified-integration-provenance', integration_pr=number,
                integration_head=head, development=upstream, check=check['id'], **receipt)


def ordinary_route(staging, main):
    def side(ref, sha):
        return dict(ref=ref, sha=sha, repo=dict(id=REPO_ID, full_name=REPO))

    event = {'pull_request': {'head': side('staging', staging), 'base': side('main', main)}}
    repo = Repository('.')
    code, reason = assess(event, repo)
    if code != 0:
        raise MainRouteHold(reason, staging, main, repo.phases)
    return repo.phases[-1]['tree']


def plan_draft(get, staging, route=ordinary_route):
    require(oid(staging) and get('git/ref/heads/staging')['object']['sha'] == staging,
            'staging-event-is-not-current')
    main = get('git/ref/heads/main')['object']['sha']
    require(oid(main), 'main-ref-unavailable')

    associated = get(f'commits/{staging}/pulls?per_page=100')
    require(len(associated) < 100, 'incomplete-staging-pr-associations')
    merged = [item for item in associated if item.get('merge_commit_sha') == staging
              and (item.get('base') or {}).get('ref') == 'staging'
              and item.get('state') == 'closed' and item.get('merged_at')]
    require(len(merged) == 1, 'missing-or-ambiguous-staging-pr')
    number = merged[0].get('number')
    require(type(number) is int and 0 < number < 10**10, 'invalid-staging-pr-number')
    pr = get(f'pulls/{number}')
    src, dest = pr.get('head') or {}, pr.get('base') or {}
    require(pr.get('number') == number and pr.get('merged') is True
            and pr.get('state') == 'closed' and pr.get('draft') is False
            and pr.get('merge_commit_sha') == staging
            and (pr.get('merged_by') or {}).get('id') == OWNER_ID
            and isinstance(src.get('ref'), str) and dest.get('ref') == 'staging'
            and all(local_repo(side.get('repo')) for side in (src, dest))
            and oid(src.get('sha')) and oid(dest.get('sha')),
            'not-an-owner-reviewed-staging-squash')
    head, parent = src['sha'], dest['sha']
    integrated = get(f'git/commits/{staging}')
    signature = integrated.get('verification') or {}
    tree = (integrated.get('tree') or {}).get('sha')
    require(integrated.get('sha') == staging and oid(tree)
            and [commit.get('sha') for commit in integrated.get('parents', [])] == [parent]
            and signature.get('verified') is True and signature.get('reason') == 'valid'
            and get(f'git/commits/{head}')['tree']['sha'] == tree,
            'staging-squash-not-signed-with-reviewed-tree')

    main_tree = get(f'git/commits/{main}')['tree']['sha']
    require(oid(main_tree) and get(f'git/commits/{parent}')['tree']['sha'] == main_tree,
            'staging-review-does-not-start-from-current-main-tree')
    require(tree != main_tree, 'nothing-new-for-main')
    status = verify_jenkins_status(get, head, pr.get('merged_at'))
    actions = verify_actions(get, number, head, parent, pr.get('merged_at'))
    upstream = staging_upstream(get, src, parent, tree)
    ansible = inherited_ansible(get, upstream, tree, pr.get('merged_at'))
    require(get(OPEN_MAIN) == [], 'main-pr-already-open')
    require(route(staging, main) == tree, 'ordinary-main-route-tree-mismatch')
    require(get('git/ref/heads/staging')['object']['sha'] == staging
            and get('git/ref/heads/main')['object']['sha'] == main,
            'promotion-refs-moved-during-plan')
    return dict(staging_pr=number, staging=staging, main=main, tree=tree,
                staging_jenkins_status=status, staging_actions=actions,
                ansible_provenance=ansible)


def create_once(get, post, staging, expected, route=ordinary_route):
    plan = plan_draft(get, staging, route)
    require(fingerprint(plan) == expected, 'main-draft-plan-changed')
    draft = post('pulls', dict(title='Promote the reviewed staging tree to main',
                              head='staging', base='main', draft=True, body=(
                                  f"Owner-reviewed staging PR #{plan['staging_pr']} integrated as "
                                  f"`{plan['staging']}` with tree `{plan['tree']}`.\n\n"
                                  f"Staging Actions run `{plan['staging_actions']['run']}` and "
                                  f"Jenkins status `{plan['staging_jenkins_status']}` passed before "
                                  "that review. Ansible evidence is inherited from verified "
                                  f"integration PR #{plan['ansible_provenance']['integration_pr']}; "
                                  "this is not a new Ansible run or check on the promotion head.\n\n"
                                  "Qualify the exact main candidate on Jenkins with publication "
                                  "disabled and retain the per-image validation results."
                              )))
    src, dest = draft.get('head') or {}, draft.get('base') or {}
    number = draft.get('number')
    require(type(number) is int and number > 0 and draft.get('draft') is True
            and all(local_repo(side.get('repo')) for side in (src, dest))
            and src.get('ref') == 'staging' and dest.get('ref') == 'main'
            and src.get('sha') == staging and dest.get('sha') == plan['main'],
            'main-draft-response-moved-review-required')
    return number


def staging_notification(event):
    notification = event.get('workflow_run') or {}
    staging = notification.get('head_sha')
    require(notification.get('event') == 'push' and notification.get('conclusion') == 'success'
            and notification.get('head_branch') == 'staging'
            and local_repo(notification.get('head_repository')) and oid(staging),
            'ignored-staging-notification')
    return staging


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--create-plan')
    args = parser.parse_args()
    try:
        require(os.environ.get('GITHUB_REPOSITORY') == REPO
                and os.environ.get('GITHUB_REF') == 'refs/heads/main'
                and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_run',
                'untrusted-main-draft-workflow')
        event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_bytes())
        staging = staging_notification(event)
        get = lambda path: api('GET', path)
        if args.create_plan is None:
            plan = plan_draft(get, staging)
            with Path(os.environ['GITHUB_OUTPUT']).open('a', encoding='utf-8') as stream:
                stream.write(f'plan={fingerprint(plan)}\n')
            print(json.dumps(dict(plan, result='main-draft-preflight')))
        else:
            token = os.environ.get('MAIN_DRAFT_TOKEN')
            require(os.environ.get('CREATE_MAIN_DRAFTS') == 'true' and bool(token)
                    and re.fullmatch(r'[a-f0-9]{64}', args.create_plan), 'main-draft-creation-disabled')
            def post(path, body):
                return api('POST', path, body, token=token)

            number = create_once(get, post, staging, args.create_plan)
            print(json.dumps(dict(pull_request=number, result='main-draft-created')))
    except (Hold, RouteUnavailable) as exc:
        print(json.dumps(dict(result='held', reason=str(exc), **getattr(exc, 'details', {}))))
        return 2 if args.create_plan is not None else 0
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError, PreflightError):
        print(json.dumps(dict(result='held', reason='main-draft-evidence-unavailable')))
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(run())
