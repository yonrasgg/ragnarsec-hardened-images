"""Prepare a main promotion draft from a verified, owner-reviewed staging squash."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

from jenkins_promotion_route import RouteUnavailable
from prepare_staging_draft import (
    Hold, REPO, REPO_ID, api, fingerprint, local_repo, oid, require, verify_jenkins_status,
)
from promotion_candidate import assess
from promotion_route import PreflightError, Repository


OWNER_ID = 87682163
OPEN_MAIN = 'pulls?state=open&base=main&per_page=100'


def ordinary_route(staging, main):
    def side(ref, sha):
        return dict(ref=ref, sha=sha, repo=dict(id=REPO_ID, full_name=REPO))

    event = {'pull_request': {'head': side('staging', staging), 'base': side('main', main)}}
    repo = Repository('.')
    code, reason = assess(event, repo)
    require(code == 0, f'ordinary-main-route-{reason}')
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
            and src.get('ref') == 'development' and dest.get('ref') == 'staging'
            and all(local_repo(side.get('repo')) for side in (src, dest))
            and oid(src.get('sha')) and oid(dest.get('sha')),
            'not-an-owner-reviewed-ordinary-staging-squash')
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
    require(get(OPEN_MAIN) == [], 'main-pr-already-open')
    require(route(staging, main) == tree, 'ordinary-main-route-tree-mismatch')
    return dict(staging_pr=number, staging=staging, main=main, tree=tree,
                staging_jenkins_status=status)


def create_once(get, post, staging, expected, route=ordinary_route):
    plan = plan_draft(get, staging, route)
    require(fingerprint(plan) == expected, 'main-draft-plan-changed')
    draft = post('pulls', dict(title='Promote the reviewed staging tree to main',
                              head='staging', base='main', draft=True, body=(
                                  f"Owner-reviewed staging PR #{plan['staging_pr']} integrated as "
                                  f"`{plan['staging']}` with tree `{plan['tree']}`.\n\n"
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
        print(json.dumps(dict(result='held', reason=str(exc))))
        return 2 if args.create_plan is not None else 0
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError, PreflightError):
        print(json.dumps(dict(result='held', reason='main-draft-evidence-unavailable')))
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(run())
