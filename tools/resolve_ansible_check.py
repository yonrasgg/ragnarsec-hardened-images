"""Bind an Ansible check request to a live same-repository development PR."""
import json
import os
from pathlib import Path
import re
import sys

from ansible_receipt_gate import _gh_json
from prepare_staging_draft import Hold, REPO, local_repo, oid, require


WORKFLOW = 'promotion-route-preflight.yml'


def resolve(event, get):
    run = event['workflow_run']
    head = run.get('head_sha')
    require(event.get('action') == 'completed'
            and local_repo(event.get('repository'))
            and local_repo(run.get('head_repository'))
            and run.get('event') == 'pull_request'
            and run.get('status') == 'completed'
            and oid(head), 'unexpected-check-trigger')
    workflow_id = get(f'actions/workflows/{WORKFLOW}').get('id')
    require(type(workflow_id) is int and workflow_id > 0 and run.get('workflow_id') == workflow_id,
            'unexpected-trigger-workflow')

    linked = run.get('pull_requests') or []
    if not linked:
        linked = get(f'commits/{head}/pulls?per_page=100')
        require(isinstance(linked, list) and len(linked) < 100, 'incomplete-associated-pr-list')
        linked = [pr for pr in linked if pr.get('state') == 'open'
                  and (pr.get('head') or {}).get('sha') == head
                  and (pr.get('base') or {}).get('ref') == 'development']
    require(isinstance(linked, list) and len(linked) == 1, 'ambiguous-check-pr')
    number = linked[0].get('number')
    require(type(number) is int and 0 < number < 10**10, 'invalid-check-pr')

    pr = get(f'pulls/{number}')
    source, target = pr.get('head') or {}, pr.get('base') or {}
    require(pr.get('number') == number and pr.get('state') == 'open'
            and source.get('sha') == head
            and local_repo(source.get('repo')) and local_repo(target.get('repo'))
            and re.fullmatch(r'fix/[A-Za-z0-9][A-Za-z0-9._-]*', source.get('ref', ''))
            and target.get('ref') == 'development' and oid(target.get('sha')),
            'check-pr-is-not-the-current-development-candidate')
    base = get('git/ref/heads/development')['object']['sha']
    require(target['sha'] == base, 'check-pr-base-moved')
    return {'pr_number': number, 'head_sha': head, 'base_sha': base}


def main():
    try:
        require(os.environ.get('GITHUB_REPOSITORY') == REPO
                and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_run'
                and os.environ.get('GITHUB_REF') == 'refs/heads/main', 'unprotected-check-policy')
        event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_bytes())
        print(json.dumps(resolve(event, lambda path: json.loads(_gh_json(f'repos/{REPO}/{path}'))),
                         sort_keys=True))
    except Hold as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (KeyError, TypeError, AttributeError, ValueError, OSError, RuntimeError):
        print('invalid-or-unavailable-check-context', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
