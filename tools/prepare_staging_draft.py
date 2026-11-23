"""Prepare only the development-to-staging draft after exact Ansible proof."""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import urlencode


REPO = 'yonrasgg/ragnarsec-hardened-images'
REPO_ID = 1426336836
OPEN_DRAFTS = 'pulls?state=open&base=staging&head=yonrasgg%3Adevelopment&per_page=100'


class Hold(Exception):
    """Incomplete, stale, or unconfirmed; do not create or promote anything."""


class Correct(Exception):
    """A confirmed failure on the exact reviewed inputs."""


def require(test, reason):
    if not test:
        raise Hold(reason)


def oid(value):
    return isinstance(value, str) and re.fullmatch(r'[a-f0-9]{40}', value) is not None


def local_repo(doc):
    return isinstance(doc, dict) and doc.get('id') == REPO_ID and doc.get('full_name') == REPO


def fingerprint(plan):
    return hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def before_merge(check, merged_at):
    value = check.get('completed_at')
    if not isinstance(value, str) or not isinstance(merged_at, str):
        return False
    try:
        return datetime.fromisoformat(value) <= datetime.fromisoformat(merged_at)
    except (ValueError, TypeError):
        return False


def plan_draft(get, number, check_name, app_id):
    require(type(number) is int and 0 < number < 10**10 and type(app_id) is int and app_id > 0
            and isinstance(check_name, str) and 0 < len(check_name) <= 100,
            'trusted-ansible-binding-not-configured')
    pr = get(f'pulls/{number}')
    src, dest = pr.get('head') or {}, pr.get('base') or {}
    require(pr.get('number') == number and pr.get('merged') is True and pr.get('state') == 'closed'
            and dest.get('ref') == 'development'
            and all(local_repo(side.get('repo')) for side in (src, dest))
            and re.fullmatch(r'fix/[A-Za-z0-9][A-Za-z0-9._-]*', src.get('ref', '')),
            'not-an-integrated-fix-to-development')
    head = src.get('sha')
    dev = get('git/ref/heads/development')['object']['sha']
    stage = get('git/ref/heads/staging')['object']['sha']
    require(all(oid(x) for x in (head, dev, stage)) and pr.get('merge_commit_sha') == dev,
            'not-the-latest-development-squash')
    signed = get(f'commits/{dev}')
    tree = signed['commit']['tree']['sha']
    parents = [p['sha'] for p in signed['parents']]
    signature = signed['commit']['verification']
    require(signed.get('sha') == dev and signature.get('verified') is True
            and signature.get('reason') == 'valid' and len(parents) == 1 and oid(parents[0])
            and oid(tree), 'development-squash-not-verified')
    parent = parents[0]
    require(get(f'git/commits/{head}')['tree']['sha'] == tree,
            'development-tree-is-not-the-reviewed-head-tree')
    rules = get('rules/branches/development')
    require(any(r.get('type') == 'required_status_checks'
                and r['parameters'].get('strict_required_status_checks_policy') is True
                and any(c.get('context') == check_name and c.get('integration_id') == app_id
                        for c in r['parameters'].get('required_status_checks', []))
                for r in rules), 'ansible-not-required-by-github')
    query = urlencode(dict(check_name=check_name, filter='latest', per_page=100))
    checks = get(f'commits/{head}/check-runs?{query}')
    require(checks.get('total_count', 100) < 100, 'incomplete-check-list')
    trusted = [c for c in checks.get('check_runs', [])
               if c.get('name') == check_name and (c.get('app') or {}).get('id') == app_id
               and c.get('head_sha') == head]
    require(len(trusted) == 1, 'missing-or-ambiguous-ansible-check')
    check = trusted[0]
    require(type(check.get('id')) is int and check['id'] > 0 and check.get('status') == 'completed'
            and before_merge(check, pr.get('merged_at'))
            and (check.get('output') or {}).get('summary') == f'pr={number};base={parent};head={head}',
            'ansible-check-not-bound-to-the-integrated-fix')
    if check.get('conclusion') in ('failure', 'timed_out'):
        raise Correct(f'fix/ansible-retry-pr-{number} → development')
    require(check.get('conclusion') == 'success', 'ansible-did-not-succeed')
    require(get(f'git/commits/{stage}')['tree']['sha'] != tree, 'nothing-new-for-staging')
    require(get(OPEN_DRAFTS) == [], 'staging-pr-already-open')
    return dict(pr=number, head=head, development=dev, staging=stage, ansible_check=check['id'])


def create_once(get, post, number, check_name, app_id, expected):
    plan = plan_draft(get, number, check_name, app_id)
    require(fingerprint(plan) == expected, 'draft-plan-changed')
    new = post('pulls', {
        'title': 'Review development for promotion to staging',
        'head': 'development',
        'base': 'staging',
        'draft': True,
        'body': (
            f"Development `{plan['development']}` was checked with Ansible "
            f"for #{plan['pr']} (check `{plan['ansible_check']}`).\n\n"
            "Review the current diff and applicable checks. A human marks it ready and "
            "performs **Squash and merge** only when the review passes. A confirmed failure "
            "returns through a new `fix/*` branch into `development`. "
            "This draft does not authorize a staging or main merge."
        ),
    })
    src, dest = new.get('head') or {}, new.get('base') or {}
    require(new.get('draft') is True and all(local_repo(s.get('repo')) for s in (src, dest))
            and src.get('ref') == 'development' and dest.get('ref') == 'staging'
            and src.get('sha') == plan['development'] and dest.get('sha') == plan['staging'],
            'draft-response-moved-review-required')
    return new['number']


def api(method, path, body=None):
    args = ['gh', 'api', '--hostname', 'github.com', '--method', method, f'repos/{REPO}/{path}']
    if body is not None:
        args.extend(('--input', '-'))
    return json.loads(subprocess.check_output(args, input=json.dumps(body).encode() if body else None,
                                              timeout=30))


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--create-plan')
    args = parser.parse_args()
    try:
        require(os.environ.get('GITHUB_REPOSITORY') == REPO, 'wrong-workflow-repository')
        event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_bytes())
        kind = os.environ.get('GITHUB_EVENT_NAME')
        if kind == 'pull_request_target':
            require(event.get('action') == 'closed' and event['pull_request'].get('merged') is True,
                    'ignored-event')
            number = event.get('number')
        else:
            require(kind == 'workflow_dispatch' and os.environ.get('GITHUB_REF') == 'refs/heads/main',
                    'ignored-event')
            value = event.get('inputs', {}).get('integrated_pr', '')
            require(isinstance(value, str) and re.fullmatch(r'[1-9][0-9]{0,9}', value),
                    'invalid-pr-number')
            number = int(value)
        raw_app = os.environ.get('ANSIBLE_APP_ID', '')
        require(re.fullmatch(r'[1-9][0-9]{0,9}', raw_app), 'trusted-ansible-binding-not-configured')
        check = os.environ.get('ANSIBLE_CHECK_NAME', '')
        get = lambda path: api('GET', path)
        if args.create_plan is None:
            plan = plan_draft(get, number, check, int(raw_app))
            with Path(os.environ['GITHUB_OUTPUT']).open('a', encoding='utf-8') as f:
                f.write(f'plan={fingerprint(plan)}\n')
            print(json.dumps(dict(plan, result='human-staging-draft-preflight')))
        else:
            require(os.environ.get('CREATE_STAGING_DRAFTS') == 'true'
                    and re.fullmatch(r'[a-f0-9]{64}', args.create_plan), 'draft-creation-disabled')
            draft = create_once(get, lambda p, b: api('POST', p, b), number, check,
                                int(raw_app), args.create_plan)
            print(json.dumps(dict(result='draft-created-awaiting-human-review', pull_request=draft)))
    except Correct as exc:
        print(json.dumps({'result': 'new-fix-required', 'route': str(exc)}))
        return 1
    except Hold as exc:
        print(json.dumps({'result': 'held', 'reason': str(exc)}))
        return 2 if args.create_plan is not None else 0
    return 0


if __name__ == '__main__':
    raise SystemExit(run())
