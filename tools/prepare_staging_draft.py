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

from ansible_receipt_gate import reviewed_tree_sha


REPO = 'yonrasgg/ragnarsec-hardened-images'
REPO_ID = 1426336836
OPEN_DRAFTS = 'pulls?state=open&base=staging&head=yonrasgg%3Adevelopment&per_page=100'
EVIDENCE_ROOT = '40-Evidence/Audits/change-validation/'
RECEIPT_REF = re.compile(r'\breceipt_ref=([^\s]+)\b')
RECEIPT_SHA = re.compile(r'\breceipt_sha256=([a-f0-9]{64})\b')
TARGET_TREE = re.compile(r'\btarget_tree_sha=([a-f0-9]{40})\b')
HEAD_TREE = re.compile(r'\bhead_tree_sha=([a-f0-9]{40})\b')
TARGET_COMMIT = re.compile(r'\btarget_commit_sha=([a-f0-9]{40})\b')


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


def receipt_binding(check, tree, reviewed):
    """Read the receipt reference published by the GATE; never infer one.

    The check's external_id is the SHA-256 of the exact receipt bytes. The
    check text must repeat that hash, an allowlisted EVD receipt path, the
    full head tree, the reviewed tree (head tree minus the evidence path,
    which a self-referential in-tree receipt cannot bind to) and the reviewed
    parent commit the receipt binds to. Any absence is a Hold, never a draft.
    """
    external_id = check.get('external_id')
    text = (check.get('output') or {}).get('text')
    if not isinstance(external_id, str) or re.fullmatch(r'[a-f0-9]{64}', external_id) is None:
        return None
    if not isinstance(text, str):
        return None
    sha = RECEIPT_SHA.search(text)
    ref = RECEIPT_REF.search(text)
    bound = TARGET_TREE.search(text)
    head = HEAD_TREE.search(text)
    commit = TARGET_COMMIT.search(text)
    if sha is None or ref is None or bound is None or head is None or commit is None:
        return None
    if (sha.group(1) != external_id or head.group(1) != tree
            or bound.group(1) != reviewed):
        return None
    path = ref.group(1)
    if (not path.startswith(EVIDENCE_ROOT) or path.startswith('/')
            or '..' in path or not path.endswith('/receipt.json')):
        return None
    return dict(external_id=external_id, receipt_ref=path,
                target_tree_sha=bound.group(1), head_tree_sha=head.group(1),
                target_commit_sha=commit.group(1))


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
    head_commit = get(f'git/commits/{head}')
    require((head_commit.get('tree') or {}).get('sha') == tree,
            'development-tree-is-not-the-reviewed-head-tree')
    # The receipt commit is a child of the reviewed commit; the GATE binds to
    # that single parent. Read it from the API commit, never from the check.
    head_parents = [p.get('sha') for p in (head_commit.get('parents') or [])
                    if isinstance(p, dict)]
    require(len(head_parents) == 1 and oid(head_parents[0]),
            'ansible-head-parent-not-single')
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
    # A green alone is no longer enough: the GATE must have bound a real,
    # verified receipt to this exact reviewed tree. Absence holds the draft.
    tree_entries = get(f'git/trees/{tree}').get('tree')
    require(isinstance(tree_entries, list), 'ansible-head-tree-unreadable')
    reviewed = reviewed_tree_sha(tree_entries)
    receipt = receipt_binding(check, tree, reviewed)
    require(receipt is not None, 'ansible-receipt-not-bound')
    require(receipt['target_commit_sha'] == head_parents[0],
            'ansible-receipt-not-bound-to-reviewed-parent')
    require(get(f'git/commits/{stage}')['tree']['sha'] != tree, 'nothing-new-for-staging')
    require(get(OPEN_DRAFTS) == [], 'staging-pr-already-open')
    return dict(pr=number, head=head, development=dev, staging=stage,
                ansible_check=check['id'], ansible_receipt=receipt['external_id'],
                ansible_receipt_ref=receipt['receipt_ref'],
                ansible_receipt_tree=receipt['target_tree_sha'],
                ansible_receipt_head_tree=receipt['head_tree_sha'],
                ansible_receipt_commit=receipt['target_commit_sha'])


def create_once(get, post, number, check_name, app_id, expected):
    plan = plan_draft(get, number, check_name, app_id)
    require(fingerprint(plan) == expected, 'draft-plan-changed')
    new = post('pulls', {
        'title': 'Review development for promotion to staging',
        'head': 'development',
        'base': 'staging',
        'draft': True,
        'body': (
            f"Development `{plan['development']}` has a verified Ansible validation "
            f"receipt for tree `{plan['ansible_receipt_tree']}` accepted by check "
            f"`{plan['ansible_check']}` (receipt `{plan['ansible_receipt']}`).\n\n"
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
        if kind == 'workflow_run':
            # CI-004 corrective: the privileged draft job runs on `workflow_run`
            # from the protected default branch. The PR number is supplied ONLY
            # by the trusted resolver in that workflow (INTEGRATED_PR); none of
            # the untrusted triggering run's outputs are consumed here.
            # plan_draft() below re-validates the entire PR through the
            # read-only API before any draft is planned or created.
            wr = event.get('workflow_run') or {}
            require(wr.get('event') == 'pull_request'
                    and (wr.get('head_repository') or {}).get('id') == REPO_ID,
                    'ignored-event')
            value = os.environ.get('INTEGRATED_PR', '')
            require(isinstance(value, str) and re.fullmatch(r'[1-9][0-9]{0,9}', value),
                    'invalid-pr-number')
            number = int(value)
        else:
            # Owner-triggered path, retained unchanged. The dormant
            # pull_request_target branch was REMOVED: no workflow in this
            # repository uses it after CI-004 and it must never be re-enabled
            # for a credential-minting job.
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
