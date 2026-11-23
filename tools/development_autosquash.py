"""Run a normal development squash only after fresh, bound Jenkins evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


REPO = 'yonrasgg/ragnarsec-hardened-images'
REPO_ID = 1426336836
APP = 5736684
ACTOR = 356023509
BOT = 'ragnarsec-jenkins-ci[bot]'
JENKINS = 'continuous-integration/jenkins/pr-head'
BINDING = 'continuous-integration/jenkins/development-plan-binding'
SAFE_RULES = {'non_fast_forward', 'deletion', 'pull_request', 'required_linear_history',
              'required_signatures'}
NON_APP_BYPASS_ACTORS = {'OrganizationAdmin', 'RepositoryRole', 'Team', 'User'}


class Blocked(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise Blocked(reason)


def sha(value):
    return isinstance(value, str) and re.fullmatch(r'[a-f0-9]{40}', value) is not None


def fingerprint(plan):
    return hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def development_pr(pr, head):
    src, dst = pr.get('head') or {}, pr.get('base') or {}
    return (pr.get('state') == 'open' and pr.get('draft') is False and src.get('sha') == head
            and dst.get('ref') == 'development'
            and re.fullmatch(r'fix/[a-zA-Z0-9][a-zA-Z0-9._-]*', src.get('ref', ''))
            and all((side.get('repo') or {}).get('id') == REPO_ID
                    and (side.get('repo') or {}).get('full_name') == REPO for side in (src, dst)))


def check_rules(rules):
    require(isinstance(rules, list) and SAFE_RULES <= {r.get('type') for r in rules},
            'missing-protected-branch-rules')
    exact = {(JENKINS, APP), (BINDING, APP)}
    for rule in rules:
        params = rule.get('parameters') or {}
        if (rule.get('type') == 'required_status_checks'
                and params.get('strict_required_status_checks_policy') is True
                and exact <= {(s.get('context'), s.get('integration_id'))
                              for s in params.get('required_status_checks', [])}):
            return
    raise Blocked('github-does-not-enforce-both-strict-jenkins-checks')


def check_write_scope(get):
    """The API compares head only; a PR can be retargeted after our final read.

    Require GitHub itself to prevent the Actions app from updating every other
    branch. Missing bypass metadata is not proof that bypass is impossible.
    """
    summaries = get('rulesets?includes_parents=true&targets=branch&per_page=100')
    require(isinstance(summaries, list) and len(summaries) < 100, 'incomplete-ruleset-list')
    for row in summaries:
        rid = row.get('id')
        if (type(rid) is not int or rid <= 0 or row.get('enforcement') != 'active'
                or row.get('target') != 'branch'):
            continue
        rule = get(f'rulesets/{rid}?includes_parents=true')
        bypass = rule.get('bypass_actors')
        if (rule.get('id') == rid and rule.get('enforcement') == 'active'
                and rule.get('target') == 'branch'
                and rule.get('conditions') == {
                    'ref_name': {'include': ['~ALL'], 'exclude': ['refs/heads/development']}}
                and any(r.get('type') == 'update' for r in rule.get('rules', []))
                and isinstance(bypass, list)
                and all(a.get('actor_type') in NON_APP_BYPASS_ACTORS for a in bypass)):
            return rid
    raise Blocked('github-does-not-scope-actions-writes-to-development')


def signed_current_history(get, head_commit, base, head):
    def verified(commit):
        sig = commit['commit']['verification']
        return sig.get('verified') is True and sig.get('reason') == 'valid'

    if not verified(head_commit) or head_commit.get('sha') != head:
        return False
    if [p['sha'] for p in head_commit['parents']] == [base]:
        return True
    linear = get(f'compare/{base}...{head}?per_page=100')
    commits = linear.get('commits', [])
    if (linear.get('status') != 'ahead' or linear.get('behind_by') != 0
            or (linear.get('merge_base_commit') or {}).get('sha') != base
            or type(linear.get('ahead_by')) is not int
            or not 1 < len(commits) == linear['ahead_by'] < 100):
        return False
    previous = base
    for commit in commits:
        if (not sha(commit.get('sha')) or not verified(commit)
                or [p['sha'] for p in commit['parents']] != [previous]):
            return False
        previous = commit['sha']
    return previous == head


def read_plan(get, event):
    """Read from GitHub only. Never follow a Jenkins URL supplied by a status."""
    head, sender = event.get('sha'), event.get('sender') or {}
    require(sha(head) and event.get('context') in (JENKINS, BINDING)
            and event.get('state') == 'success' and sender.get('id') == ACTOR
            and sender.get('login') == BOT and sender.get('type') == 'Bot', 'untrusted-event')
    associated = get(f'commits/{head}/pulls?per_page=100')
    require(isinstance(associated, list) and len(associated) < 100, 'incomplete-pr-list')
    candidates = [p for p in associated if development_pr(p, head)]
    require(len(candidates) == 1, 'no-unique-fix-to-development')
    number = candidates[0].get('number')
    require(type(number) is int and 0 < number < 10**10, 'invalid-pr-number')
    pr = get(f'pulls/{number}')
    require(pr.get('number') == number and development_pr(pr, head)
            and pr.get('mergeable') is True and pr.get('auto_merge') is None,
            'pr-moved-or-not-mergeable')
    base = get('git/ref/heads/development')['object']['sha']
    candidate = pr.get('merge_commit_sha')
    require(sha(base) and sha(candidate) and pr['base'].get('sha') == base, 'unknown-or-stale-base')
    source = get(f"git/ref/heads/{pr['head']['ref']}")['object']['sha']
    require(source == head, 'source-moved')
    src = get(f'commits/{head}')
    test_merge = get(f'git/commits/{candidate}')
    tree = src['commit']['tree']['sha']
    require(sha(tree) and signed_current_history(get, src, base, head),
            'not-a-signed-current-base-fix')
    require(test_merge.get('sha') == candidate and test_merge['tree']['sha'] == tree
            and [p['sha'] for p in test_merge['parents']] == [base, head], 'candidate-mismatch')
    check_rules(get('rules/branches/development'))
    statuses = get(f'commits/{head}/statuses?per_page=100')
    require(isinstance(statuses, list) and len(statuses) < 100, 'incomplete-status-list')

    def checked(context):
        relevant = [s for s in statuses if s.get('context') == context]
        require(relevant and all(type(s.get('id')) is int and s['id'] > 0 for s in relevant),
                'missing-jenkins-check')
        status = max(relevant, key=lambda s: s['id'])
        actor = status.get('creator') or {}
        require(status.get('state') == 'success' and actor.get('id') == ACTOR
                and actor.get('login') == BOT and actor.get('type') == 'Bot', 'untrusted-latest-check')
        return status

    generic, bound = checked(JENKINS), checked(BINDING)
    url = generic.get('target_url')
    prefix = f'http://127.0.0.1:8080/job/ragnarsec-hardened-images/job/PR-{number}/'
    match = re.fullmatch(re.escape(prefix) + r'([1-9][0-9]{0,9})/display/redirect',
                         url if isinstance(url, str) else '')
    require(match and bound.get('target_url') == url, 'jenkins-run-mismatch')
    run = int(match[1])
    require(bound.get('description') == f'pr={number};base={base};run={run}', 'jenkins-base-not-attested')
    return dict(pr=number, head=head, base=base, candidate=candidate, tree=tree,
                jenkins_run=run, generic_status=generic['id'], bound_status=bound['id'],
                write_scope_ruleset=check_write_scope(get))


def squash_once(get, put, event, intended):
    latest = read_plan(get, event)
    require(fingerprint(latest) == intended, 'reviewed-plan-changed')
    # GitHub owns the expected-head comparison and strict, non-bypassed base gate.
    # No persistent auto-merge request: one normal server-side squash or stop.
    reply = put(f"pulls/{latest['pr']}/merge", {'sha': latest['head'], 'merge_method': 'squash'})
    require(reply.get('merged') is True and sha(reply.get('sha')), 'squash-not-confirmed')
    commit = reply['sha']
    result = get(f'commits/{commit}')
    require(result.get('sha') == commit and [p['sha'] for p in result['parents']] == [latest['base']]
            and result['commit']['tree']['sha'] == latest['tree']
            and result['commit']['verification'].get('verified') is True
            and result['commit']['verification'].get('reason') == 'valid',
            'squash-reported-but-signed-result-not-verified')
    return latest, commit


def api(method, path, body=None):
    args = ['gh', 'api', '--hostname', 'github.com', '--method', method, f'repos/{REPO}/{path}']
    if body is not None:
        args.extend(('--input', '-'))
    return json.loads(subprocess.check_output(args, input=json.dumps(body).encode() if body else None,
                                              timeout=30))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply-plan')
    args = parser.parse_args()
    try:
        require(os.environ.get('GITHUB_REPOSITORY') == REPO
                and os.environ.get('GITHUB_REF') == 'refs/heads/main'
                and os.environ.get('GITHUB_EVENT_NAME') == 'status', 'wrong-workflow-context')
        event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_bytes())
        get = lambda path: api('GET', path)
        if args.apply_plan is None:
            plan = read_plan(get, event)
            output = Path(os.environ['GITHUB_OUTPUT'])
            with output.open('a', encoding='utf-8') as f:
                f.write(f'plan_sha256={fingerprint(plan)}\n')
            print(json.dumps(dict(plan, result='development-squash-preflight', merged=False)))
        else:
            require(os.environ.get('RAGNARSEC_AUTO_SQUASH') == 'true'
                    and re.fullmatch(r'[a-f0-9]{64}', args.apply_plan), 'squash-disabled')
            plan, commit = squash_once(get, lambda path, body: api('PUT', path, body),
                                       event, args.apply_plan)
            print(json.dumps(dict(plan, result='development-squashed', merged=True, commit=commit)))
    except Blocked as exc:
        print(json.dumps({'result': 'blocked', 'reason': str(exc)}))
        return 2 if args.apply_plan is not None else 0
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
