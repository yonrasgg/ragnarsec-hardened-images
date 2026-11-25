"""Check one ordinary promotion on exact PR inputs using protected policy."""
import argparse
import json
import subprocess

from jenkins_promotion_route import RouteUnavailable, git, live
from promotion_route import OID, PreflightError, Repository, RouteConflict

REPO = 'yonrasgg/ragnarsec-hardened-images'
REPO_ID = 1426336836
UPSTREAM = {'staging': 'development', 'main': 'staging'}


def event_inputs(event):
    pr = event['pull_request']
    source, target = pr['head'], pr['base']
    for side in (source, target):
        repo = side.get('repo') or {}
        if repo.get('id') != REPO_ID or repo.get('full_name') != REPO:
            raise RouteUnavailable('same-repository-promotion-required')
    source_name, target_name = source['ref'], target['ref']
    if target_name not in UPSTREAM or source_name != UPSTREAM[target_name]:
        raise RouteUnavailable('unsupported-ordinary-promotion-route')
    head, base = source['sha'], target['sha']
    if not all(isinstance(x, str) and OID.fullmatch(x) for x in (head, base)):
        raise RouteUnavailable('invalid-pr-commit')
    return source_name, target_name, head, base


def assess(event, repo, read_live=live, run_git=git):
    source, target, head, base = event_inputs(event)
    refs = {f'refs/heads/{source}': head, f'refs/heads/{target}': base}

    def assert_pins():
        if read_live(list(refs)) != refs:
            raise RouteUnavailable('source-or-target-moved')

    if run_git('rev-parse', '--verify', 'HEAD').strip() != base:
        raise RouteUnavailable('trusted-checkout-must-be-the-exact-target')
    assert_pins()
    run_git('fetch', '--no-tags', '--no-write-fetch-head', '--refmap=', 'origin', *refs)
    repo.check_inputs({'base': base, 'head': head})
    try:
        repo.squash(f'{source}-to-{target}', base, head)
    except RouteConflict:
        assert_pins()
        return 1, 'conflict'
    assert_pins()
    phase = repo.phases[-1]
    if not phase['source_tree_matches'] or phase['no_op']:
        return 1, 'unexpected-candidate-tree' if not phase['source_tree_matches'] else 'no-op'
    return 0, 'pass'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('event')
    args = parser.parse_args()
    repo = Repository('.')
    try:
        with open(args.event, encoding='utf-8') as stream:
            code, result = assess(json.load(stream), repo)
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError,
            RouteUnavailable, PreflightError) as exc:
        code = 2
        result = str(exc) if isinstance(exc, RouteUnavailable) else 'invalid-or-unavailable-input'
    print(json.dumps({'exit_code': code, 'result': result, 'phases': repo.phases,
                      'merge_authorized': False}, sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
