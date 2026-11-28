"""Check an ordinary or owner-signed exact-tree promotion using protected policy."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from jenkins_promotion_route import OWNER_SSH_PUBLIC_KEY, SIGN_IDENTITY, RouteUnavailable, git, live
from promotion_route import OID, PreflightError, Repository, RouteConflict

REPO = 'yonrasgg/ragnarsec-hardened-images'
REPO_ID = 1426336836
UPSTREAM = {'staging': 'development', 'main': 'staging'}
SYNC_TRAILER = 'RagnarSec-Promotion-Source'


def sync_revision(source, target):
    """The sync branch name identifies exactly one protected upstream tip."""
    prefix = f'sync/{UPSTREAM[target]}-to-{target}-'
    revision = source.removeprefix(prefix)
    return revision if revision != source and OID.fullmatch(revision) else None


def event_inputs(event):
    pr = event['pull_request']
    source, target = pr['head'], pr['base']
    for side in (source, target):
        repo = side.get('repo') or {}
        if repo.get('id') != REPO_ID or repo.get('full_name') != REPO:
            raise RouteUnavailable('same-repository-promotion-required')
    source_name, target_name = source['ref'], target['ref']
    if (target_name not in UPSTREAM or not isinstance(source_name, str)
            or (source_name != UPSTREAM[target_name] and not sync_revision(source_name, target_name))):
        raise RouteUnavailable('unsupported-ordinary-promotion-route')
    head, base = source['sha'], target['sha']
    if not all(isinstance(x, str) and OID.fullmatch(x) for x in (head, base)):
        raise RouteUnavailable('invalid-pr-commit')
    return source_name, target_name, head, base


def verify_sync_signature(head, run_git):
    headers = run_git('cat-file', 'commit', head).split('\n\n', 1)[0].splitlines()
    if 'gpgsig -----BEGIN SSH SIGNATURE-----' not in headers:
        raise RouteUnavailable('exact-tree-owner-signature-required')
    with tempfile.TemporaryDirectory(prefix='promotion-signers-') as directory:
        signers = Path(directory) / 'allowed_signers'
        signers.write_text(f'{SIGN_IDENTITY} {OWNER_SSH_PUBLIC_KEY}\n', encoding='utf-8')
        try:
            run_git('-c', f'gpg.ssh.allowedSignersFile={signers}',
                    '-c', 'gpg.ssh.program=ssh-keygen',
                    '-c', 'gpg.minTrustLevel=fully', 'verify-commit', head)
        except subprocess.CalledProcessError as exc:
            raise RouteUnavailable('exact-tree-owner-signature-invalid') from exc


def validate_exact_tree(repo, run_git, upstream, upstream_head, target, base, head):
    if run_git('rev-list', '--parents', '-n', '1', head).split() != [head, base]:
        raise RouteUnavailable('exact-tree-target-parent-mismatch')
    if repo.require_oid('rev-parse', f'{head}^{{tree}}') != repo.require_oid(
            'rev-parse', f'{upstream_head}^{{tree}}'):
        raise RouteUnavailable('exact-tree-upstream-tree-mismatch')
    format_trailer = f'%(trailers:key={SYNC_TRAILER},valueonly,unfold,separator=%x00)'
    trailers = run_git('show', '-s', f'--format={format_trailer}', head).rstrip('\n')
    if trailers != f'{upstream}@{upstream_head} -> {target}':
        raise RouteUnavailable('exact-tree-signed-lane-mismatch')
    verify_sync_signature(head, run_git)


def assess(event, repo, read_live=live, run_git=git):
    source, target, head, base = event_inputs(event)
    refs = {f'refs/heads/{source}': head, f'refs/heads/{target}': base}
    upstream = UPSTREAM[target]
    upstream_head = sync_revision(source, target)
    inputs = {'base': base, 'head': head}
    if upstream_head:
        refs[f'refs/heads/{upstream}'] = upstream_head
        inputs['upstream'] = upstream_head

    def assert_pins():
        if read_live(list(refs)) != refs:
            raise RouteUnavailable('source-or-target-moved')

    if run_git('rev-parse', '--verify', 'HEAD').strip() != base:
        raise RouteUnavailable('trusted-checkout-must-be-the-exact-target')
    assert_pins()
    run_git('fetch', '--no-tags', '--no-write-fetch-head', '--refmap=', 'origin', *refs)
    repo.check_inputs(inputs)
    lane = f'{upstream}-to-{target}'
    if upstream_head:
        validate_exact_tree(repo, run_git, upstream, upstream_head, target, base, head)
        try:
            repo.squash(lane, base, upstream_head)
        except RouteConflict:
            lane += '-reconciliation'
        else:
            assert_pins()
            return 1, 'exact-tree-ordinary-route-not-conflicted'
    try:
        repo.squash(lane, base, head)
    except RouteConflict:
        assert_pins()
        return 1, 'conflict'
    assert_pins()
    phase = repo.phases[-1]
    if not phase['source_tree_matches'] or phase['no_op']:
        return 1, 'unexpected-candidate-tree' if not phase['source_tree_matches'] else 'no-op'
    return 0, 'pass-reconciled-exact-tree' if upstream_head else 'pass'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('event', nargs='?')
    parser.add_argument('--jenkins-input', nargs=4, metavar=('SOURCE', 'TARGET', 'HEAD', 'BASE'))
    args = parser.parse_args()
    if (args.event is None) == (args.jenkins_input is None):
        parser.error('supply an event file or --jenkins-input')
    repo = Repository('.')
    try:
        if args.jenkins_input:
            source, target, head, base = args.jenkins_input
            identity = {'id': REPO_ID, 'full_name': REPO}
            event = {'pull_request': {'head': {'ref': source, 'sha': head, 'repo': identity},
                                      'base': {'ref': target, 'sha': base, 'repo': identity}}}
        else:
            with open(args.event, encoding='utf-8') as stream:
                event = json.load(stream)
        code, result = assess(event, repo)
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError,
            RouteUnavailable, PreflightError) as exc:
        code = 2
        result = str(exc) if isinstance(exc, RouteUnavailable) else 'invalid-or-unavailable-input'
    print(json.dumps({'exit_code': code, 'result': result, 'phases': repo.phases,
                      'merge_authorized': False}, sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
