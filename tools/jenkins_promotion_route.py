"""Run the squash simulation on live refs without checking out candidate code."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from promotion_route import OID, PreflightError, Repository, RouteConflict


SOURCE = re.compile(r'fix/[a-zA-Z0-9][a-zA-Z0-9._-]*')
ROUTE = Path(__file__).resolve().with_name('promotion_route.py')
RECONCILIATION_SOURCE = 'fix/automated-promotion-preflight'
RECONCILIATION_PARENT = '1ba8a2ae90dc778ff0483535f9a31f8ba4d6f464'
RECONCILIATION_BASES = {
    'development': '40c82e789bad5895b730a92ffba2ee8838aeaf4a',
    'staging': 'e9ab7f4655ff1c32cd60bc3e4f6750e3d7b68e26',
    'main': 'f0a1d6f044406d04e0410016985c638b04b4e47f',
}


class RouteUnavailable(Exception):
    pass


def git(*args):
    return subprocess.run(['git', '--no-replace-objects', *args], check=True,
                          capture_output=True, text=True, timeout=60).stdout


def live(refs):
    result = {}
    for line in git('ls-remote', '--refs', 'origin', *refs).splitlines():
        sha, sep, ref = line.partition('\t')
        if not sep or not OID.fullmatch(sha) or ref not in refs or ref in result:
            raise RouteUnavailable('unexpected-live-ref')
        result[ref] = sha
    if set(result) != set(refs):
        raise RouteUnavailable('missing-live-ref')
    return result


def require_reconciliation_context(source, reviewed_head, env):
    if (source != RECONCILIATION_SOURCE or reviewed_head is not None
            or env.get('JOB_NAME') != 'ragnarsec-hardened-images/PR-164'
            or env.get('CHANGE_ID') != '164' or env.get('CHANGE_TARGET') != 'development'):
        raise RouteUnavailable('unsupported-reconciliation-context')


def plan_reconciliation(path, inputs):
    """Model the two named target-based drafts, never mark a direct squash clean."""
    repo = Repository(os.fspath(path))
    repo.check_inputs(inputs)
    fix = repo.squash('fix-to-development', inputs['development'], inputs['fix_head'])
    reviewed_tree = repo.require_oid('rev-parse', f'{fix}^{{tree}}')
    if repo.phases[0]['source_tree_matches'] is not True:
        raise RouteUnavailable('reconciliation-source-tree-mismatch')
    for name, source in (('staging', 'development'), ('main', 'staging')):
        base = inputs[name]
        planned = repo.require_oid('commit-tree', reviewed_tree, '-p', base, '--no-gpg-sign',
                                   '-m', f'Local {name} reconciliation simulation. Do not push.')
        repo.squash(f'{source}-to-{name}-reconciliation', base, planned)
        if repo.phases[-1]['tree'] != reviewed_tree or repo.phases[-1]['no_op']:
            raise RouteUnavailable('reconciliation-candidate-tree-mismatch')
    return {'schema_version': 1, 'result': 'pass', 'exit_code': 0, 'inputs': inputs,
            'reviewed_tree': reviewed_tree, 'phases': repo.phases, 'merge_authorized': False,
            'requires_verified_reconciliation_prs': True}


def check(source, reviewed_head, reconcile=False):
    if not SOURCE.fullmatch(source):
        raise RouteUnavailable('unsupported-source')
    if reconcile:
        require_reconciliation_context(source, reviewed_head, os.environ)
    prefix = 'refs/heads/'
    source_ref = prefix + source
    try:
        git('check-ref-format', source_ref)
    except subprocess.CalledProcessError as exc:
        raise RouteUnavailable('unsupported-source') from exc
    branches = ('development', 'staging', 'main')
    refs = [prefix + name for name in branches] + [source_ref]
    pins = live(refs)
    head = pins[source_ref]
    checkout = git('rev-parse', '--verify', 'HEAD').strip()
    if reviewed_head is None:
        # Jenkins discovers the PR head and runs its normal development check.
        if head != checkout:
            raise RouteUnavailable('checkout-does-not-match-live-source')
    else:
        # Actions executes only the protected base checkout; the PR is read as Git objects.
        if not OID.fullmatch(reviewed_head) or head != reviewed_head:
            raise RouteUnavailable('event-does-not-match-live-source')
        if checkout != pins[prefix + 'development']:
            raise RouteUnavailable('checkout-does-not-match-live-base')
    git('fetch', '--no-tags', '--no-write-fetch-head', '--refmap=', 'origin', *refs)
    if reconcile and (
            any(pins[prefix + name] != sha for name, sha in RECONCILIATION_BASES.items())
            or git('rev-list', '--parents', '-n1', head).strip() != f'{head} {RECONCILIATION_PARENT}'):
        raise RouteUnavailable('reconciliation-bases-or-source-parent-moved')
    args = [sys.executable, '-B', str(ROUTE), '--fix-head', head]
    for name in branches:
        args.extend(('--' + name, pins[prefix + name]))
    run = subprocess.run(args, capture_output=True, text=True, timeout=240)
    report = json.loads(run.stdout)
    if report.get('merge_authorized') is not False or report.get('exit_code') != run.returncode:
        raise RouteUnavailable('invalid-route-report')
    if live(refs) != pins:
        raise RouteUnavailable('live-refs-changed-during-route-check')
    if reconcile:
        failed = report.get('phases', [])[-1:]
        if (run.returncode != 1 or not failed or failed[0].get('lane') != 'development-to-staging'
                or failed[0].get('conflict_paths') != ['tests/test_public_ci.py']):
            raise RouteUnavailable('unrecognized-direct-route-conflict')
        inputs = dict(RECONCILIATION_BASES, fix_head=head)
        planned = plan_reconciliation('.', inputs)
        if live(refs) != pins:
            raise RouteUnavailable('live-refs-changed-during-route-check')
        return dict(planned, direct_route=report)
    if run.returncode == 0:
        expected = ['fix-to-development', 'development-to-staging', 'staging-to-main']
        phases = report.get('phases', [])
        if [p.get('lane') for p in phases] != expected:
            raise RouteUnavailable('incomplete-promotion-route')
        if any(p.get('source_tree_matches') is not True for p in phases[1:]):
            report.update(result='tree-mismatch', exit_code=1)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, help='internal fix branch from the PR event')
    parser.add_argument('--reviewed-head', help='expected PR head for a trusted Actions base checkout')
    parser.add_argument('--approved-reconciliation', action='store_true',
                        help='verify the frozen, one-time PR-164 reconciliation plan')
    args = parser.parse_args()
    try:
        output = check(args.source, args.reviewed_head, args.approved_reconciliation)
    except RouteUnavailable as exc:
        output = dict(result='blocked', exit_code=2, reason=str(exc), merge_authorized=False)
    except (OSError, subprocess.SubprocessError, ValueError, PreflightError, RouteConflict):
        output = dict(result='blocked', exit_code=2, reason='route-input-unavailable', merge_authorized=False)
    print(json.dumps(output, sort_keys=True))
    sys.exit(output['exit_code'])
