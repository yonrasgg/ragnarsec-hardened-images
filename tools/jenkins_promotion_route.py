"""Run the squash simulation on live refs without checking out candidate code."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

from promotion_route import OID


SOURCE = re.compile(r'fix/[a-zA-Z0-9][a-zA-Z0-9._-]*')
ROUTE = Path(__file__).resolve().with_name('promotion_route.py')


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


def check(source, reviewed_head):
    if not SOURCE.fullmatch(source):
        raise RouteUnavailable('unsupported-source')
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
    args = [sys.executable, '-B', str(ROUTE), '--fix-head', head]
    for name in branches:
        args.extend(('--' + name, pins[prefix + name]))
    run = subprocess.run(args, capture_output=True, text=True, timeout=240)
    report = json.loads(run.stdout)
    if report.get('merge_authorized') is not False or report.get('exit_code') != run.returncode:
        raise RouteUnavailable('invalid-route-report')
    if live(refs) != pins:
        raise RouteUnavailable('live-refs-changed-during-route-check')
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
    args = parser.parse_args()
    try:
        output = check(args.source, args.reviewed_head)
    except RouteUnavailable as exc:
        output = dict(result='blocked', exit_code=2, reason=str(exc), merge_authorized=False)
    except (OSError, subprocess.SubprocessError, ValueError):
        output = dict(result='blocked', exit_code=2, reason='route-input-unavailable', merge_authorized=False)
    print(json.dumps(output, sort_keys=True))
    sys.exit(output['exit_code'])
