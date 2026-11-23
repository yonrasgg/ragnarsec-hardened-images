"""Simulate protected squash promotions against exact local commits.

This writes unnamed Git objects, never refs, the index, or the worktree.
Use a trusted, complete clone. This is not a signature or merge authority.
"""
import argparse
import json
import os
import re
import subprocess
import sys


OID = re.compile(r'[0-9a-f]{40}')
TIMEOUT = 60


class PreflightError(Exception):
    """Missing inputs, unsupported Git, or an incomplete simulation."""


class RouteConflict(Exception):
    """A content conflict in one of the protected transitions."""


class Repository:
    def __init__(self, path):
        self.path = path
        self.env = dict(os.environ, GIT_NO_REPLACE_OBJECTS='1',
                        GIT_AUTHOR_NAME='Promotion simulation',
                        GIT_AUTHOR_EMAIL='promotion-simulation@invalid',
                        GIT_COMMITTER_NAME='Promotion simulation',
                        GIT_COMMITTER_EMAIL='promotion-simulation@invalid',
                        GIT_AUTHOR_DATE='2000-01-01T00:00:00Z',
                        GIT_COMMITTER_DATE='2000-01-01T00:00:00Z')
        self.phases = []

    def git(self, *args):
        return subprocess.run(['git', '-C', self.path, *args], env=self.env,
                              capture_output=True, timeout=TIMEOUT)

    def require_oid(self, *args):
        completed = self.git(*args)
        oid = completed.stdout.strip().decode('ascii', errors='replace')
        if completed.returncode or not OID.fullmatch(oid):
            raise PreflightError(f'Git could not resolve {args[-1]}')
        return oid

    def check_inputs(self, inputs):
        shallow = self.git('rev-parse', '--is-shallow-repository')
        if shallow.returncode != 0 or shallow.stdout.strip() != b'false':
            raise PreflightError('A complete Git history is required')
        for label, oid in inputs.items():
            if not OID.fullmatch(oid):
                raise PreflightError(f'{label} must be a full commit SHA')
            obj = self.git('cat-file', '-t', oid)
            if obj.returncode != 0 or obj.stdout.strip() != b'commit':
                raise PreflightError(f'{label} is not an available commit')

    def squash(self, lane, base, head):
        merged = self.git('merge-tree', '--write-tree', '--name-only',
                          '--messages', '-z', base, head)
        parts = merged.stdout.split(b'\0')
        tree = parts[0].decode('ascii', errors='replace')
        if merged.returncode not in (0, 1) or not OID.fullmatch(tree):
            raise PreflightError(f'{lane}: git merge-tree could not simulate the merge')
        phase = {'lane': lane, 'base_sha': base, 'head_sha': head}
        if merged.returncode == 1:
            paths = []
            for entry in parts[1:]:
                if not entry:
                    break
                paths.append(os.fsdecode(entry))
            if not paths:
                raise PreflightError(f'{lane}: Git did not report conflict paths')
            self.phases.append(dict(phase, result='conflict', conflict_paths=paths))
            raise RouteConflict(lane)
        base_tree = self.require_oid('rev-parse', f'{base}^{{tree}}')
        source_tree = self.require_oid('rev-parse', f'{head}^{{tree}}')
        no_op = tree == base_tree
        # When content is unchanged, there is no squash commit to promote.
        candidate = base if no_op else self.require_oid(
            'commit-tree', tree, '-p', base, '--no-gpg-sign',
            '-m', f'Local squash simulation: {lane}')
        self.phases.append(dict(phase, result='clean', tree=tree,
                                simulated_candidate_sha=candidate, no_op=no_op,
                                source_tree_matches=tree == source_tree))
        return candidate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', default='.')
    parser.add_argument('--development')
    parser.add_argument('--staging', required=True)
    parser.add_argument('--main', required=True)
    parser.add_argument('--fix-head', help='optional exact fix PR head')
    parser.add_argument('--staging-to-main-only', action='store_true',
                        help='check the actual staging tip after an owner squash')
    args = parser.parse_args()
    repo = Repository(args.repository)
    inputs = {'staging': args.staging, 'main': args.main}
    report = {'schema_version': 1, 'merge_authorized': False,
              'inputs': inputs, 'phases': repo.phases}
    try:
        if args.staging_to_main_only:
            if args.development is not None or args.fix_head is not None:
                raise PreflightError('Do not supply development or fix inputs in staging-only mode')
        else:
            if args.development is None:
                raise PreflightError('Development is required for the full route')
            inputs['development'] = args.development
            if args.fix_head is not None:
                inputs['fix_head'] = args.fix_head
        repo.check_inputs(inputs)
        staging = args.staging
        if not args.staging_to_main_only:
            development = args.development
            if args.fix_head is not None:
                development = repo.squash('fix-to-development', development, args.fix_head)
            staging = repo.squash('development-to-staging', staging, development)
        repo.squash('staging-to-main', args.main, staging)
        report.update(result='pass', exit_code=0)
    except RouteConflict:
        report.update(result='conflict', exit_code=1)
    except PreflightError as exc:
        report.update(result='error', exit_code=2, error=str(exc))
    except (OSError, subprocess.TimeoutExpired):
        report.update(result='error', exit_code=2, error='Git could not run within the local preflight limits')
    print(json.dumps(report, sort_keys=True))
    return report['exit_code']


if __name__ == '__main__':
    sys.exit(main())
