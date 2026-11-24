"""Read-only GitHub signature gate for a staging or main promotion."""
import argparse
import json
import re
import subprocess
import sys


REPO = 'yonrasgg/ragnarsec-hardened-images'
SHA = re.compile(r'[a-f0-9]{40}')
SOURCE = re.compile(r'(?:development|staging|fix/[a-z0-9][a-z0-9-]*)')
MAX_COMMITS = 128


class Blocked(Exception):
    """A signature check is missing, invalid, or stale."""


def get(path):
    data = subprocess.check_output(
        ['gh', 'api', '--method', 'GET', f'repos/{REPO}/{path}'], timeout=20)
    return json.loads(data)


def git_incoming(repo, base, head):
    def git(*args):
        return subprocess.check_output(['git', '-C', repo, '--no-replace-objects', *args], timeout=20, text=True)

    if git('rev-parse', '--is-shallow-repository').strip() != 'false':
        raise Blocked('complete Git history is required')
    return git('rev-list', f'--max-count={MAX_COMMITS + 1}', head, f'^{base}').splitlines()


def verify(repo, source, target, head, base, *, api=get, incoming=git_incoming):
    if not SHA.fullmatch(head) or not SHA.fullmatch(base):
        raise Blocked('full exact head and base SHAs are required')
    if not SOURCE.fullmatch(source) or target not in ('staging', 'main') or source == target:
        raise Blocked('unsupported promotion refs')

    def live_refs():
        for ref, pinned in ((source, head), (target, base)):
            if api(f'git/ref/heads/{ref}')['object']['sha'] != pinned:
                raise Blocked(f'branch changed: {ref}')

    live_refs()
    commits = incoming(repo, base, head)
    if not commits or len(commits) > MAX_COMMITS or head not in commits:
        raise Blocked('empty, incomplete, or oversized incoming commit range')
    if len(set(commits)) != len(commits) or not all(SHA.fullmatch(sha) for sha in commits):
        raise Blocked('invalid local commit range')
    for sha in commits:
        obj = api(f'commits/{sha}')
        sig = obj.get('commit', {}).get('verification') or {}
        if obj.get('sha') != sha or sig.get('verified') is not True or sig.get('reason') != 'valid':
            raise Blocked(f'GitHub did not verify signature: {sha}')
    live_refs()
    return commits


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repository', default='.')
    for field in ('source', 'target', 'head', 'base'):
        p.add_argument('--' + field, required=True)
    a = p.parse_args()
    out = dict(source=a.source, target=a.target, head=a.head, base=a.base,
               repository=REPO, merge_authorized=False)
    try:
        out.update(commits=verify(a.repository, a.source, a.target, a.head, a.base),
                   result='pass', exit_code=0)
    except Blocked as exc:
        out.update(result='blocked', exit_code=1, reason=str(exc))
    except (OSError, subprocess.SubprocessError, KeyError, TypeError, ValueError):
        out.update(result='blocked', exit_code=2, reason='signature evidence unavailable')
    print(json.dumps(out, sort_keys=True))
    return out['exit_code']


if __name__ == '__main__':
    sys.exit(main())
