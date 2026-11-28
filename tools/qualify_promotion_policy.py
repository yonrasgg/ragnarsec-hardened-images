"""Exercise both verifiers against frozen production objects with an isolated signer."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch


REPO = 'yonrasgg/ragnarsec-hardened-images'
REPO_ID = 1426336836
PATCHED_CHECKOUT = Path(__file__).resolve().parents[1]
MAIN = 'dfd4b7e9d9a0f0b7fe4cec05fe893d8153c78daa'
STAGING = '2add4efdd48e1d579e47158928b9d0cde9bccd97'


def run(*args, cwd=None, check=True):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=check)


def git(root, *args):
    return run('git', '-C', str(root), *args).stdout.strip()


def side(ref, sha):
    return dict(ref=ref, sha=sha, repo=dict(id=REPO_ID, full_name=REPO))


with tempfile.TemporaryDirectory(prefix='ragnarsec-promo-real-objects-') as directory:
    root = Path(directory)
    origin = root / 'origin.git'
    checkout = root / 'checkout'
    run('git', 'init', '--bare', '-q', '-b', 'main', str(origin))
    git(origin, 'fetch', '--no-tags', str(PATCHED_CHECKOUT),
        f'{MAIN}:refs/heads/main', f'{STAGING}:refs/heads/staging')
    run('git', 'clone', '-q', str(origin), str(checkout))
    assert git(checkout, 'rev-parse', 'HEAD') == MAIN
    assert not git(checkout, 'status', '--porcelain')
    git(checkout, 'config', 'user.name', 'RagnarSec test fixture')
    git(checkout, 'config', 'user.email', 'fixture@invalid')
    tree = git(checkout, 'rev-parse', f'{STAGING}^{{tree}}')
    key = root / 'test-ed25519'
    run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key))
    head = git(checkout, '-c', 'gpg.format=ssh', '-c', f'user.signingkey={key}',
               'commit-tree', tree, '-p', MAIN, '-S', '-m', 'Synthetic promotion for readback',
               '-m', f'RagnarSec-Promotion-Source: staging@{STAGING} -> main')
    source = f'sync/staging-to-main-{STAGING}'
    git(checkout, 'push', 'origin', f'{head}:refs/heads/{source}')
    event = {'pull_request': {'head': side(source, head), 'base': side('main', MAIN)}}
    event_path = root / 'event.json'
    event_path.write_text(json.dumps(event), encoding='utf-8')

    old = run(sys.executable, '-B', 'tools/promotion_candidate.py', str(event_path), cwd=checkout, check=False)
    old_report = json.loads(old.stdout)
    assert old.returncode == 2 and old_report['result'] == 'unsupported-ordinary-promotion-route'

    os.chdir(checkout)
    sys.path.insert(0, str(PATCHED_CHECKOUT / 'tools'))
    from promotion_candidate import assess
    from promotion_route import Repository
    repo = Repository('.')
    with patch('promotion_candidate.OWNER_SSH_PUBLIC_KEY', key.with_suffix('.pub').read_text().strip()):
        code, result = assess(event, repo)
    assert code == 0 and result == 'pass-reconciled-exact-tree'
    ordinary, accepted = repo.phases
    assert ordinary['result'] == 'conflict' and len(ordinary['conflict_paths']) == 12
    assert accepted['tree'] == tree and accepted['source_tree_matches'] is True
    assert git(checkout, 'rev-parse', 'HEAD') == MAIN
    assert not git(checkout, 'status', '--porcelain')
    print(json.dumps(dict(scope='isolated fixture with frozen real Git objects and ephemeral signing key',
                          staging=STAGING, main=MAIN, expected_tree=tree, legacy=old_report,
                          proposed=dict(exit_code=code, result=result, phases=repo.phases),
                          merge_authorized=False, publish=False), indent=2, sort_keys=True))
