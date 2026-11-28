"""Qualify the owner-signed staging candidate carried by this signed test tag."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REPO = {'id': 1426336836, 'full_name': 'yonrasgg/ragnarsec-hardened-images'}
SOURCE = '326546a32c000ed16abe78767152323770a9e232'
TARGET = '2add4efdd48e1d579e47158928b9d0cde9bccd97'
MAIN = 'dfd4b7e9d9a0f0b7fe4cec05fe893d8153c78daa'
TREE = '790cc50d2745890822834f5bf77a146399598238'
SOURCE_BRANCH = f'sync/development-to-staging-{SOURCE}'
TAG_REF = 'refs/tags/ragnarsec-staging-pr264-qualify-20261128'
POLICY_HASHES = {
    'ansible_receipt_gate.py': 'c1cad2890bae1e0023ae35035fe38fc4265293c673bf9233ca6aa054d83a0f38',
    'jenkins_promotion_route.py': '0820eb747a4c2a3296b0aff8b101cda49276d3dfc064ee6a0170061c7f41f300',
    'promotion_candidate.py': '0fb3932eebb75ae680d7dcc38ccfe0940049e7ef35af5ffe24d9e6599717d240',
    'promotion_route.py': '6a7d367135a64ca94c3717951193dc8dd2459a9a6e83254f145a6c71d4ce5d0f',
}
PROTECTED_REFS = {
    'refs/heads/development': SOURCE, 'refs/heads/main': MAIN, 'refs/heads/staging': TARGET,
}


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def git(path, *args):
    return subprocess.check_output(['git', '-C', str(path), '--no-replace-objects', *args], timeout=60)


def revision(path, ref):
    return git(path, 'rev-parse', '--verify', ref).decode().strip()


def remote_pins(tag_object):
    expected = dict(PROTECTED_REFS, **{TAG_REF: tag_object})
    refs = [*expected, f'refs/heads/{SOURCE_BRANCH}']
    rows = [line.split('\t') for line in git(ROOT, 'ls-remote', '--refs', 'origin', *refs).decode().splitlines()]
    require(len(rows) == len(expected) and {ref: sha for sha, ref in rows} == expected,
            'protected-refs-or-tag-moved')


def event_side(ref, sha):
    return {'ref': ref, 'sha': sha, 'repo': REPO}


def main():
    carrier = revision(ROOT, 'HEAD')
    require(carrier == os.environ['GITHUB_SHA'] and os.environ['GITHUB_REF'] == TAG_REF, 'unexpected-workflow-revision')
    require(revision(ROOT, TAG_REF + '^{commit}') == carrier, 'tag-carrier-mismatch')
    tag_object = revision(ROOT, TAG_REF + '^{tag}')
    remote_pins(tag_object)
    require(revision(ROOT, SOURCE+'^{tree}') == TREE, 'source-tree-mismatch')
    carrier_parents = git(ROOT, 'rev-list', '--parents', '-n', '1', carrier).decode().split()
    require(len(carrier_parents) == 2, 'carrier-must-have-one-parent')
    candidate = carrier_parents[1]
    changes = git(ROOT, 'diff', '--name-only', '-z', candidate, carrier).split(b'\0')[:-1]
    require(set(changes) == {b'.github/workflows/jenkins-observer.yml', b'tools/qualify_staging_cutover.py'},
            'unexpected-carrier-files')

    with tempfile.TemporaryDirectory(prefix='ragnarsec-staging-qualifier-') as name:
        tmp = Path(name)
        policy_path = tmp / 'policy'
        policy_path.mkdir()
        for file, expected in POLICY_HASHES.items():
            contents = git(ROOT, 'show', f'{SOURCE}:tools/{file}')
            require(hashlib.sha256(contents).hexdigest() == expected, 'protected-policy-bytes-mismatch')
            (policy_path / file).write_bytes(contents)
        sys.path.insert(0, str(policy_path))
        from jenkins_promotion_route import OWNER_SSH_PUBLIC_KEY, SIGN_IDENTITY
        from promotion_candidate import assess
        from promotion_route import Repository

        allowed = tmp / 'allowed_signers'
        allowed.write_text(f'{SIGN_IDENTITY} {OWNER_SSH_PUBLIC_KEY}\n')
        git(ROOT, '-c','gpg.ssh.program=ssh-keygen','-c',f'gpg.ssh.allowedSignersFile={allowed}',
            '-c','gpg.minTrustLevel=fully','verify-tag',tag_object)
        origin, workspace = tmp/'origin.git', tmp/'workspace'
        subprocess.run(['git','init','--bare','-q','-b','staging',str(origin)],check=True,timeout=30)
        git(origin,'fetch','--no-tags',str(ROOT), f'{SOURCE}:refs/heads/development',
            f'{TARGET}:refs/heads/staging', f'{candidate}:refs/heads/{SOURCE_BRANCH}')
        subprocess.run(['git','clone','-q',str(origin),str(workspace)],check=True,timeout=60)
        os.chdir(workspace)
        try:
            record = Repository('.')
            code, result = assess({'pull_request': {'head':event_side(SOURCE_BRANCH,candidate),
                                                   'base':event_side('staging',TARGET)}}, record)
            require(code==0 and result=='pass-reconciled-exact-tree','protected-policy-rejected-candidate')
        finally:
            os.chdir(ROOT)
        conflict, exact = record.phases
        require(len(conflict['conflict_paths'])==12 and exact['tree']==TREE and exact['source_tree_matches'],
                'unexpected-reconciliation-result')
        remote_pins(tag_object)
        print(json.dumps(dict(result=result,policy_revision=SOURCE,carrier=carrier,candidate=candidate,
                              candidate_parent=TARGET,candidate_tree=TREE,protected_refs=PROTECTED_REFS,
                              candidate_ref_scope='isolated-pre-PR-qualification',phases=record.phases,
                              merge_authorized=False,publish=False),sort_keys=True,indent=2))


if __name__ == '__main__':
    main()
