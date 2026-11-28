"""Run the squash simulation on live refs without checking out candidate code.

Reconciliation admission data is supplied as an owner-signed manifest committed
inside the PR branch. The tool (running from the trusted protected base) reads the
manifest from the fetched PR object, verifies the detached SSH signature against
a key pinned here, and re-verifies every field against live refs before and after
the simulation. There is no per-PR allowlist in this file. Missing, unsigned or
mismatched manifests fail closed; nothing here authorizes a merge or a publish.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from ansible_receipt_gate import RECEIPT_PATH, VERSIONED_RECEIPTS, versioned_receipt_path
from promotion_route import OID, PreflightError, Repository, RouteConflict


SOURCE = re.compile(r'fix/[a-zA-Z0-9][a-zA-Z0-9._-]*')
ROUTE = Path(__file__).resolve().with_name('promotion_route.py')
MANIFEST_DIR = 'reconciliation'
MANIFEST_NAME = 'PR-{pr}.json'
MANIFEST_SCHEMA = 1
SIGN_NAMESPACE = 'ragnarsec-promotion-reconciliation-v1'
SIGN_IDENTITY = 'ragnarsec-owner'
BRANCHES = ('development', 'staging', 'main')

# Full owner key pinned in protected policy. Never taken from the PR.
OWNER_SSH_PUBLIC_KEY = (
    'ssh-ed25519 '
    'AAAAC3NzaC1lZDI1NTE5AAAAIMeuFvoc8mL6ud8EkvgMdTy9wT2MggRpklzA9ALVkIER '
    'ragnarsec-git-signing'
)

# Every canonical field is covered by the detached signature. guard_files is
# optional and, when present, is signed and re-checked as in the original gate.
MANIFEST_FIELDS = ('schema_version', 'pr', 'source_branch', 'parent',
                   'reviewed_head', 'reviewed_tree', 'bases', 'conflict_paths', 'run_id')
OPTIONAL_MANIFEST_FIELDS = ('guard_files',)


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


def canonical_manifest(body):
    return json.dumps(body, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True).encode('utf-8')


def manifest_payload(manifest):
    if not isinstance(manifest, dict):
        raise RouteUnavailable('manifest-invalid')
    missing = [name for name in MANIFEST_FIELDS if name not in manifest]
    if missing or not isinstance(manifest.get('signature'), str):
        raise RouteUnavailable('manifest-invalid')
    body = {name: manifest[name] for name in MANIFEST_FIELDS}
    for name in OPTIONAL_MANIFEST_FIELDS:
        if name in manifest:
            body[name] = manifest[name]
    return canonical_manifest(body)


def verify_manifest_signature(manifest):
    """Verify the detached owner signature over the canonical manifest bytes."""
    payload = manifest_payload(manifest)
    with tempfile.TemporaryDirectory(prefix='promotion-reconciliation-') as tmp:
        data = Path(tmp) / 'payload'
        sig = Path(tmp) / 'payload.sig'
        signers = Path(tmp) / 'allowed_signers'
        data.write_bytes(payload)
        sig.write_text(manifest['signature'], encoding='utf-8')
        signers.write_text(f'{SIGN_IDENTITY} {OWNER_SSH_PUBLIC_KEY}\n', encoding='utf-8')
        try:
            run = subprocess.run(
                ['ssh-keygen', '-Y', 'verify', '-f', str(signers),
                 '-I', SIGN_IDENTITY, '-n', SIGN_NAMESPACE, '-s', str(sig)],
                input=payload, capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            raise RouteUnavailable('manifest-signature-unverifiable')
    if run.returncode != 0:
        raise RouteUnavailable('manifest-signature-invalid')


def load_manifest(pr, head):
    """Read PR-<pr>.json from the fetched PR object; never from the working tree."""
    pr = '' if pr is None else str(pr)
    if not pr.isdigit() or not OID.fullmatch(head):
        raise RouteUnavailable('manifest-pr-or-head-invalid')
    path = f'{MANIFEST_DIR}/{MANIFEST_NAME.format(pr=pr)}'
    try:
        text = git('show', f'{head}:{path}')
    except subprocess.CalledProcessError:
        raise RouteUnavailable('manifest-missing')
    try:
        manifest = json.loads(text)
    except (ValueError, TypeError):
        raise RouteUnavailable('manifest-invalid')
    # Signature first: no field is trusted until the owner signature verifies.
    verify_manifest_signature(manifest)
    conflicts = manifest.get('conflict_paths')
    bases = manifest.get('bases')
    if (manifest.get('schema_version') != MANIFEST_SCHEMA
            or str(manifest.get('pr')) != pr
            or not isinstance(manifest.get('source_branch'), str)
            or not manifest['source_branch']
            or any(not OID.fullmatch(str(manifest.get(key)))
                   for key in ('parent', 'reviewed_head', 'reviewed_tree'))
            or not isinstance(bases, dict)
            or set(bases) != set(BRANCHES)
            or any(not OID.fullmatch(str(sha)) for sha in bases.values())
            or not isinstance(conflicts, list) or not conflicts
            or any(not isinstance(item, str) or not item for item in conflicts)
            or len(conflicts) != len(set(conflicts))
            or not isinstance(manifest.get('run_id'), str) or not manifest['run_id']):
        raise RouteUnavailable('manifest-invalid')
    if 'guard_files' in manifest:
        guards = manifest['guard_files']
        if (not isinstance(guards, list)
                or any(not isinstance(item, str) or not item for item in guards)):
            raise RouteUnavailable('manifest-invalid')
    return manifest


def require_reconciliation_context(manifest, source, env):
    """Jenkins: trusted job/PR/target binding, with no per-PR enumeration."""
    pr = str(manifest['pr'])
    if (source != manifest['source_branch']
            or env.get('CHANGE_ID') != pr
            or env.get('JOB_NAME') != f'ragnarsec-hardened-images/PR-{pr}'
            or env.get('CHANGE_FORK')
            or env.get('CHANGE_TARGET') != 'development'):
        raise RouteUnavailable('unsupported-reconciliation-context')


def require_actions_reconciliation_context(manifest, source, reviewed_head, change_id, repo):
    """Actions: trusted pull_request_target event binding; base checkout stays policy."""
    pr = '' if change_id is None else str(change_id)
    if (repo != 'yonrasgg/ragnarsec-hardened-images'
            or not pr.isdigit()
            or pr != str(manifest['pr'])
            or source != manifest['source_branch']
            or reviewed_head is None
            or not OID.fullmatch(reviewed_head)):
        raise RouteUnavailable('unsupported-reconciliation-context')


def require_reconciliation_pins(manifest, refs, head):
    """head is the reviewed source commit named by the signed manifest."""
    if (any(refs[f'refs/heads/{name}'] != sha for name, sha in manifest['bases'].items())
            or git('rev-list', '--parents', '-n1', head).strip()
            != f"{head} {manifest['parent']}"
            or git('rev-parse', f'{head}^{{tree}}').strip() != manifest['reviewed_tree']):
        raise RouteUnavailable('reconciliation-bases-or-source-parent-moved')
    guards = manifest.get('guard_files')
    if guards is not None:
        changed = git('diff', '--name-only', '-z', manifest['parent'], head).split('\0')[:-1]
        if changed != guards:
            raise RouteUnavailable('reconciliation-unreviewed-guard-files')


def require_reconciliation_candidate(manifest, head):
    """Bind the final source tree to reviewed code plus exact metadata paths.

    The owner-signed manifest binds the complete reviewed source tree. Only this
    PR's manifest and the Ansible receipt may differ in the final candidate.
    Receipt authenticity remains the responsibility of the independent Ansible
    gate; this check never treats an allowed path as an accepted receipt.
    """
    manifest_path = f"{MANIFEST_DIR}/{MANIFEST_NAME.format(pr=manifest['pr'])}"
    diff = git('diff', '--no-ext-diff', '--no-textconv', '--no-renames',
               '--ignore-submodules=none', '--name-only', '-z',
               manifest['reviewed_head'], head, '--')
    changed = set(filter(None, diff.split('\0')))
    receipt_path = RECEIPT_PATH
    if any(path.startswith(f'{VERSIONED_RECEIPTS}/') for path in changed):
        parents = git('rev-list', '--parents', '-n', '1', head).split()
        if len(parents) != 2 or parents[0] != head or not OID.fullmatch(parents[1]):
            raise RouteUnavailable('reconciliation-receipt-parent-invalid')
        receipt_path = versioned_receipt_path(parents[1])
        if receipt_path not in changed or git('ls-tree', '-z', parents[1], '--', receipt_path):
            raise RouteUnavailable('reconciliation-receipt-not-new-for-parent')
    allowed = {manifest_path, receipt_path}
    if not changed <= allowed:
        raise RouteUnavailable('reconciliation-unreviewed-candidate-files')
    # Read Git objects, not checkout paths. Both metadata files must remain
    # regular, non-executable blobs; deletion, symlinks and gitlinks fail closed.
    for path in sorted(allowed):
        entry = git('ls-tree', '-z', head, '--', path)
        if re.fullmatch(r'100644 blob [0-9a-f]{40}\t' + re.escape(path) + r'\x00',
                        entry) is None:
            raise RouteUnavailable('reconciliation-candidate-metadata-not-regular')
    candidate_tree = git('rev-parse', f'{head}^{{tree}}').strip()
    if not OID.fullmatch(candidate_tree):
        raise RouteUnavailable('reconciliation-candidate-tree-unavailable')
    return candidate_tree


def plan_reconciliation(path, inputs, expected_reviewed_tree=None):
    """Model the two named target-based drafts, never mark a direct squash clean."""
    repo = Repository(os.fspath(path))
    repo.check_inputs(inputs)
    fix = repo.squash('fix-to-development', inputs['development'], inputs['fix_head'])
    reviewed_tree = repo.require_oid('rev-parse', f'{fix}^{{tree}}')
    if repo.phases[0]['source_tree_matches'] is not True:
        raise RouteUnavailable('reconciliation-source-tree-mismatch')
    if expected_reviewed_tree is not None and reviewed_tree != expected_reviewed_tree:
        raise RouteUnavailable('reconciliation-reviewed-tree-mismatch')
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


def check(source, reviewed_head, reconcile=False, actions_change_id=None, actions_repo=None,
          manifest_head=None, manifest_pr=None):
    if not SOURCE.fullmatch(source):
        raise RouteUnavailable('unsupported-source')
    # Bind the trusted event before any ref work or manifest read: a wrong PR
    # number or repository must never reach the admission path.
    if reconcile and reviewed_head is not None:
        event_pr = '' if manifest_pr is None else str(manifest_pr)
        trusted_pr = '' if actions_change_id is None else str(actions_change_id)
        if (not event_pr.isdigit() or event_pr != trusted_pr
                or actions_repo != 'yonrasgg/ragnarsec-hardened-images'):
            raise RouteUnavailable('unsupported-reconciliation-context')
    prefix = 'refs/heads/'
    source_ref = prefix + source
    try:
        git('check-ref-format', source_ref)
    except subprocess.CalledProcessError as exc:
        raise RouteUnavailable('unsupported-source') from exc
    refs = [prefix + name for name in BRANCHES] + [source_ref]
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
    for name in BRANCHES:
        args.extend(('--' + name, pins[prefix + name]))
    run = subprocess.run(args, capture_output=True, text=True, timeout=240)
    report = json.loads(run.stdout)
    if report.get('merge_authorized') is not False or report.get('exit_code') != run.returncode:
        raise RouteUnavailable('invalid-route-report')
    if live(refs) != pins:
        raise RouteUnavailable('live-refs-changed-during-route-check')

    failed = report.get('phases', [])[-1:]
    if (reconcile and run.returncode == 1 and failed
            and failed[0].get('lane') == 'development-to-staging'
            and failed[0].get('conflict_paths')):
        if reviewed_head is not None:
            pr = '' if manifest_pr is None else str(manifest_pr)
            trusted_pr = '' if actions_change_id is None else str(actions_change_id)
            if (not pr.isdigit() or pr != trusted_pr
                    or manifest_head is None or manifest_head != reviewed_head):
                raise RouteUnavailable('unsupported-reconciliation-context')
        else:
            pr = os.environ.get('CHANGE_ID') or ''
            if not pr.isdigit():
                raise RouteUnavailable('unsupported-reconciliation-context')
            manifest_head = head
        manifest = load_manifest(pr, manifest_head)
        if reviewed_head is not None:
            require_actions_reconciliation_context(manifest, source, reviewed_head,
                                                   actions_change_id, actions_repo)
        else:
            require_reconciliation_context(manifest, source, os.environ)
        reviewed_source = manifest['reviewed_head']
        try:
            ancestry = subprocess.run(
                ['git', '--no-replace-objects', 'merge-base', '--is-ancestor',
                 reviewed_source, head], capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            raise RouteUnavailable('manifest-reviewed-head-unverifiable')
        if ancestry.returncode != 0:
            raise RouteUnavailable('manifest-reviewed-head-not-in-source')
        require_reconciliation_pins(manifest, pins, reviewed_source)
        if failed[0]['conflict_paths'] != manifest['conflict_paths']:
            raise RouteUnavailable('unrecognized-direct-route-conflict')
        candidate_tree = require_reconciliation_candidate(manifest, head)
        inputs = dict(manifest['bases'], fix_head=head)
        planned = plan_reconciliation('.', inputs, candidate_tree)
        if live(refs) != pins:
            raise RouteUnavailable('live-refs-changed-during-route-check')
        return dict(planned, direct_route=report, manifest_pr=manifest['pr'],
                    manifest_reviewed_head=manifest['reviewed_head'],
                    manifest_reviewed_tree=manifest['reviewed_tree'],
                    candidate_head=head, candidate_tree=candidate_tree,
                    run_id=manifest['run_id'])
    if run.returncode == 0:
        expected = ['fix-to-development', 'development-to-staging', 'staging-to-main']
        phases = report.get('phases', [])
        if [item.get('lane') for item in phases] != expected:
            raise RouteUnavailable('incomplete-promotion-route')
        if any(item.get('source_tree_matches') is not True for item in phases[1:]):
            report.update(result='tree-mismatch', exit_code=1)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, help='internal fix branch from the PR event')
    parser.add_argument('--reviewed-head', help='expected PR head for a trusted Actions base checkout')
    parser.add_argument('--allow-manifest-reconciliation', action='store_true',
                        help='consider an owner-signed manifest in the PR object; never approve by itself')
    parser.add_argument('--manifest-from-pr', help='PR head to read the signed manifest from (Actions)')
    parser.add_argument('--pr', help='trusted PR number supplied by the event')
    parser.add_argument('--change-id', help='trusted PR number supplied by the Actions event')
    parser.add_argument('--repo', help='trusted GITHUB_REPOSITORY supplied by the Actions event')
    args = parser.parse_args()
    try:
        output = check(args.source, args.reviewed_head, args.allow_manifest_reconciliation,
                       args.change_id, args.repo, args.manifest_from_pr, args.pr)
    except RouteUnavailable as exc:
        output = dict(result='blocked', exit_code=2, reason=str(exc), merge_authorized=False)
    except (OSError, subprocess.SubprocessError, ValueError, PreflightError, RouteConflict):
        output = dict(result='blocked', exit_code=2, reason='route-input-unavailable', merge_authorized=False)
    print(json.dumps(output, sort_keys=True))
    sys.exit(output['exit_code'])
