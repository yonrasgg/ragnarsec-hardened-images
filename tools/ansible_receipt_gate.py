"""Fail-closed GATE verifier for tree-bound Ansible validation receipts (Option C).

Layer 3 of the four-layer design (VALIDATOR -> CUSTODY -> GATE -> CONSUMER).
This module never emits a GitHub check, never creates a receipt, never runs
Ansible and never mutates a repository. It verifies an already-fetched receipt
against the exact PR head tree and returns a structured decision that the
caller may use to publish a check run.

Trust is anchored by an owner-pinned SSH public-key hash (a public value, not
a secret) and by an owner-pinned trusted-runner registry. Until the owner pins
a real key and produces a pilot receipt, every decision is fail-closed.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCHEMA = 'ragnarsec.validation-receipt/1.0'
SIGNATURE_NAMESPACE = 'ragnarsec-receipt-v1'
EVIDENCE_ROOT = '40-Evidence/Audits/change-validation/'
RECEIPT_PATH = 'receipts/ansible-validate.json'
REQUIRED_COMMANDS = {'syntax-v1': ('C1', 'C2')}
MAX_AGE_SECONDS = 7 * 24 * 3600
GENESIS = '0' * 64

# Public trust anchor. No secret material: the verification half of an SSH
# key is public. OWNER-ACTION: replace the placeholder hash with the SHA-256
# of the exact authorized SSH public-key line before any pilot receipt can be
# accepted. A missing/placeholder hash rejects every signer (fail closed).
TRUST = {
    'trusted_runners': [
        {
            'host_id': 'heimdall',
            'actor': 'userone',
            'key_id': 'heimdall-userone-pilot-ed25519',
            'public_key_sha256': None,
        },
    ],
    'chain': {'seq': 1, 'prev_receipt_sha256': GENESIS},
}

OID40 = re.compile(r'[a-f0-9]{40}\Z')
OID64 = re.compile(r'[a-f0-9]{64}\Z')


class Reject(Exception):
    """A fail-closed rejection with its ordered verification step."""

    def __init__(self, step, reason):
        super().__init__(f'step-{step}:{reason}')
        self.step = step
        self.reason = reason


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(doc):
    """JCS-like canonical bytes: sorted keys, no insignificant whitespace."""
    return json.dumps(doc, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False).encode('utf-8')


def _oid40(value):
    return isinstance(value, str) and OID40.fullmatch(value) is not None


def _oid64(value):
    return isinstance(value, str) and OID64.fullmatch(value) is not None


def parse_time(value):
    if not isinstance(value, str) or not value.endswith('Z'):
        return None
    try:
        return datetime.fromisoformat(value[:-1] + '+00:00')
    except ValueError:
        return None


def git_tree_sha(entries):
    """Compute a Git tree object SHA-256... SHA-1 from flat API tree entries.

    `entries` are the `tree` objects returned by GET /git/trees/{sha}: each
    has `path`, `mode`, `type` and `sha`. Nested paths are rebuilt into a
    hierarchy and each tree object is hashed exactly as Git does.
    """
    root = {}
    for entry in entries:
        path = entry.get('path')
        mode = entry.get('mode')
        sha = entry.get('sha')
        kind = entry.get('type')
        if not isinstance(path, str) or not path or not _oid40(sha):
            raise ValueError('malformed tree entry')
        node = root
        parts = path.split('/')
        for part in parts[:-1]:
            node = node.setdefault(part, {})
            if not isinstance(node, dict):
                raise ValueError('conflicting tree entry')
        if parts[-1] in node:
            raise ValueError('duplicate tree entry')
        node[parts[-1]] = {'mode': str(mode), 'sha': sha,
                           'type': kind if kind in ('blob', 'tree', 'commit') else 'blob'}

    def build(node):
        rendered = []
        for name, value in node.items():
            if isinstance(value, dict) and 'sha' not in value:
                child_sha = build(value)
                rendered.append((name + '/', '40000', child_sha))
            else:
                rendered.append((name, value['mode'], value['sha']))
        rendered.sort(key=lambda item: item[0].encode('utf-8'))
        payload = b''.join(
            f'{mode} {name}\0'.encode('utf-8') + bytes.fromhex(sha)
            for name, mode, sha in rendered
        )
        return hashlib.sha1(
            b'tree ' + str(len(payload)).encode('ascii') + b'\0' + payload
        ).hexdigest()

    return build(root)


def reviewed_tree_sha(head_tree_entries, receipt_path=RECEIPT_PATH):
    """Head tree with the evidence path removed (the tree the validator saw).

    A receipt stored inside the tree it describes cannot bind to a tree that
    contains itself. The evidence path is therefore excluded from the bound
    tree; the full head tree is still recorded for the consumer binding.
    """
    top = receipt_path.split('/')[0]
    entries = [entry for entry in head_tree_entries
               if isinstance(entry, dict)
               and str(entry.get('path', '')).split('/')[0] != top]
    return git_tree_sha(entries)


def verify_signature(payload, signature, identity, public_key):
    """Verify an OpenSSH detached signature over canonical payload bytes.

    Returns (ok, detail). Uses `ssh-keygen -Y verify`, available on the
    runner and locally, so no Python crypto dependency and no secret is
    required: only the pinned public key is public data.
    """
    if not isinstance(public_key, str) or not public_key.startswith('ssh-'):
        return False, 'signer-public-key-not-pinned'
    if not isinstance(signature, str) or 'BEGIN SSH SIGNATURE' not in signature:
        return False, 'signature-malformed'
    if not isinstance(identity, str) or not identity:
        return False, 'signer-identity-malformed'
    with tempfile.TemporaryDirectory(prefix='ansible-receipt-') as tmp:
        root = Path(tmp)
        (root / 'payload').write_bytes(payload)
        (root / 'receipt.sig').write_text(signature, encoding='utf-8')
        (root / 'allowed').write_text(
            f'{identity} namespaces="{SIGNATURE_NAMESPACE}" {public_key}\n',
            encoding='utf-8',
        )
        try:
            with (root / 'payload').open('rb') as payload_stream:
                result = subprocess.run(
                    ['ssh-keygen', '-Y', 'verify', '-f', str(root / 'allowed'),
                     '-I', identity, '-n', SIGNATURE_NAMESPACE,
                     '-s', str(root / 'receipt.sig')],
                    stdin=payload_stream,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
                )
        except (OSError, subprocess.SubprocessError):
            return False, 'signature-verifier-unavailable'
        if result.returncode != 0:
            return False, 'signature-invalid'
    return True, ''


def verify_receipt(raw, *, head_sha, head_tree_sha, head_tree_entries,
                   trust=None, now=None, repo=None,
                   receipt_path=RECEIPT_PATH,
                   max_age_seconds=MAX_AGE_SECONDS):
    """Verify a receipt byte-for-byte, fail-closed, in ordered steps.

    `head_tree_sha` is the exact tree returned by
    GET /repos/{owner}/{repo}/git/commits/{head_sha}; `head_tree_entries`
    is GET /repos/{owner}/{repo}/git/trees/{head_tree_sha} (non-recursive).
    Returns a decision dict; `ok` is True only after every step passes.
    """
    trust = trust if trust is not None else TRUST
    now = now if now is not None else datetime.now(timezone.utc)
    receipt_sha = sha256_bytes(raw)
    decision = {
        'ok': False, 'step': 0, 'reason': 'not-verified',
        'receipt_sha256': receipt_sha, 'external_id': None,
        'target_tree_sha': None, 'head_tree_sha': head_tree_sha,
        'reviewed_tree_sha': None, 'ansible_version': None, 'result': None,
        'details_url': None, 'receipt_ref': None, 'verification_time': now.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'title': 'no valid Ansible validation receipt', 'text': '',
    }

    def fail(step, reason):
        decision['step'] = step
        decision['reason'] = f'step-{step}:{reason}'
        decision['text'] = (
            f'No valid Ansible validation receipt. Failed {reason} '
            f'(verification step {step}). No success conclusion is emitted.'
        )
        return decision

    try:
        # Step 1 — caller-supplied context (PR shape is re-checked by the workflow).
        if not _oid40(head_sha) or not _oid40(head_tree_sha):
            return fail(1, 'head-context-malformed')

        # Step 2 — expected tree resolved from the PR head by the caller.
        expected_tree = head_tree_sha

        # Step 3 — receipt path must be the single allowlisted path.
        if receipt_path != RECEIPT_PATH:
            return fail(3, 'receipt-path-not-allowlisted')

        # Step 4 — receipt bytes already fetched; hash them.
        if not isinstance(raw, (bytes, bytearray)) or not raw:
            return fail(4, 'receipt-bytes-missing')

        # Step 5 — canonical JSON schema and required fields.
        try:
            receipt = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            return fail(5, 'receipt-json-invalid')
        if not isinstance(receipt, dict) or receipt.get('schema') != SCHEMA:
            return fail(5, 'schema-not-accepted')
        required = ('run_id', 'target_tree_sha', 'target_commit_sha', 'commands',
                    'outputs_sha256', 'ansible_version', 'ansible_version_sha256',
                    'host_id', 'actor', 'observed_at', 'result', 'validation_profile',
                    'tree_assertion', 'owner_gates', 'evidence_refs', 'signer',
                    'signature', 'chain')
        missing = [key for key in required if key not in receipt]
        if missing:
            return fail(5, 'missing-field:' + ','.join(missing))
        decision['target_tree_sha'] = receipt.get('target_tree_sha')
        decision['result'] = receipt.get('result')

        # Step 6 — signer/registry and cryptographic signature.
        signer = receipt.get('signer')
        if not isinstance(signer, dict):
            return fail(6, 'signer-malformed')
        if not isinstance(receipt.get('signature'), str):
            return fail(6, 'signature-missing')
        trusted = next((t for t in (trust.get('trusted_runners') or [])
                        if isinstance(t, dict)
                        and t.get('host_id') == receipt.get('host_id')
                        and t.get('actor') == receipt.get('actor')
                        and t.get('key_id') == signer.get('key_id')
                        and signer.get('identity') == f"{receipt.get('host_id')}:{receipt.get('actor')}"),
                       None)
        if trusted is None:
            return fail(6, 'signer-not-in-registry')
        if signer.get('mechanism') not in ('ed25519', 'ed25519-durable'):
            return fail(6, 'signer-mechanism-not-accepted')
        public_key = signer.get('public_key')
        pinned = trusted.get('public_key_sha256')
        if (not isinstance(public_key, str) or not public_key.startswith('ssh-')
                or not _oid64(pinned)
                or sha256_bytes(public_key.encode('utf-8')) != pinned):
            return fail(6, 'signer-public-key-not-pinned')
        unsigned = {k: v for k, v in receipt.items() if k != 'signature'}
        ok, detail = verify_signature(canonical_bytes(unsigned), receipt['signature'],
                                      signer.get('identity'), public_key)
        if not ok:
            return fail(6, detail)

        # Step 7 — hash chain: ordered, typed, genesis or pinned predecessor.
        chain = receipt.get('chain')
        if not isinstance(chain, dict):
            return fail(7, 'chain-malformed')
        seq = chain.get('seq')
        prev = chain.get('prev_receipt_sha256')
        if type(seq) is not int or seq < 1 or not _oid64(prev):
            return fail(7, 'chain-fields-invalid')
        pinned = trust.get('chain') or {}
        if seq == 1 and prev != GENESIS:
            return fail(7, 'chain-genesis-mismatch')
        if seq > 1 and (prev == GENESIS or pinned.get('seq') != seq
                        or not _oid64(pinned.get('prev_receipt_sha256'))
                        or pinned['prev_receipt_sha256'] != prev):
            return fail(7, 'chain-predecessor-not-pinned')

        # Step 8 — exact tree binding.
        bound_tree = reviewed_tree_sha(head_tree_entries, receipt_path)
        decision['reviewed_tree_sha'] = bound_tree
        if not _oid40(receipt.get('target_tree_sha')) or receipt['target_tree_sha'] != bound_tree:
            return fail(8, 'target-tree-mismatch')

        # Step 9 — commit binding.
        if not _oid40(receipt.get('target_commit_sha')) or receipt['target_commit_sha'] != head_sha:
            return fail(9, 'target-commit-mismatch')

        # Step 10 — freshness: no future date, inside the owner window.
        observed = parse_time(receipt.get('observed_at'))
        if observed is None:
            return fail(10, 'observed-at-invalid')
        if observed > now + timedelta(minutes=5):
            return fail(10, 'observed-at-in-future')
        if now - observed > timedelta(seconds=max_age_seconds):
            return fail(10, 'receipt-stale')
        if 'completed_at' in receipt:
            completed = parse_time(receipt['completed_at'])
            if completed is None or completed > now + timedelta(minutes=5):
                return fail(10, 'completed-at-invalid')
            if now - completed > timedelta(seconds=max_age_seconds):
                return fail(10, 'receipt-stale')

        # Step 11 — hash fields and evidence references (EVD root only).
        for field in ('outputs_sha256', 'ansible_version_sha256',
                      'playbook_sha', 'inventory_sha'):
            if not _oid64(receipt.get(field)):
                return fail(11, f'{field}-invalid')
        commands_now = receipt.get('commands')
        capture_summary = [
            {'id': c.get('id'), 'rc': c.get('rc'),
             'stdout_sha256': c.get('stdout_sha256'),
             'stderr_sha256': c.get('stderr_sha256')}
            for c in commands_now if isinstance(c, dict)
        ]
        if sha256_bytes(canonical_bytes(capture_summary)) != receipt['outputs_sha256']:
            return fail(11, 'outputs-hash-mismatch')
        refs = receipt.get('evidence_refs')
        if not isinstance(refs, list) or not refs:
            return fail(11, 'evidence-refs-missing')
        if any(not isinstance(ref, str) or not ref.startswith(EVIDENCE_ROOT)
               or '..' in ref or ref.startswith('/') for ref in refs):
            return fail(11, 'evidence-ref-not-allowlisted')
        if sha256_bytes(receipt['ansible_version'].encode('utf-8')) != receipt['ansible_version_sha256']:
            return fail(11, 'ansible-version-hash-mismatch')

        # Step 12 — commands: profile-required ids, rc==0, no sudo/gates.
        profile = receipt.get('validation_profile')
        required_ids = REQUIRED_COMMANDS.get(profile)
        if required_ids is None:
            return fail(12, 'validation-profile-not-accepted')
        commands = receipt.get('commands')
        if not isinstance(commands, list) or not commands:
            return fail(12, 'commands-missing')
        ids = [c.get('id') for c in commands if isinstance(c, dict)]
        if any(identifier not in ids for identifier in required_ids):
            return fail(12, 'required-command-missing')
        for command in commands:
            if not isinstance(command, dict):
                return fail(12, 'command-malformed')
            if command.get('rc') != 0 or type(command.get('rc')) is not int:
                return fail(12, f"command-rc-nonzero:{command.get('id')}")
            if command.get('owner_gate') is not False or command.get('sudo_required') is not False:
                return fail(12, f"command-privileged:{command.get('id')}")
            if not _oid64(command.get('stdout_sha256')) or not _oid64(command.get('stderr_sha256')):
                return fail(12, f"command-capture-missing:{command.get('id')}")
            started, finished = parse_time(command.get('started_at')), parse_time(command.get('finished_at'))
            if started is None or finished is None or finished < started:
                return fail(12, f"command-timestamps-invalid:{command.get('id')}")

        # Step 13 — result and tree assertion.
        if receipt.get('result') != 'pass' or receipt.get('owner_gates') != []:
            return fail(13, 'result-not-pass')
        assertion = receipt.get('tree_assertion')
        if not isinstance(assertion, dict) or assertion.get('match') is not True:
            return fail(13, 'tree-assertion-not-true')
        if assertion.get('observed') != bound_tree or assertion.get('expected') != bound_tree:
            return fail(13, 'tree-assertion-not-bound')

        # Step 14 — version bound to C1 capture.
        version = receipt.get('ansible_version')
        if not isinstance(version, str) or not version.strip():
            return fail(14, 'ansible-version-empty')
        if not any(c.get('id') == 'C1' for c in commands if isinstance(c, dict)):
            return fail(14, 'ansible-version-unbound')

        # Step 15 — accepted: emit the decision the caller may publish.
        decision.update({
            'ok': True, 'step': 15, 'reason': 'verified',
            'external_id': receipt_sha,
            'ansible_version': version.splitlines()[0].strip(),
            'result': 'pass',
            'receipt_ref': refs[0],
            'details_url': (f'https://github.com/{repo}/blob/{head_sha}/{receipt_path}'
                            if repo else None),
            'title': (f'Ansible validation receipt accepted (tree {bound_tree}, '
                      f'receipt {receipt_sha[:12]})'),
        })
        decision['text'] = '\n'.join([
            'Tree-bound Ansible validation receipt verified.',
            f'receipt_ref={refs[0]}',
            f'receipt_sha256={receipt_sha}',
            f'target_tree_sha={bound_tree}',
            f'head_tree_sha={head_tree_sha}',
            f'verification_time={decision["verification_time"]}',
            f'ansible_version={decision["ansible_version"]}',
            'result=pass',
            f'run_id={receipt.get("run_id")}',
        ])
        return decision
    except Exception as exc:  # fail closed on any unexpected condition
        return fail(decision['step'] or 1, f'verification-error:{type(exc).__name__}')


def _gh_json(path, token=None):
    env = os.environ.copy()
    if token:
        env['GH_TOKEN'] = token
    result = subprocess.run(
        ['gh', 'api', '--hostname', 'github.com', '--method', 'GET', path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode('utf-8', 'replace').strip()[:300])
    return result.stdout


def live_decision():
    """Fetch read-only API data, verify, and return a fail-closed decision."""
    repo = os.environ.get('REPOSITORY', '')
    head = os.environ.get('HEAD_SHA', '')
    token = os.environ.get('GH_TOKEN') or os.environ.get('APP_TOKEN')
    receipt_path = os.environ.get('RECEIPT_PATH', RECEIPT_PATH)
    now = datetime.now(timezone.utc)
    try:
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo):
            raise RuntimeError('repository-not-allowlisted')
        commit = json.loads(_gh_json(f'repos/{repo}/git/commits/{head}', token))
        tree_sha = (commit.get('tree') or {}).get('sha')
        if not _oid40(tree_sha):
            raise RuntimeError('head-tree-unresolved')
        tree = json.loads(_gh_json(f'repos/{repo}/git/trees/{tree_sha}', token))
        entries = tree.get('tree')
        if tree.get('truncated') is True or not isinstance(entries, list):
            raise RuntimeError('head-tree-incomplete')
        content = json.loads(_gh_json(
            f'repos/{repo}/contents/{receipt_path}?ref={head}', token))
        if content.get('encoding') != 'base64' or not isinstance(content.get('content'), str):
            raise RuntimeError('receipt-encoding-invalid')
        import base64
        raw = base64.b64decode(''.join(content['content'].split()), validate=True)
        return verify_receipt(raw, head_sha=head, head_tree_sha=tree_sha,
                              head_tree_entries=entries, trust=TRUST, now=now,
                              repo=repo, receipt_path=receipt_path)
    except Exception as exc:
        reason = f'fetch-error:{type(exc).__name__}'
        return {
            'ok': False, 'step': 2, 'reason': reason,
            'receipt_sha256': None, 'external_id': None, 'target_tree_sha': None,
            'head_tree_sha': None, 'reviewed_tree_sha': None,
            'ansible_version': None, 'result': None, 'details_url': None,
            'receipt_ref': None, 'verification_time': now.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'title': 'no valid Ansible validation receipt',
            'text': (f'No valid Ansible validation receipt. {reason} '
                     '(verification step 2). No success conclusion is emitted.'),
        }


def main(argv):
    if len(argv) != 3 or argv[1] != '--decision-out':
        print('usage: ansible_receipt_gate.py --decision-out FILE', file=sys.stderr)
        return 2
    decision = live_decision()
    Path(argv[2]).write_text(json.dumps(decision, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps({k: decision[k] for k in
                      ('ok', 'step', 'reason', 'receipt_sha256', 'target_tree_sha')}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
