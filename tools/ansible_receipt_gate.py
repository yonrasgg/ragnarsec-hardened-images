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
GIT_TREE_SCHEMA = 'ragnarsec.validation-receipt/1.1'
SIGNATURE_NAMESPACE = 'ragnarsec-receipt-v1'
EVIDENCE_ROOT = '40-Evidence/Audits/change-validation/'
RECEIPT_PATH = 'receipts/ansible-validate.json'
VERSIONED_RECEIPTS = 'receipts/ansible'
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
            # Owner-pinned public-half hash from the dedicated pilot key
            # generated on heimdall (sha256sum of the .pub FILE, which includes
            # its trailing newline). The receipt MUST carry that same key line
            # WITH the trailing newline in `signer.public_key`, or step 6
            # rejects it. No private material is stored here.
            'public_key_sha256': (
                'd78b1c0c693978f42ca1e4c701e35c04789cd424b14f0bbf020628e3f5799066'
            ),
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


def git_tree_sha(entries, *, schema=SCHEMA):
    """Hash Git API entries with the serialization declared by the receipt.

    `entries` are the `tree` objects returned by GET /git/trees/{sha}: each
    has `path`, `mode`, `type` and `sha`. Nested paths are rebuilt into a
    hierarchy. Version 1.0 preserves the historic receipt serialization.
    Version 1.1 serializes Git trees, including mode and directory ordering.
    """
    if schema not in (SCHEMA, GIT_TREE_SCHEMA):
        raise ValueError('unknown-tree-schema')
    canonical = schema == GIT_TREE_SCHEMA
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
        if canonical and any(part in ('', '.', '..') or '\0' in part for part in parts):
            raise ValueError('invalid-tree-path')
        for part in parts[:-1]:
            node = node.setdefault(part, {})
            if not isinstance(node, dict):
                raise ValueError('conflicting tree entry')
        if parts[-1] in node:
            raise ValueError('duplicate tree entry')
        if canonical:
            modes = {'tree': ('040000', '40000'), 'blob': ('100644', '100755', '120000'),
                     'commit': ('160000',)}
            if mode not in modes.get(kind, ()):
                raise ValueError('invalid-tree-entry-mode')
            if kind == 'tree':
                mode = '40000'
        node[parts[-1]] = {'mode': str(mode), 'sha': sha,
                           'type': kind if kind in ('blob', 'tree', 'commit') else 'blob'}

    def build(node):
        rendered = []
        for name, value in node.items():
            if isinstance(value, dict) and 'sha' not in value:
                child_sha = build(value)
                rendered.append((name + '/', name if canonical else name + '/', '40000', child_sha))
            else:
                order = name + '/' if canonical and value['type'] == 'tree' else name
                rendered.append((order, name, value['mode'], value['sha']))
        rendered.sort(key=lambda item: item[0].encode('utf-8'))
        payload = b''.join(
            f'{mode} {name}\0'.encode('utf-8') + bytes.fromhex(sha)
            for _, name, mode, sha in rendered
        )
        return hashlib.sha1(
            b'tree ' + str(len(payload)).encode('ascii') + b'\0' + payload
        ).hexdigest()

    return build(root)


def reviewed_tree_sha(head_tree_entries, receipt_path=RECEIPT_PATH, *, schema=SCHEMA):
    """Head tree with the evidence path removed (the tree the validator saw).

    A receipt stored inside the tree it describes cannot bind to a tree that
    contains itself. The evidence path is therefore excluded from the bound
    tree; the full head tree is still recorded for the consumer binding.
    """
    top = receipt_path.split('/')[0]
    entries = [entry for entry in head_tree_entries
               if isinstance(entry, dict)
               and str(entry.get('path', '')).split('/')[0] != top]
    return git_tree_sha(entries, schema=schema)


def versioned_receipt_path(parent_sha):
    if not _oid40(parent_sha):
        raise ValueError('invalid-receipt-parent')
    return f'{VERSIONED_RECEIPTS}/{parent_sha}.json'


def _without_receipt(entries, parts, read_tree):
    entry = next((row for row in entries if row.get('path') == parts[0]), None)
    if entry is None:
        return None
    remaining = [row for row in entries if row is not entry]
    if len(parts) == 1:
        if entry.get('type') != 'blob' or entry.get('mode') != '100644':
            raise Reject(3, 'versioned-receipt-not-regular')
        return remaining, entry['sha']
    if entry.get('type') != 'tree' or entry.get('mode') not in ('40000', '040000'):
        raise Reject(3, 'versioned-receipt-directory-not-regular')
    child = _without_receipt(read_tree(entry['sha']), parts[1:], read_tree)
    if child is None:
        return None
    child_entries, receipt_blob = child
    if child_entries:
        remaining.append(dict(entry, sha=git_tree_sha(child_entries, schema=GIT_TREE_SCHEMA)))
    return remaining, receipt_blob


def resolve_receipt_path(entries, parent_sha, read_tree, read_parent_tree_sha):
    """Select one new regular receipt, or keep the historical singleton path."""
    versioned = versioned_receipt_path(parent_sha)
    change = _without_receipt(entries, versioned.split('/'), read_tree)
    if change is None:
        for tree in (entries, read_tree(read_parent_tree_sha())):
            receipts = next((row for row in tree if row.get('path') == 'receipts'), None)
            if receipts and receipts.get('type') == 'tree' and any(
                    row.get('path') == 'ansible' for row in read_tree(receipts['sha'])):
                raise Reject(3, 'versioned-receipt-for-parent-required')
        return RECEIPT_PATH, None
    remaining, receipt_blob = change
    # Removing only the new path must reconstruct the entire reviewed parent,
    # including all previous receipts and file modes.
    if git_tree_sha(remaining, schema=GIT_TREE_SCHEMA) != read_parent_tree_sha():
        raise Reject(3, 'versioned-receipt-not-sole-addition')
    return versioned, receipt_blob


def canonical_evidence_ref(path, schema):
    if not isinstance(path, str) or not path.startswith(EVIDENCE_ROOT):
        return False
    parts = path[len(EVIDENCE_ROOT):].split('/')
    if len(parts) < 3 or any(
        part in ('.', '..') or re.fullmatch(r'[A-Za-z0-9._-]+', part) is None for part in parts
    ):
        return False
    if schema == GIT_TREE_SCHEMA:
        return parts[-1] == 'SHA256SUMS.captures'
    return schema == SCHEMA and parts[-1] in ('receipt.json', 'SHA256SUMS.captures')


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


def verify_receipt(raw, *, head_sha, parent_sha, head_tree_sha, head_tree_entries,
                   trust=None, now=None, repo=None,
                   receipt_path=RECEIPT_PATH, versioned_addition=False,
                   max_age_seconds=MAX_AGE_SECONDS):
    """Verify a receipt byte-for-byte, fail-closed, in ordered steps.

    `head_tree_sha` is the exact tree returned by
    GET /repos/{owner}/{repo}/git/commits/{head_sha}; `head_tree_entries`
    is GET /repos/{owner}/{repo}/git/trees/{head_tree_sha} (non-recursive).
    `parent_sha` is the single parent of that commit: the reviewed commit
    whose tree the receipt describes. A receipt stored in the tree it
    validates cannot bind to the hash of the commit that contains it, so the
    binding is to the reviewed parent instead (two-commit design). Tree
    binding, signature, registry, freshness, hashes and result checks are
    unchanged. For a versioned path the caller must first establish the
    append-only relation to the exact parent. Returns a decision dict.
    """
    trust = trust if trust is not None else TRUST
    now = now if now is not None else datetime.now(timezone.utc)
    receipt_sha = sha256_bytes(raw)
    decision = {
        'ok': False, 'step': 0, 'reason': 'not-verified',
        'receipt_sha256': receipt_sha, 'external_id': None,
        'target_tree_sha': None, 'head_tree_sha': head_tree_sha,
        'parent_sha': parent_sha,
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
        # The reviewed parent is mandatory: without it a receipt could never
        # bind truthfully to a commit that contains it. Fail closed if absent.
        if not _oid40(parent_sha):
            return fail(1, 'parent-context-malformed')

        # Step 2 — expected tree resolved from the PR head by the caller.
        expected_tree = head_tree_sha

        # Step 3 — allow the historic path or the verified append for this parent.
        if receipt_path != RECEIPT_PATH and not (
                versioned_addition is True and receipt_path == versioned_receipt_path(parent_sha)):
            return fail(3, 'receipt-path-not-allowlisted')

        # Step 4 — receipt bytes already fetched; hash them.
        if not isinstance(raw, (bytes, bytearray)) or not raw:
            return fail(4, 'receipt-bytes-missing')

        # Step 5 — canonical JSON schema and required fields.
        try:
            receipt = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            return fail(5, 'receipt-json-invalid')
        if not isinstance(receipt, dict) or receipt.get('schema') not in (SCHEMA, GIT_TREE_SCHEMA):
            return fail(5, 'schema-not-accepted')
        schema = receipt['schema']
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
        if schema == GIT_TREE_SCHEMA and git_tree_sha(head_tree_entries, schema=schema) != expected_tree:
            return fail(8, 'head-tree-mismatch')
        bound_tree = reviewed_tree_sha(head_tree_entries, receipt_path, schema=schema)
        decision['reviewed_tree_sha'] = bound_tree
        if not _oid40(receipt.get('target_tree_sha')) or receipt['target_tree_sha'] != bound_tree:
            return fail(8, 'target-tree-mismatch')

        # Step 9 — commit binding to the REVIEWED PARENT, not the head that
        # carries this receipt. Step 8 still binds the head tree with receipts/
        # removed; together they pin (reviewed tree, reviewed parent commit).
        if (not _oid40(receipt.get('target_commit_sha'))
                or receipt['target_commit_sha'] != parent_sha):
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
        if not canonical_evidence_ref(refs[0], schema):
            return fail(11, 'canonical-evidence-ref-required')
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
            f'receipt_schema={schema}',
            f'receipt_sha256={receipt_sha}',
            f'target_tree_sha={bound_tree}',
            f'head_tree_sha={head_tree_sha}',
            f'target_commit_sha={receipt.get("target_commit_sha")}',
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
    now = datetime.now(timezone.utc)
    try:
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo):
            raise RuntimeError('repository-not-allowlisted')
        if not _oid40(head):
            raise RuntimeError('head-not-allowlisted')
        commit = json.loads(_gh_json(f'repos/{repo}/git/commits/{head}', token))
        tree_sha = (commit.get('tree') or {}).get('sha')
        if commit.get('sha') != head or not _oid40(tree_sha):
            raise RuntimeError('head-tree-unresolved')
        # The reviewed parent comes from the API commit object, never from an
        # env var or from receipt content. A merge/multi-parent head is refused.
        parents = commit.get('parents') or []
        if (len(parents) != 1 or not isinstance(parents[0], dict)
                or not _oid40(parents[0].get('sha'))):
            raise RuntimeError('head-parent-not-single')
        parent_sha = parents[0]['sha']
        def read_tree(sha):
            if not _oid40(sha):
                raise RuntimeError('tree-sha-invalid')
            tree = json.loads(_gh_json(f'repos/{repo}/git/trees/{sha}', token))
            entries = tree.get('tree')
            if (tree.get('sha') != sha or tree.get('truncated') is not False
                    or not isinstance(entries, list)
                    or git_tree_sha(entries, schema=GIT_TREE_SCHEMA) != sha):
                raise RuntimeError('tree-unverified')
            return entries

        def read_parent_tree_sha():
            parent = json.loads(_gh_json(f'repos/{repo}/git/commits/{parent_sha}', token))
            parent_tree = (parent.get('tree') or {}).get('sha')
            if parent.get('sha') != parent_sha or not _oid40(parent_tree):
                raise RuntimeError('reviewed-parent-tree-unresolved')
            return parent_tree

        entries = read_tree(tree_sha)
        receipt_path, blob = resolve_receipt_path(entries, parent_sha, read_tree, read_parent_tree_sha)
        requested_path = os.environ.get('RECEIPT_PATH')
        if requested_path is not None and requested_path != receipt_path:
            raise Reject(3, 'receipt-path-does-not-match-tree')
        content = json.loads(_gh_json(
            f'repos/{repo}/contents/{receipt_path}?ref={head}', token))
        if content.get('encoding') != 'base64' or not isinstance(content.get('content'), str):
            raise RuntimeError('receipt-encoding-invalid')
        import base64
        raw = base64.b64decode(''.join(content['content'].split()), validate=True)
        if blob is not None:
            blob_bytes = str(len(raw)).encode('ascii') + b'\0' + raw
            if (content.get('sha') != blob or content.get('type') != 'file'
                    or hashlib.sha1(b'blob ' + blob_bytes).hexdigest() != blob):
                raise Reject(3, 'versioned-receipt-blob-mismatch')
        return verify_receipt(raw, head_sha=head, parent_sha=parent_sha,
                              head_tree_sha=tree_sha, head_tree_entries=entries,
                              trust=TRUST, now=now, repo=repo, receipt_path=receipt_path,
                              versioned_addition=blob is not None)
    except Exception as exc:
        step = exc.step if isinstance(exc, Reject) else 2
        reason = str(exc) if isinstance(exc, Reject) else f'fetch-error:{type(exc).__name__}'
        return {
            'ok': False, 'step': step, 'reason': reason,
            'receipt_sha256': None, 'external_id': None, 'target_tree_sha': None,
            'head_tree_sha': None, 'reviewed_tree_sha': None,
            'ansible_version': None, 'result': None, 'details_url': None,
            'receipt_ref': None, 'verification_time': now.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'title': 'no valid Ansible validation receipt',
            'text': (f'No valid Ansible validation receipt. {reason} '
                     f'(verification step {step}). No success conclusion is emitted.'),
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
