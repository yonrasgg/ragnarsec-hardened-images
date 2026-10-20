#!/usr/bin/env python3
"""Read-only publication boundary check. Findings never contain matched values.

This complements a pinned secret scanner; a clean result is not proof of absence.
"""
import argparse
import ipaddress
import json
import re
import subprocess
from pathlib import Path

IP = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
NETWORKS = tuple(ipaddress.ip_network((int(ipaddress.IPv4Address(bytes(octets))), prefix))
                 for octets, prefix in [([10, 0, 0, 0], 8), ([172, 16, 0, 0], 12),
                                        ([192, 168, 0, 0], 16), ([169, 254, 0, 0], 16)])
RULES = {
    'private-key': re.compile(r'-----BEGIN (?:[A-Z0-9 ]+)?PRIVATE KEY-----'),
    'cloud-resource-id': re.compile(r'ocid1\.[a-z]+\.[a-z0-9.]+', re.I),
    'internal-domain': re.compile(r'\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:local|internal|lan)\b', re.I),
    'hardware-address': re.compile(r'\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b', re.I),
    'downstream-dispatch': re.compile(r'api\.github\.com/repos/[^\s/]+/[^\s/]+/dispatches'),
    'personal-email': re.compile(r'\b[\w.+-]+@(?:gmail|hotmail|outlook|yahoo)\.com\b', re.I),
}
EXCLUDED_DIRS = {'.git', '__pycache__'}
SENSITIVE_NAMES = {'.env', '.netrc', '.npmrc', '.pypirc', 'id_rsa', 'id_ed25519', 'credentials', 'terraform.tfstate'}
INTERNAL_DIRS = {'.agents', '.codex', '.opencode', '.claude', '.context', 'contexts', 'context', 'skills', 'routes', 'agents', 'prompts', 'instructions', '.cursor', '.windsurf', '.roo', '.continue'}
INTERNAL_NAMES = {'agents.md', 'claude.md', 'gemini.md', 'skill.md', 'context.md', 'context.json',
                  'context.yaml', 'context.yml', 'routes.md', 'routers.md', 'agents.override.md', 'mcp.json', 'routes.json', 'routes.yaml', 'routes.yml',
                  'opencode.json', 'opencode.jsonc', 'copilot-instructions.md'}


def internal_metadata(path):
    parts = Path(path).parts
    name = parts[-1].lower()
    return (any(part.lower() in INTERNAL_DIRS for part in parts)
            or name in INTERNAL_NAMES or name.endswith('.instructions.md')
            or name.startswith(('ctx-rou-', 'ctx-pnd-', 'handoff-')))


MAX_BYTES = 2 * 1024 * 1024


def scan_text(text):
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        for name, pattern in RULES.items():
            if pattern.search(line):
                found.append({'rule': name, 'line': number})
        for match in IP.finditer(line):
            try:
                address = ipaddress.ip_address(match.group())
            except ValueError:
                continue
            if any(address in network for network in NETWORKS):
                found.append({'rule': 'private-network', 'line': number})
                break
    return found


def scan_tree(root):
    root = Path(root)
    if not root.is_dir() or root.is_symlink():
        raise ValueError('root-must-be-real-directory')
    findings, files = [], 0
    stack = [root]
    while stack:
        directory = stack.pop()
        for item in sorted(directory.iterdir()):
            rel = item.relative_to(root).as_posix()
            if internal_metadata(rel):
                findings.append({'path': rel, 'rule': 'internal-metadata-not-public'})
                continue  # Classify by path; do not open internal payloads.
            if item.is_symlink():
                findings.append({'path': rel, 'rule': 'symlink-requires-review'})
                continue
            if item.is_dir():
                if item.name not in EXCLUDED_DIRS:
                    stack.append(item)
                continue
            if not item.is_file():
                findings.append({'path': rel, 'rule': 'special-file'})
                continue
            files += 1
            if item.name in SENSITIVE_NAMES or item.suffix.lower() in {'.key', '.pem', '.p12', '.pfx', '.pcap', '.kdbx'} or (item.name.startswith('.env.') and item.name != '.env.example'):
                findings.append({'path': rel, 'rule': 'sensitive-file-name'})
                continue  # Do not open known credential/key files.
            if item.stat().st_size > MAX_BYTES:
                findings.append({'path': rel, 'rule': 'oversized-requires-review'})
                continue
            try:
                data = item.read_bytes()
                if b'\0' in data:
                    raise UnicodeError()
                text = data.decode('utf-8')
            except UnicodeError:
                findings.append({'path': rel, 'rule': 'binary-requires-review'})
                continue
            findings.extend(dict(path=rel, **f) for f in scan_text(text))
    return {'files': files, 'findings': findings}


def scan_history(root):
    def git(*args):
        result = subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True, text=True)
        return result.stdout
    if git('rev-parse', '--is-shallow-repository').strip() != 'false':
        raise ValueError('complete-history-required')
    paths = git('log', 'HEAD', '--format=', '--name-only', '-z', '--no-renames').split('\0')
    return [{'path':path.strip(), 'rule':'internal-metadata-in-intended-history'}
            for path in sorted(set(paths)) if path.strip() and internal_metadata(path.strip())]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--history', action='store_true', help='Require complete intended HEAD history and reject internal metadata paths')
    args = parser.parse_args()
    try:
        result = scan_tree(args.root)
        if args.history:
            result['findings'].extend(scan_history(args.root))
    except (OSError, ValueError, subprocess.CalledProcessError):
        print(json.dumps({'result': 'error', 'exit_code': 2, 'reason': 'incomplete-scan'}))
        return 2
    result.update(result='pass' if not result['findings'] else 'blocked', exit_code=0 if not result['findings'] else 1,
                  scope='worktree-and-intended-history-paths' if args.history else 'worktree-only', limitations=['no-full-secret-or-semantic-architecture-review'] + ([] if args.history else ['no-history-scan']))
    print(json.dumps(result, sort_keys=True))
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
