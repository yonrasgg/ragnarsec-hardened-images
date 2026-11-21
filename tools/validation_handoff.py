#!/usr/bin/env python3
"""Verify a same-build native image transfer before publication can begin."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil

import image_ci as ci

AMD64, ARM64 = ci.DEFAULT_PLATFORMS
BUNDLE = 'handoff.json'
ARCHIVE = 'images.tar'


def hash_file(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('missing-or-unsafe-handoff-file:' + path.name)
    with path.open('rb') as handle:
        digest = hashlib.sha256()
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
        return digest.hexdigest()


def identity(selected, tag, revision):
    if (not re.fullmatch(r'[0-9a-f]{40}', revision)
            or not re.fullmatch(rf'sha-{revision}-[0-9]+(?:-[a-zA-Z0-9_.-]+)?', tag)
            or ci.command('git', 'rev-parse', '--verify', 'HEAD', capture=True).stdout.strip() != revision):
        raise ValueError('handoff-revision-mismatch')
    return {'image': selected, 'tag': tag, 'revision': revision, 'platform': ARM64}


def arm_hashes(directory, receipts):
    names = {'validated.json', 'validate.log', ARCHIVE, *(r['sbom'] for r in receipts)}
    return {name: hash_file(directory / name) for name in sorted(names)}


def pack(selected, tag, revision, directory):
    meta = identity(selected, tag, revision)
    receipts = ci.verify_receipts(selected, tag, directory, [ARM64])
    ci.command('docker', 'image', 'save', '--platform', ARM64, '-o',
               str(directory / ARCHIVE), *sorted(r['ref'] for r in receipts))
    meta['sha256'] = arm_hashes(directory, receipts)
    with (directory / BUNDLE).open('x') as manifest:
        json.dump(meta, manifest, sort_keys=True)


def assemble(selected, tag, revision, directory, output):
    # The private stash is scoped to this Jenkins run. Its checksums detect a
    # partial, stale or altered transfer, not a compromised validation agent.
    expected = identity(selected, tag, revision)
    amd = directory / 'amd64'
    arm = directory / 'arm64'
    manifest = arm / BUNDLE
    if manifest.is_symlink() or not manifest.is_file():
        raise ValueError('missing-or-unsafe-handoff-manifest')
    meta = json.loads(manifest.read_text())
    if {key: meta.get(key) for key in expected} != expected:
        raise ValueError('handoff-identity-mismatch')
    amd_rows = ci.verify_receipts(selected, tag, amd, [AMD64])
    arm_rows = ci.verify_receipts(selected, tag, arm, [ARM64], inspect_images=False)
    if meta.get('sha256') != arm_hashes(arm, arm_rows):
        raise ValueError('handoff-checksum-mismatch')
    sboms = [r['sbom'] for r in amd_rows + arm_rows]
    if len(sboms) != len(set(sboms)):
        raise ValueError('handoff-duplicate-sbom')
    output.mkdir(mode=0o700)
    for source, rows in ((amd, amd_rows), (arm, arm_rows)):
        for row in rows:
            shutil.copyfile(source / row['sbom'], output / row['sbom'])
    (output / 'validated.json').write_text(json.dumps(amd_rows + arm_rows, indent=2) + '\n')
    ci.command('docker', 'image', 'load', '--platform', ARM64, '-i', str(arm / ARCHIVE))
    ci.verify_receipts(selected, tag, output, [AMD64, ARM64])
    print('Native handoff verified: AMD64 and ARM64 receipts, SBOMs and image identities.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['pack', 'assemble'])
    parser.add_argument('--image', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.action == 'pack':
        pack(args.image, args.tag, args.revision, args.directory)
    else:
        if args.output is None:
            parser.error('--output is required for assemble')
        assemble(args.image, args.tag, args.revision, args.directory, args.output)


if __name__ == '__main__':
    main()
