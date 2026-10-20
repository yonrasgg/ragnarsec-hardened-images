#!/usr/bin/env python3
"""Bounded image validation on a disposable standard Linux AMD64 runner.

No production hosts, deployment, global Docker cleanup, or persistent caches.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = 'ghcr.io/yonrasgg/'


def catalog():
    result = {}
    for dockerfile in sorted(ROOT.glob('*/Dockerfile')) + sorted(ROOT.glob('plane/*/Dockerfile')):
        relative = dockerfile.relative_to(ROOT)
        name = 'ragnarsec-' + ('plane-' + dockerfile.parent.name if relative.parts[0] == 'plane' else dockerfile.parent.name)
        parents = re.findall(r'^FROM\s+ghcr\.io/yonrasgg/(ragnarsec-[\w-]+):\$\{BASE_TAG\}', dockerfile.read_text(), re.M)
        result[name] = {'name':name, 'context':'.' if relative.parts[0]=='plane' else dockerfile.parent.name,
                        'dockerfile':relative.as_posix(), 'parents':list(dict.fromkeys(parents))}
    return result


def plan(selected, images=None):
    images = catalog() if images is None else images
    ordered, visiting, done = [], set(), set()
    def visit(name):
        if name not in images:
            raise ValueError('unknown-image')
        if name in visiting:
            raise ValueError('dependency-cycle')
        if name in done:
            return
        visiting.add(name)
        for parent in images[name]['parents']:
            visit(parent)
        visiting.remove(name)
        done.add(name)
        ordered.append(images[name])
    visit(selected)
    return ordered


def command(*args, capture=False):
    return subprocess.run(args, cwd=ROOT, check=True, text=True, capture_output=capture)


def validate(selected, tag, output):
    if not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{0,119}', tag):
        raise ValueError('invalid-image-tag')
    command('python3', 'tools/publication_guard.py', '.', '--history')
    output.mkdir(mode=0o700, exist_ok=False)
    receipts = []
    for image in plan(selected):
        name = image['name']
        test = ROOT/'tests'/(name+'.yaml')
        if not test.is_file():
            raise ValueError('missing-structure-test')
        ref = REGISTRY+name+':'+tag
        command('hadolint', '--ignore', 'DL3007', image['dockerfile'])
        command('docker', 'build', '--platform', 'linux/amd64', '--build-arg', 'BASE_TAG='+tag,
                '--build-arg', 'BUILD_DATE='+os.environ.get('BUILD_DATE','1970-01-01T00:00:00Z'),
                '--build-arg', 'VCS_REF='+(os.environ.get('GIT_COMMIT') or os.environ.get('GITHUB_SHA') or 'local'),
                '-t', ref, '-f', image['dockerfile'], image['context'])
        image_id = command('docker', 'image', 'inspect', '--format={{.Id}}', ref, capture=True).stdout.strip()
        command('container-structure-test', 'test', '--image', ref, '--config', str(test))
        command('trivy', 'image', '--scanners', 'vuln,secret,misconfig', '--severity', 'HIGH,CRITICAL',
                '--exit-code', '1', '--image-config-scanners', 'misconfig,secret', '--ignorefile', '/dev/null', ref)
        command('trivy', 'image', '--scanners', 'license', '--format', 'table', '--exit-code', '0', ref)
        sbom = output/(name+'.cdx.json')
        command('trivy', 'image', '--format', 'cyclonedx', '--output', str(sbom), ref)
        receipts.append({'ref':ref, 'id':image_id, 'sbom':sbom.name,
                         'sbom_sha256':hashlib.sha256(sbom.read_bytes()).hexdigest()})
    (output/'validated.json').write_text(json.dumps(receipts, indent=2)+'\n')
    print(json.dumps({'validated_images':len(receipts), 'platform':'linux/amd64', 'published':False}))


def publish(selected, tag, output):
    # Publishing requires explicit enablement, a signing key and a validated receipt.
    # The orchestrator (Jenkins) enables this only inside the approved publication stage.
    if os.environ.get('PUBLICATION_ENABLED') != 'true':
        raise ValueError('publication-not-enabled')
    key = os.environ.get('COSIGN_KEY')
    if not key or not Path(key).is_file():
        raise ValueError('signing-key-not-configured')
    expected = [REGISTRY+i['name']+':'+tag for i in plan(selected)]
    receipts = json.loads((output/'validated.json').read_text())
    if [r['ref'] for r in receipts] != expected:
        raise ValueError('validation-receipt-mismatch')
    for r in receipts:
        if Path(r['sbom']).name != r['sbom']:
            raise ValueError('sbom-path')
        if hashlib.sha256((output/r['sbom']).read_bytes()).hexdigest() != r['sbom_sha256']:
            raise ValueError('sbom-changed')
        actual = command('docker','image','inspect','--format={{.Id}}',r['ref'],capture=True).stdout.strip()
        if actual != r['id']:
            raise ValueError('validated-image-changed')
    for r in receipts:
        command('docker', 'push', r['ref'])
        digests = json.loads(command('docker','image','inspect','--format={{json .RepoDigests}}',r['ref'],capture=True).stdout)
        repository = r['ref'].rsplit(':',1)[0]
        digest = next((d for d in digests or [] if d.startswith(repository+'@sha256:')),None)
        if not digest or not re.fullmatch(re.escape(repository)+r'@sha256:[a-f0-9]{64}',digest):
            raise ValueError('pushed-digest-unconfirmed')
        command('cosign','sign','--yes','--key',key,digest)
        command('cosign','attest','--yes','--key',key,'--type','cyclonedx','--predicate',str(output/r['sbom']),digest)
        command('cosign','verify','--key',key,digest)
        command('cosign','verify-attestation','--type','cyclonedx','--key',key,digest)
        print('Published and signature/attestation verified: '+digest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['plan','validate','publish'])
    parser.add_argument('--image',required=True,choices=sorted(catalog()))
    parser.add_argument('--tag',default='local-validation')
    parser.add_argument('--output',type=Path)
    args = parser.parse_args()
    if args.action == 'plan':
        print(json.dumps(plan(args.image)))
    else:
        if args.output is None:
            parser.error('--output required')
        if args.action=='validate': validate(args.image,args.tag,args.output)
        else: publish(args.image,args.tag,args.output)


if __name__ == '__main__':
    main()
