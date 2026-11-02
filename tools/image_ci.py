#!/usr/bin/env python3
"""Bounded multi-arch image validation.

Runner requirements: Linux x86_64 with buildx and binfmt/qemu for ARM64 target
images. The pinned CI tools are AMD64-only; native ARM64 hosts are not yet
supported. No production hosts, deployment, global Docker cleanup or caches.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = 'ghcr.io/yonrasgg/'
sys.path.insert(0, str(Path(__file__).resolve().parent))
import image_policy as policy  # noqa: E402

# Default keeps the previous behaviour explicit instead of implicit.
DEFAULT_PLATFORMS = ('linux/amd64', 'linux/arm64')
ALLOWED_PLATFORMS = {'linux/amd64': 'amd64', 'linux/arm64': 'arm64'}
QEMU_HANDLERS = {'amd64': 'qemu-x86_64', 'arm64': 'qemu-aarch64'}
BASE_MIN_APK_PACKAGES = {'alpine-baselayout-data', 'alpine-release',
                         'ca-certificates-bundle', 'musl', 'tini'}


def platforms():
    raw = os.environ.get('PLATFORMS', ','.join(DEFAULT_PLATFORMS))
    items = [p.strip() for p in raw.split(',') if p.strip()]
    if not items:
        raise ValueError('no-platforms')
    unknown = [p for p in items if p not in ALLOWED_PLATFORMS]
    if unknown:
        raise ValueError('unsupported-platform:' + ','.join(unknown))
    if len(set(items)) != len(items):
        raise ValueError('duplicate-platform')
    return items


def catalog():
    result = {}
    for dockerfile in sorted(ROOT.glob('*/Dockerfile')) + sorted(ROOT.glob('plane/*/Dockerfile')):
        relative = dockerfile.relative_to(ROOT)
        name = 'ragnarsec-' + ('plane-' + dockerfile.parent.name if relative.parts[0] == 'plane' else dockerfile.parent.name)
        parents = re.findall(r'^FROM\s+ghcr\.io/yonrasgg/(ragnarsec-[\w-]+):\$\{BASE_TAG\}', dockerfile.read_text(), re.M)
        result[name] = {'name': name, 'context': '.' if relative.parts[0] == 'plane' else dockerfile.parent.name,
                        'dockerfile': relative.as_posix(), 'parents': list(dict.fromkeys(parents))}
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


def require_platforms_available(targets):
    host = os.uname().machine
    if host != 'x86_64':
        raise ValueError('unsupported-ci-host-arch:' + host)
    for platform in targets:
        arch = ALLOWED_PLATFORMS[platform]
        if arch == 'amd64':
            continue
        marker = Path('/proc/sys/fs/binfmt_misc') / QEMU_HANDLERS[arch]
        if not marker.exists():
            raise ValueError('platform-not-native-and-not-emulated:' + platform)


def require_local_parent_builder():
    """The docker driver shares --load images with dependent FROM instructions."""
    info = command('docker', 'buildx', 'inspect', capture=True).stdout
    driver = re.search(r'^Driver:[ \t]*(\S+)[ \t]*$', info, re.M)
    if not driver or driver.group(1) != 'docker':
        raise ValueError('builder-must-use-docker-driver')


def _build_args(image, tag, platform):
    return ('--build-arg', 'BASE_TAG=' + tag,
            '--build-arg', 'BUILD_DATE=' + os.environ.get('BUILD_DATE', '1970-01-01T00:00:00Z'),
            '--build-arg', 'VCS_REF=' + (os.environ.get('GIT_COMMIT') or os.environ.get('GITHUB_SHA') or 'local'),
             '-f', image['dockerfile'], image['context'])


def require_base_min_inventory(sbom):
    """A green scan is meaningless if the runtime's APK packages are invisible."""
    components = json.loads(sbom.read_text()).get('components') or []
    apk = [c for c in components if (c.get('purl') or '').startswith('pkg:apk/alpine/')]
    names = [c.get('name') for c in apk]
    if (set(names) != BASE_MIN_APK_PACKAGES or len(names) != len(BASE_MIN_APK_PACKAGES)
            or any(not c.get('version') for c in apk)
            or not any(c.get('name') == 'alpine' for c in components)):
        raise ValueError('base-min-sbom-package-inventory-mismatch')


def validate(selected, tag, output):
    if not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{0,119}', tag):
        raise ValueError('invalid-image-tag')
    targets = platforms()
    require_platforms_available(targets)
    require_local_parent_builder()
    command('python3', 'tools/publication_guard.py', '.', '--history')
    output.mkdir(mode=0o700, exist_ok=False)
    receipts = []
    for image in plan(selected):
        name = image['name']
        test = ROOT / 'tests' / (name + '.yaml')
        if not test.is_file():
            raise ValueError('missing-structure-test')
        command('hadolint', '--ignore', 'DL3007', '--failure-threshold', 'warning', image['dockerfile'])
        problems = policy.check_dockerfile(ROOT / image['dockerfile'])
        cfg = json.loads((ROOT / 'policy.json').read_text())
        if problems and name in cfg.get('enforce', []):
            raise ValueError('dockerfile-policy:' + ','.join(problems))
        elif problems:
            print('POLICY_WARN ' + name + ' ' + ','.join(problems))
        for platform in targets:
            suffix = ALLOWED_PLATFORMS[platform]
            ref = REGISTRY + name + ':' + tag + '-' + suffix
            # buildx --load supports one platform per invocation; this keeps the
            # structure test and the scanner honest about the exact bytes.
            # Disable Buildx attestations: with a containerd store, even a single
            # platform otherwise pushes an index (runtime + provenance) rather
            # than the manifest that the publish/signing checks expect. Trivy
            # generates the SBOM; Cosign signs and attests the validated result.
            # Parents are tagged with the platform suffix, so BASE_TAG must match
            # that suffix or dependent recipes would look for a tag never built.
            command('docker', 'buildx', 'build', '--platform', platform,
                    '--provenance=false', '--sbom=false', '--load',
                    '-t', ref, *_build_args(image, tag + '-' + suffix, platform))
            image_id = command('docker', 'image', 'inspect', '--format={{.Id}}', ref, capture=True).stdout.strip()
            size = int(command('docker', 'image', 'inspect', '--format={{.Size}}', ref, capture=True).stdout.strip())
            over = policy.check_budget(name, size, ROOT / 'budgets.json')
            if over:
                raise ValueError(over[0])
            command('container-structure-test', 'test', '--image', ref, '--config', str(test))
            command('trivy', 'image', '--scanners', 'vuln,secret,misconfig', '--severity', 'HIGH,CRITICAL',
                    '--exit-code', '1', '--exit-on-eol', '1', '--image-config-scanners',
                    'misconfig,secret', '--ignorefile', '/dev/null', ref)
            command('trivy', 'image', '--scanners', 'license', '--format', 'table', '--exit-code', '0', ref)
            sbom = output / (name + '.' + suffix + '.cdx.json')
            command('trivy', 'image', '--format', 'cyclonedx', '--output', str(sbom), ref)
            if name == 'ragnarsec-base-min':
                require_base_min_inventory(sbom)
            receipts.append({'ref': ref, 'name': name, 'platform': platform, 'id': image_id,
                             'sbom': sbom.name,
                             'sbom_sha256': hashlib.sha256(sbom.read_bytes()).hexdigest()})
    (output / 'validated.json').write_text(json.dumps(receipts, indent=2) + '\n')
    print(json.dumps({'validated_images': len(receipts), 'platforms': targets, 'published': False}))


def _inspect(ref):
    data = json.loads(command('docker', 'buildx', 'imagetools', 'inspect', ref,
                              '--format', '{{json .Manifest}}', capture=True).stdout)
    digest = data.get('digest')
    if not digest or not re.fullmatch(r'sha256:[a-f0-9]{64}', digest):
        raise ValueError('index-digest-unconfirmed')
    repository = ref.rsplit(':', 1)[0]
    per_platform = {}
    for item in data.get('manifests') or []:
        platform = item.get('platform') or {}
        key = platform.get('os', '') + '/' + platform.get('architecture', '')
        if key in ALLOWED_PLATFORMS and item.get('digest'):
            per_platform[key] = repository + '@' + item['digest']
    return repository + '@' + digest, per_platform


def publish(selected, tag, output):
    """Promote the validated per-platform images and assemble the index.

    Nothing is rebuilt here: rebuilding would create bytes that were never
    scanned or attested. The validated local images are pushed as-is, then an
    index references their digests.
    """
    if os.environ.get('PUBLICATION_ENABLED') != 'true':
        raise ValueError('publication-not-enabled')
    key = os.environ.get('COSIGN_KEY')
    if not key or not Path(key).is_file():
        raise ValueError('signing-key-not-configured')
    targets = platforms()
    require_platforms_available(targets)
    public = output / 'cosign.pub'
    if public.exists():
        public.unlink()
    command('cosign', 'public-key', '--key', key, '--outfile', str(public))
    if not public.is_file():
        raise ValueError('public-key-not-derived')

    receipts = json.loads((output / 'validated.json').read_text())
    images = plan(selected)
    expected = sorted((i['name'], p, REGISTRY + i['name'] + ':' + tag + '-' + ALLOWED_PLATFORMS[p])
                      for i in images for p in targets)
    seen = sorted((r['name'], r['platform'], r['ref']) for r in receipts)
    if seen != expected:
        raise ValueError('validation-receipt-mismatch')

    for r in receipts:
        if Path(r['sbom']).name != r['sbom']:
            raise ValueError('sbom-path')
        if hashlib.sha256((output / r['sbom']).read_bytes()).hexdigest() != r['sbom_sha256']:
            raise ValueError('sbom-changed')
        actual = command('docker', 'image', 'inspect', '--format={{.Id}}', r['ref'], capture=True).stdout.strip()
        if actual != r['id']:
            raise ValueError('validated-image-changed')

    for image in images:
        refs = {}
        for r in receipts:
            if r['name'] != image['name']:
                continue
            command('docker', 'push', r['ref'])
            repository = r['ref'].rsplit(':', 1)[0]
            digests = json.loads(command('docker', 'image', 'inspect', '--format={{json .RepoDigests}}',
                                         r['ref'], capture=True).stdout)
            digest = next((d for d in digests or [] if d.startswith(repository + '@sha256:')), None)
            if not digest or not re.fullmatch(re.escape(repository) + r'@sha256:[a-f0-9]{64}', digest):
                raise ValueError('pushed-digest-unconfirmed:' + r['platform'])
            refs[r['platform']] = digest
        needed = targets
        missing = [p for p in needed if p not in refs]
        if missing:
            raise ValueError('platform-digest-missing:' + ','.join(missing))

        index_ref = REGISTRY + image['name'] + ':' + tag
        command('docker', 'buildx', 'imagetools', 'create', '--tag', index_ref,
                *[refs[p] for p in needed])
        index, per_platform = _inspect(index_ref)
        for platform in needed:
            if per_platform.get(platform) != refs[platform]:
                raise ValueError('index-platform-mismatch:' + platform)

        for platform in needed:
            r = next(x for x in receipts if x['name'] == image['name'] and x['platform'] == platform)
            command('cosign', 'attest', '--yes', '--key', key, '--type', 'cyclonedx',
                    '--predicate', str(output / r['sbom']), refs[platform])
            command('cosign', 'sign', '--yes', '--key', key, refs[platform])
        command('cosign', 'sign', '--yes', '--key', key, index)

        command('cosign', 'verify', '--key', str(public), index)
        for platform in needed:
            command('cosign', 'verify', '--key', str(public), refs[platform])
            command('cosign', 'verify-attestation', '--type', 'cyclonedx', '--key', str(public), refs[platform])
        print('Published validated index with signatures and attestations: ' + index)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['plan', 'validate', 'publish'])
    parser.add_argument('--image', required=True, choices=sorted(catalog()))
    parser.add_argument('--tag', default='local-validation')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.action == 'plan':
        print(json.dumps(plan(args.image)))
    else:
        if args.output is None:
            parser.error('--output required')
        if args.action == 'validate':
            validate(args.image, args.tag, args.output)
        else:
            publish(args.image, args.tag, args.output)


if __name__ == '__main__':
    main()
