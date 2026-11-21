"""Infer the catalog image a change request touches, so PR builds need no human parameter.

Rules (first match wins):
1. ``--image`` explicitly given and not empty -> use it (manual builds keep working).
2. Changed paths under exactly one recipe directory (``<dir>/Dockerfile`` exists) -> that image.
3. Changed paths under several recipe directories -> fail: one image per build is the
   pipeline contract; the author splits the PR or dispatches manually.
4. Only shared files changed (``tools/``, ``tests/``, ``Jenkinsfile``, docs) -> the
   smallest base recipe (``ragnarsec-base-min``) so the plan-only gates still run.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
FALLBACK_IMAGE = 'ragnarsec-base-min'


def _catalog():
    spec = importlib.util.spec_from_file_location('image_ci', ROOT / 'tools' / 'image_ci.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.catalog()


def changed_paths(base_ref, head_ref):
    """Paths changed between two refs (``git diff --name-only``), relative to the repo root."""
    out = subprocess.run(['git', 'diff', '--name-only', f'{base_ref}...{head_ref}'],
                         cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return [p for p in out.splitlines() if p]


def images_for_paths(paths, catalog):
    """Map changed paths to catalog images by recipe context directory."""
    by_context = {}
    for image in catalog.values():
        by_context.setdefault(image['context'], image['name'])
        by_context.setdefault(str(Path(image['dockerfile']).parent), image['name'])
    hit = set()
    for p in paths:
        parts = Path(p).parts
        if not parts:
            continue
        for depth in (2, 1):
            key = '/'.join(parts[:depth])
            if key in by_context:
                hit.add(by_context[key])
                break
    return sorted(hit)


def select(explicit, paths, catalog):
    if explicit:
        if explicit not in catalog:
            raise ValueError('unknown-image:' + explicit)
        return explicit, 'explicit'
    hit = images_for_paths(paths, catalog)
    if len(hit) == 1:
        return hit[0], 'inferred-from-diff'
    if len(hit) > 1:
        raise ValueError('multiple-images-changed:' + ','.join(hit))
    return FALLBACK_IMAGE, 'fallback-shared-change'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='')
    parser.add_argument('--base', required=True, help='base ref, e.g. origin/development')
    parser.add_argument('--head', default='HEAD')
    args = parser.parse_args()
    catalog = _catalog()
    paths = changed_paths(args.base, args.head)
    image, reason = select(args.image, paths, catalog)
    print(json.dumps({'image': image, 'reason': reason, 'changed_paths': len(paths)}))
    print(image, file=sys.stderr)


if __name__ == '__main__':
    main()
