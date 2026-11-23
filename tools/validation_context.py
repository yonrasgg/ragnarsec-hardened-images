"""Write the immutable inputs a Jenkins PR plan used, without claiming success."""
import argparse
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def build_context(*, pull_request, head_sha, base_sha, target, image, build_number, publish_requested):
    if type(pull_request) is not int or pull_request < 1:
        raise ValueError('invalid-pull-request-number')
    if type(build_number) is not int or build_number < 1:
        raise ValueError('invalid-build-number')
    if not all(isinstance(sha, str) and re.fullmatch(r'[0-9a-f]{40}', sha)
               for sha in (head_sha, base_sha)):
        raise ValueError('invalid-plan-revision')
    if target not in ('development', 'staging', 'main'):
        raise ValueError('invalid-plan-target')
    if not isinstance(image, str) or not re.fullmatch(r'ragnarsec-[a-z0-9][a-z0-9-]*', image):
        raise ValueError('invalid-selected-image')
    if type(publish_requested) is not bool:
        raise ValueError('invalid-publish-request')
    return {
        'schema_version': 1,
        'kind': 'jenkins-plan-inputs',
        'pull_request': pull_request,
        'head_sha': head_sha,
        'base_sha': base_sha,
        'target': target,
        'image': image,
        'build_number': build_number,
        'publish_requested': publish_requested,
    }


def write_context(path, binding):
    with path.open('x', encoding='utf-8') as output:
        json.dump(binding, output, indent=2, sort_keys=True)
        output.write('\n')


def resolve_revision(ref):
    return subprocess.run(['git', 'rev-parse', '--verify', '--end-of-options', f'{ref}^{{commit}}'],
                          cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()


def capture_plan_inputs(image, env):
    target = env.get('CHANGE_TARGET')
    if target not in ('development', 'staging', 'main'):
        return
    from select_image import _catalog, changed_paths, select

    publish = env['CI_PUBLISH_REQUESTED']
    if publish not in ('true', 'false'):
        raise ValueError('invalid-publish-request')
    target_ref = 'refs/remotes/origin/' + target
    base_sha, head_sha = resolve_revision(target_ref), resolve_revision('HEAD')
    paths = changed_paths(base_sha, head_sha)
    selected, _ = select(env.get('IMAGE', ''), paths, _catalog())
    if selected != image or (resolve_revision(target_ref), resolve_revision('HEAD')) != (base_sha, head_sha):
        raise ValueError('plan-revision-or-image-changed')
    binding = build_context(
        pull_request=int(env['CHANGE_ID']), build_number=int(env['BUILD_NUMBER']),
        target=target, image=image, base_sha=base_sha, head_sha=head_sha, publish_requested=publish == 'true',
    )
    write_context(Path(env['CI_ROOT']) / 'validation-context.json', binding)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pull-request', required=True, type=int)
    parser.add_argument('--head-sha', required=True)
    parser.add_argument('--base-sha', required=True)
    parser.add_argument('--target', required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--build-number', required=True, type=int)
    parser.add_argument('--publish-requested', required=True, choices=('true', 'false'))
    parser.add_argument('--write', required=True, type=Path)
    args = parser.parse_args()
    try:
        binding = build_context(pull_request=args.pull_request, head_sha=args.head_sha,
                                base_sha=args.base_sha, target=args.target, image=args.image,
                                build_number=args.build_number,
                                publish_requested=args.publish_requested == 'true')
        write_context(args.write, binding)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))


if __name__ == '__main__':
    main()
