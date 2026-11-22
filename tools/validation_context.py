"""Write the immutable inputs a Jenkins PR plan used, without claiming success."""
import argparse
import json
from pathlib import Path
import re


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
        with args.write.open('x', encoding='utf-8') as output:
            json.dump(binding, output, indent=2, sort_keys=True)
            output.write('\n')
    except (ValueError, OSError) as exc:
        parser.error(str(exc))


if __name__ == '__main__':
    main()
