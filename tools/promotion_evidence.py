"""Evaluate normalized staging-to-main evidence without authorizing a merge.

Only a trusted collector may supply inputs: it must authenticate producers,
recheck live refs, and compute the plan from the reviewed candidate and policy.
Pull request text, arbitrary JSON, and a green commit status are not evidence.
This module has no network, GitHub write, or Jenkins scheduling capability.
"""
import re


REPOSITORY_ID = 1426336836
JENKINS_APP_ID = 5736684
PLATFORMS = ('linux/amd64', 'linux/arm64')
REVISION_FIELDS = ('head_sha', 'base_sha', 'candidate_sha', 'policy_sha')
CONTROL_CHECKS = ('source', 'contract', 'secrets')


def _hex(value, length):
    return isinstance(value, str) and re.fullmatch(f'[0-9a-f]{{{length}}}', value) is not None


def _positive(value):
    return type(value) is int and value > 0


def _image(value):
    return isinstance(value, str) and re.fullmatch(r'[a-z0-9][a-z0-9-]*', value) is not None


def _binding(value):
    return (isinstance(value, dict)
            and value.get('repository_id') == REPOSITORY_ID
            and _positive(value.get('pull_request'))
            and all(_hex(value.get(field), 40) for field in REVISION_FIELDS))


def _same_binding(expected, received):
    return (_binding(received)
            and all(expected[key] == received.get(key)
                    for key in ('repository_id', 'pull_request', *REVISION_FIELDS)))


def _valid_plan(plan):
    return isinstance(plan, dict) and all(
        _image(lane) and isinstance(images, list) and all(_image(image) for image in images)
        and lane in images and len(set(images)) == len(images)
        for lane, images in plan.items()
    )


def _decision(reason, *, ready=False):
    return {'ready': ready, 'reason': reason, 'merge_authorized': False}


def _verify_rows(rows, images):
    if not isinstance(rows, list):
        return 'invalid-platform-receipts'
    expected = {(image, platform) for image in images for platform in PLATFORMS}
    seen = set()
    for row in rows:
        if (not isinstance(row, dict) or not _image(row.get('image'))
                or row.get('platform') not in PLATFORMS or row.get('scan_enforced') is not True
                or row.get('sbom_hash_ok') is not True or not _hex(row.get('sbom_sha256'), 64)):
            return 'unverified-platform-receipt'
        pair = row['image'], row['platform']
        if pair in seen:
            return 'duplicate-platform-receipt'
        seen.add(pair)
    if seen != expected:
        return 'incomplete-platform-receipts'
    return None


def evaluate(expected, live, plan, checks, receipts):
    """Check complete, same-candidate evidence supplied by a trusted collector.

    A plan maps each selected build lane to the exact images it must produce,
    including build dependencies. An empty plan is meaningful only when the
    trusted planner proves no image lanes are needed. Checks and receipts are
    the normalized current results, not a list of historic status events.
    """
    if not _binding(expected):
        return _decision('invalid-reviewed-binding')
    if not _same_binding(expected, live):
        return _decision('live-binding-mismatch')
    if (live.get('source_repo_id') != REPOSITORY_ID or live.get('source') != 'staging'
            or live.get('target') != 'main' or live.get('state') != 'open' or live.get('draft') is not False):
        return _decision('unsupported-promotion')
    if not _valid_plan(plan):
        return _decision('invalid-image-plan')
    if (not isinstance(checks, dict) or checks.get('app_id') != JENKINS_APP_ID
            or not _same_binding(expected, checks.get('binding'))
            or any(checks.get(name) != 'success' for name in CONTROL_CHECKS)):
        return _decision('unverified-control-checks')
    if not isinstance(receipts, list):
        return _decision('invalid-image-receipts')
    lanes, runs = set(), set()
    for receipt in receipts:
        if not isinstance(receipt, dict):
            return _decision('invalid-image-receipts')
        if not _same_binding(expected, receipt.get('binding')):
            return _decision('receipt-binding-mismatch')
        lane, run = receipt.get('lane'), receipt.get('run_id')
        if (receipt.get('app_id') != JENKINS_APP_ID or not _positive(run)
                or receipt.get('publish') is not False or receipt.get('result') != 'success'
                or not _hex(receipt.get('summary_sha256'), 64)):
            return _decision('unverified-image-receipt')
        if not _image(lane) or lane not in plan:
            return _decision('unexpected-image-receipt')
        if lane in lanes or run in runs:
            return _decision('duplicate-image-receipt')
        row_failure = _verify_rows(receipt.get('rows'), plan[lane])
        if row_failure:
            return _decision(row_failure)
        lanes.add(lane)
        runs.add(run)
    if lanes != set(plan):
        return _decision('incomplete-image-plan')
    return _decision('complete-evidence', ready=True)
