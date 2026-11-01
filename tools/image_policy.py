"""Dockerfile policy and image size budget checks for the hardened image pipeline.

Pure functions: no Docker calls, no network. Integrate from tools/image_ci.py.
"""
import json
import re
from pathlib import Path

UPGRADE = re.compile(r'\b(?:apk|apt-get|apt)\s+upgrade\b')
ADD_INSTRUCTION = re.compile(r'^\s*ADD\s', re.M)
LATEST_TAG = re.compile(r'^\s*FROM\s+\S+:latest(?:\s|$)', re.M)
USER_INSTRUCTION = re.compile(r'^\s*USER\s+(\S+)', re.M)
FROM_INSTRUCTION = re.compile(r'^[ \t]*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?', re.I)
EXCEPTION = re.compile(r'#\s*policy:\s*allow-(upgrade|root)\s+(\S.{0,120})')


def _strip_comments(text):
    return '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))


def _exceptions(text):
    return {kind: reason.strip() for kind, reason in EXCEPTION.findall(text)}


def _final_stage_user(body):
    """Resolve USER in the runtime stage, including inheritance from local aliases.

    External image defaults cannot be verified from Dockerfile text and require an
    explicit USER (or a documented allow-root exception).
    """
    stage_users = {}
    current_user = None
    current_alias = None
    for line in body.splitlines():
        stage = FROM_INSTRUCTION.match(line)
        if stage:
            source, alias = stage.groups()
            current_user = stage_users.get(source.lower())
            current_alias = alias.lower() if alias else None
            if current_alias:
                stage_users[current_alias] = current_user
            continue
        user = USER_INSTRUCTION.match(line)
        if user:
            current_user = user.group(1)
            if current_alias:
                stage_users[current_alias] = current_user
    return current_user


def check_dockerfile(path):
    """Return a list of policy violations for one Dockerfile.

    Comments are ignored so that a documented exception does not trip the checks.
    Continuation lines are covered: upgrades are searched in the whole body, not
    only at the start of a RUN line.
    """
    text = Path(path).read_text()
    body = _strip_comments(text)
    allowed = _exceptions(text)
    problems = []
    if UPGRADE.search(body) and 'upgrade' not in allowed:
        problems.append('forbidden-upgrade-instruction')
    if ADD_INSTRUCTION.search(body):
        problems.append('add-instead-of-copy')
    if LATEST_TAG.search(body):
        problems.append('latest-tag-in-from')
    final_user = _final_stage_user(body)
    if final_user is None and 'root' not in allowed:
        problems.append('missing-final-user')
    elif final_user is not None and final_user.split(':', 1)[0] in ('0', 'root') and 'root' not in allowed:
        problems.append('root-final-user')
    return problems


def check_budget(name, size_bytes, budgets_path):
    budgets = json.loads(Path(budgets_path).read_text())
    limit = budgets.get(name)
    if limit is None:
        return []
    if size_bytes > limit:
        return ['size-budget-exceeded:%s>%s' % (size_bytes, limit)]
    return []
