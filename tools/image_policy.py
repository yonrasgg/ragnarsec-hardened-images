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
EXCEPTION = re.compile(r'#\s*policy:\s*allow-(upgrade|root)\s+(\S.{0,120})')


def _strip_comments(text):
    return '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))


def _exceptions(text):
    return {kind: reason.strip() for kind, reason in EXCEPTION.findall(text)}


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
    users = USER_INSTRUCTION.findall(body)
    final_user = users[-1] if users else None
    if final_user is None and 'root' not in allowed:
        problems.append('missing-final-user')
    elif final_user in ('0', 'root') and 'root' not in allowed:
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
