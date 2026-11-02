"""Dockerfile policy and image size budget checks for the hardened image pipeline.

Pure functions: no Docker calls, no network. Integrate from tools/image_ci.py.
"""
import json
import re
from pathlib import Path

UPGRADE = re.compile(r'\b(?:apk|apt-get|apt)\s+upgrade\b')
ADD_INSTRUCTION = re.compile(r'^\s*ADD\s', re.M | re.I)
LATEST_TAG = re.compile(r'^\s*FROM\s+\S+:latest(?:\s|$)', re.M | re.I)
USER_INSTRUCTION = re.compile(r'^\s*USER\s+(\S+)', re.M | re.I)
FROM_INSTRUCTION = re.compile(r'^[ \t]*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?', re.I)
EXCEPTION = re.compile(r'#\s*policy:\s*allow-(upgrade|root)\s+(\S.{0,120})')
ESCAPE_DIRECTIVE = re.compile(r'^#\s*escape\s*=\s*([`\\])\s*$', re.I)
HEREDOC = re.compile(r"<<(-?)(['\"]?)([A-Za-z_][A-Za-z0-9_.-]*)\2")


def _strip_comments(text):
    return '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))


def _exceptions(text):
    return {kind: reason.strip() for kind, reason in EXCEPTION.findall(text)}


def _logical_instructions(text):
    """Skip continuations and heredoc bodies when identifying Dockerfile opcodes."""
    lines = iter(text.splitlines())
    escape = '\\'
    started = False
    for line in lines:
        stripped = line.strip()
        if not started and line.startswith('#'):
            directive = ESCAPE_DIRECTIVE.fullmatch(line)
            if directive:
                escape = directive.group(1)
        if not stripped or stripped.startswith('#'):
            continue
        started = True
        parts = []
        while True:
            segment = line.rstrip()
            continued = segment.endswith(escape)
            parts.append(segment[:-1] if continued else segment)
            if not continued:
                break
            line = next(lines, None)
            if line is None:
                raise ValueError('incomplete-dockerfile-continuation')
            while line.lstrip().startswith('#'):
                line = next(lines, None)
                if line is None:
                    raise ValueError('incomplete-dockerfile-continuation')
        instruction = ' '.join(parts).strip()
        yield instruction
        for tabs, _, delimiter in HEREDOC.findall(instruction):
            for line in lines:
                if (line.lstrip('\t') if tabs else line) == delimiter:
                    break
            else:
                raise ValueError('unterminated-dockerfile-heredoc')


def _final_stage_user(body):
    """Resolve USER in the runtime stage, including inheritance from local aliases.

    External image defaults cannot be verified from Dockerfile text and require an
    explicit USER (or a documented allow-root exception).
    """
    stage_users = {}
    current_user = None
    current_alias = None
    for instruction in _logical_instructions(body):
        stage = FROM_INSTRUCTION.match(instruction)
        if stage:
            source, alias = stage.groups()
            current_user = stage_users.get(source.lower())
            current_alias = alias.lower() if alias else None
            if current_alias:
                stage_users[current_alias] = current_user
            continue
        user = USER_INSTRUCTION.match(instruction)
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
    instructions = list(_logical_instructions(text))
    allowed = _exceptions(text)
    problems = []
    if UPGRADE.search(body) and 'upgrade' not in allowed:
        problems.append('forbidden-upgrade-instruction')
    if any(ADD_INSTRUCTION.match(instruction) for instruction in instructions):
        problems.append('add-instead-of-copy')
    if any(LATEST_TAG.match(instruction) for instruction in instructions):
        problems.append('latest-tag-in-from')
    final_user = _final_stage_user(text)
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
