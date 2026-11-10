"""Dockerfile policy and image size budget checks for the hardened image pipeline.

Pure functions: no Docker calls, no network. Integrate from tools/image_ci.py.
"""
import datetime
import json
import re
from pathlib import Path

UPGRADE = re.compile(r'\b(?:apk|apt-get|apt)\s+upgrade\b')
ADD_INSTRUCTION = re.compile(r'^\s*ADD\s', re.M | re.I)
LATEST_TAG = re.compile(r'^\s*FROM\s+(?:--platform=\S+\s+)?\S+:latest(?:\s|$)', re.M | re.I)
USER_INSTRUCTION = re.compile(r'^\s*USER\s+(\S+)', re.M | re.I)
FROM_INSTRUCTION = re.compile(r'^[ \t]*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?', re.I)
EXCEPTION = re.compile(r'#\s*policy:\s*allow-(upgrade|root)\s+(\S.{0,120})')
ESCAPE_DIRECTIVE = re.compile(r'^#\s*escape\s*=\s*([`\\])\s*$', re.I)
HEREDOC_DELIMITER = re.compile(r'[A-Za-z_][A-Za-z0-9_.-]*')


def _strip_comments(text):
    return '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))


def _exceptions(text):
    return {kind: reason.strip() for kind, reason in EXCEPTION.findall(text)}


def _heredoc_markers(instruction):
    """Return Docker heredoc markers, excluding operators inside string literals."""
    markers = []
    contexts = [{'kind': 'base', 'quote': None, 'depth': 0}]
    i = 0
    while i < len(instruction):
        context = contexts[-1]
        char = instruction[i]
        if context['quote']:
            if char == '\\' and context['quote'] == '"':
                i += 2
                continue
            if context['quote'] == '"':
                if instruction.startswith('$((', i):
                    contexts.append({'kind': 'arithmetic', 'quote': None, 'depth': 2})
                    i += 3
                    continue
                if instruction.startswith('$(', i):
                    contexts.append({'kind': 'command', 'quote': None, 'depth': 1})
                    i += 2
                    continue
                if char == '`':
                    contexts.append({'kind': 'backtick', 'quote': None, 'depth': 0})
                    i += 1
                    continue
            if char == context['quote']:
                context['quote'] = None
            i += 1
            continue
        if context['kind'] == 'backtick' and char == '`':
            contexts.pop()
            i += 1
            continue
        if instruction.startswith('$((', i):
            contexts.append({'kind': 'arithmetic', 'quote': None, 'depth': 2})
            i += 3
            continue
        if instruction.startswith('$(', i):
            contexts.append({'kind': 'command', 'quote': None, 'depth': 1})
            i += 2
            continue
        if char == '`':
            contexts.append({'kind': 'backtick', 'quote': None, 'depth': 0})
            i += 1
            continue
        if char in ('"', "'"):
            context['quote'] = char
            i += 1
            continue
        if char == '\\':
            i += 2
            continue
        if context['kind'] in ('command', 'arithmetic') and char in '()':
            context['depth'] += 1 if char == '(' else -1
            if context['depth'] == 0:
                contexts.pop()
            i += 1
            continue
        if (context['kind'] != 'arithmetic' and
                instruction.startswith('<<', i) and
                not instruction.startswith('<<<', i) and
                (i == 0 or instruction[i - 1] != '<')):
            j = i + 2
            tabs = False
            if j < len(instruction) and instruction[j] == '-':
                tabs = True
                j += 1
            delimiter_quote = instruction[j] if j < len(instruction) and instruction[j] in ('"', "'") else None
            if delimiter_quote:
                j += 1
            delimiter = HEREDOC_DELIMITER.match(instruction, j)
            if delimiter and (not delimiter_quote or
                              delimiter.end() < len(instruction) and
                              instruction[delimiter.end()] == delimiter_quote):
                markers.append((tabs, delimiter.group(0)))
                i = delimiter.end() + (1 if delimiter_quote else 0)
                continue
        i += 1
    return markers


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
        # Docker removes the escape and newline without inserting a separator;
        # the leading whitespace of a continued line is preserved verbatim.
        instruction = ''.join(parts).strip()
        yield instruction
        for tabs, delimiter in _heredoc_markers(instruction):
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
    Search both raw heredoc bodies and normalized instructions so a continued
    RUN command cannot hide an upgrade.
    """
    text = Path(path).read_text()
    body = _strip_comments(text)
    instructions = list(_logical_instructions(text))
    allowed = _exceptions(text)
    problems = []
    has_upgrade = UPGRADE.search(body) or any(UPGRADE.search(i) for i in instructions)
    if has_upgrade and 'upgrade' not in allowed:
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


EXCEPTION_FIELDS = ('image', 'cve', 'justification', 'owner', 'expires', 'evidence')
EXCEPTION_CVE = re.compile(r'(?:CVE-\d{4}-\d{4,}|GHSA(?:-[a-z0-9]{4}){3})', re.I)
EXCEPTION_MAX_DAYS = 90


def _exception_entries(path):
    try:
        doc = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get('exceptions'), list):
        return None
    return doc['exceptions']


def check_exceptions(path, today=None, max_days=EXCEPTION_MAX_DAYS):
    """Validate the governed exception registry; return problem codes."""
    if not Path(path).is_file():
        return []
    entries = _exception_entries(path)
    if entries is None:
        return ['exception-registry-invalid']
    today = today or datetime.date.today()
    problems, seen = [], set()
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append('exception-not-object')
            continue
        cve = entry.get('cve') if isinstance(entry.get('cve'), str) else '?'
        missing = [f for f in EXCEPTION_FIELDS
                   if not isinstance(entry.get(f), str) or not entry[f].strip()]
        if missing:
            problems.append('exception-missing-field:' + cve + ':' + ','.join(missing))
            continue
        if not EXCEPTION_CVE.fullmatch(cve):
            problems.append('exception-cve-format:' + cve)
        key = (entry['image'], cve.upper())
        if key in seen:
            problems.append('exception-duplicate:' + cve)
        seen.add(key)
        try:
            expires = datetime.date.fromisoformat(entry['expires'])
        except ValueError:
            problems.append('exception-invalid-date:' + cve)
            continue
        if expires <= today:
            problems.append('exception-expired:' + cve)
        elif (expires - today).days > max_days:
            problems.append('exception-too-long:' + cve)
    return problems


def unregistered_vex_statements(vex_path, registry_path):
    """VEX statements with no matching governed exception."""
    if not Path(registry_path).is_file():
        return []
    entries = _exception_entries(registry_path) or []
    registered = {(e.get('image', '').upper(), e.get('cve', '').upper())
                  for e in entries if isinstance(e, dict)}
    image = Path(vex_path).name.replace('.openvex.json', '').upper()
    doc = json.loads(Path(vex_path).read_text())
    out = []
    for statement in doc.get('statements', []):
        vulnerability = statement.get('vulnerability') if isinstance(statement, dict) else None
        name = vulnerability.get('name') if isinstance(vulnerability, dict) else None
        if isinstance(name, str) and (image, name.upper()) not in registered:
            out.append(name)
    return sorted(set(out))
