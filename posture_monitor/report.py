"""State diff, the Telegram message and the counts-only public summary (SPEC-001 R2, R3)."""
import json

from .checks import SEVERITY_ORDER

ICON = {'high': '🔴', 'medium': '🟠', 'low': '⚪'}
MAX_LINES = 40
MAX_CHARS = 4000  # Telegram rejects messages over 4096 characters


def load_state(text):
    """Previous findings by id, or None when there is no state yet (first run)."""
    if not text.strip():
        return None
    return {f['id']: f for f in json.loads(text)['findings']}


def load_meta(text):
    """(generation, pending_message) of a state; a missing or v1 state is generation 0, nothing pending."""
    if not text.strip():
        return 0, None
    data = json.loads(text)
    return int(data.get('generation', 0)), data.get('pending_message')


def dump_state(findings, generation=0, pending_message=None):
    data = {'version': 2, 'generation': generation, 'findings': [f.as_dict() for f in findings]}
    if pending_message:
        data['pending_message'] = pending_message
    return json.dumps(data, indent=1) + '\n'


def diff(previous, current):
    current_ids = {f.id for f in current}
    opened = [f for f in current if f.id not in previous]
    resolved = sorted((f for i, f in previous.items() if i not in current_ids),
                      key=lambda f: (SEVERITY_ORDER.get(f['severity'], 9), f['id']))
    return opened, resolved


def _counts(findings):
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] += 1
    return counts


def message(opened, resolved, current, first_run):
    if not first_run and not opened and not resolved:
        return None
    opened = sorted(opened, key=lambda f: (SEVERITY_ORDER[f.severity], f.id))
    c = _counts(current)
    head = 'Posture monitor baseline' if first_run else 'Posture monitor: changes'
    lines = [f'{head} (open: {c["high"]} high, {c["medium"]} medium, {c["low"]} low)']
    if opened:
        lines.append('' if first_run else '\nOpened:')
        lines += [f'{ICON[f.severity]} {f.rule} {f.subject}' for f in opened]
    if resolved:
        lines.append('\nResolved:')
        lines += [f'✅ {f["rule"]} {f["subject"]}' for f in resolved]
    if len(lines) > MAX_LINES:
        lines = lines[:MAX_LINES] + [f'… and {len(lines) - MAX_LINES} more']
    text = '\n'.join(lines)
    return text if len(text) <= MAX_CHARS else text[:MAX_CHARS - 12] + '\n… (cut)'


def public_summary(current, opened, resolved):
    return json.dumps({**_counts(current), 'opened': opened, 'resolved': resolved})
