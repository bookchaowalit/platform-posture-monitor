"""State diff, the Telegram message and the counts-only public summary (SPEC-001 R2, R3)."""
import json
import secrets

from .checks import SEVERITY_ORDER

ICON = {'high': '🔴', 'medium': '🟠', 'low': '⚪'}
MAX_LINES = 40
MAX_CHARS = 4000  # Telegram rejects messages over 4096 characters


def load_state(text):
    """Previous findings by id, or None when there is no state yet (first run)."""
    if not text.strip():
        return None
    return {f['id']: f for f in json.loads(text)['findings']}


MAX_PENDING = 5  # unsent alerts kept for the next run; older ones collapse into a note
MAX_PENDING_AUDIT = 500  # audit events kept for the next run; the oldest go first


def load_meta(text):
    """(generation, pending_messages, pending_audit) of a state; missing or older states start empty."""
    if not text.strip():
        return 0, [], []
    data = json.loads(text)
    pending = data.get('pending_messages')
    if pending is None:  # version 2 kept one string
        pending = [data['pending_message']] if data.get('pending_message') else []
    return int(data.get('generation', 0)), [bound(m) for m in pending], list(data.get('pending_audit', []))


def load_epoch(text):
    """The state lineage id: a fresh random one for a new state, '' for one written before epochs.

    If the very first state write fails after its audit events were posted, the next run starts
    another lineage and posts them again: a duplicate, never a lost event (at-least-once on purpose).
    """
    if not text.strip():
        return secrets.token_hex(8)
    return str(json.loads(text).get('epoch', ''))


def bound(text):
    """One Telegram message: never over MAX_CHARS, so a long alert can never block the queue."""
    return text if len(text) <= MAX_CHARS else text[:MAX_CHARS - 12] + '\n… (cut)'


def cap_pending(messages):
    messages = [bound(m) for m in messages]
    if len(messages) <= MAX_PENDING:
        return messages
    dropped = len(messages) - (MAX_PENDING - 1)
    return [f'Posture monitor: {dropped} older undelivered alerts were dropped; see security-api audit.'] + \
        messages[-(MAX_PENDING - 1):]


def dump_state(findings, generation=0, pending_messages=(), pending_audit=(), epoch=''):
    data = {'version': 3, 'generation': generation, 'findings': [f.as_dict() for f in findings]}
    if epoch:
        data['epoch'] = epoch
    if pending_messages:
        data['pending_messages'] = cap_pending(list(pending_messages))
    if pending_audit:
        data['pending_audit'] = list(pending_audit)[-MAX_PENDING_AUDIT:]
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
    return bound('\n'.join(lines))


def public_summary(current, opened, resolved):
    return json.dumps({**_counts(current), 'opened': opened, 'resolved': resolved})
