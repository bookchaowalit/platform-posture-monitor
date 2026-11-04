"""One monitor run: collect, evaluate, diff, alert, then write state (SPEC-001 R3, R4)."""
import argparse
import json
import os
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from .audit import AuditSink, service_token
from .checks import PROBE_RULES, Finding, evaluate
from .collect import Cloudflare, ProviderError, dangling_cnames, probe_all, web_hosts
from .report import diff, dump_state, load_epoch, load_meta, load_state, message, public_summary

OK, PROVIDER_FAILED, NOTIFY_FAILED = 0, 2, 3


def live_findings(env):
    cf = Cloudflare(env['CLOUDFLARE_API_TOKEN'], env['CLOUDFLARE_ACCOUNT_ID'],
                    env.get('POSTURE_ZONE', 'bookchaowalit.com'))
    records, access, zone, workers_dev = cf.inventory()
    probes = probe_all(web_hosts(records))
    found = evaluate(records, access, zone, workers_dev, probes, datetime.now(UTC), dangling_cnames(records))
    return found, {host for host, p in probes.items() if not p.reachable}


def carry_forward(previous, current, unknown):
    """Keep probe findings for hosts with no verdict this run, so an outage never resolves them."""
    have = {f.id for f in current}
    kept = [Finding(f['rule'], f['severity'], f['subject']) for f in previous.values()
            if f['subject'] in unknown and f['rule'] in PROBE_RULES and f['id'] not in have]
    return current + kept


def telegram(env):
    def send(text):
        data = json.dumps({'chat_id': env['TELEGRAM_CHAT_ID'], 'text': text,
                           'disable_web_page_preview': True}).encode()
        req = urllib.request.Request(f'https://api.telegram.org/bot{env["TELEGRAM_BOT_TOKEN"]}/sendMessage',
                                     data=data, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=20) as resp:
            if not json.load(resp).get('ok'):
                raise OSError('telegram refused the message')
    return send


def run(state_in, state_out, findings_fn, send, out=sys.stdout, audit=None):
    """Returns the exit code.

    Only a failed inventory writes no state (nothing is known, so nothing may resolve). Otherwise the
    state is always written: audit events that could not be posted stay in `pending_audit` and
    alerts that could not be sent in `pending_messages`, both retried first next run. A non-zero
    exit still reports the failure through the heartbeat.
    """
    try:
        current, unknown = findings_fn()
    except ProviderError as exc:
        # Public log: the failing endpoint path and error type only, never a hostname.
        print(json.dumps({'status': 'provider_failed', 'error': str(exc)}), file=out)
        return PROVIDER_FAILED
    previous_text = state_in.read_text() if state_in.exists() else ''
    previous = load_state(previous_text)
    generation, pending_messages, pending_audit = load_meta(previous_text)
    epoch = load_epoch(previous_text)
    current = carry_forward(previous or {}, current, unknown)
    opened, resolved = diff(previous or {}, current)

    new = [('opened', f.id) for f in opened] + [('resolved', f['id']) for f in resolved]
    events = pending_audit + [{'change': c, 'id': i, 'generation': generation, **({'epoch': epoch} if epoch else {})}
                              for c, i in new]
    unposted = audit(events) if audit else []
    held = [] if audit else events  # no sink this run (local, --no-audit): keep them for a run that has one

    queue = list(pending_messages)
    text = message(opened, resolved, current, first_run=previous is None)
    if text:
        queue.append(text)
    unsent = []
    for n, item in enumerate(queue):
        try:
            send(item)
        except Exception:  # noqa: BLE001  kept in state, retried next run
            unsent = queue[n:]
            break

    state_out.write_text(dump_state(current, generation + 1, pending_messages=unsent, pending_audit=unposted or held,
                                     epoch=epoch))
    summary = json.loads(public_summary(current, len(opened), len(resolved)))
    if unposted:
        summary['status'], summary['audit_pending'] = 'audit_failed', len(unposted)
    elif held:
        summary['audit_pending'] = len(held)
    if unsent:
        summary['status'], summary['alerts_pending'] = summary.get('status', 'notify_failed'), len(unsent)
    print(json.dumps(summary), file=out)
    return PROVIDER_FAILED if unposted else NOTIFY_FAILED if unsent else OK


def main(argv=None):
    p = argparse.ArgumentParser(prog='posture_monitor')
    p.add_argument('--state-in', type=Path, required=True)
    p.add_argument('--state-out', type=Path, required=True)
    p.add_argument('--no-notify', action='store_true', help='print the alert to stderr instead of Telegram')
    p.add_argument('--require-audit', action='store_true',
                   help='fail (exit 2) when POSTURE_IDENTITY_PRIVATE_KEY_PEM is missing instead of skipping the audit')
    args = p.parse_args(argv)
    env = os.environ
    send = (lambda text: print(text, file=sys.stderr)) if args.no_notify else telegram(env)
    key = env.get('POSTURE_IDENTITY_PRIVATE_KEY_PEM')
    if args.require_audit and not key:
        print(json.dumps({'status': 'audit_failed', 'error': 'missing POSTURE_IDENTITY_PRIVATE_KEY_PEM'}))
        return PROVIDER_FAILED
    audit = AuditSink(lambda: service_token(key)) if key else None
    return run(args.state_in, args.state_out, lambda: live_findings(env), send, audit=audit)
