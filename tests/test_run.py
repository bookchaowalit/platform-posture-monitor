import io
import json
import tempfile
import unittest
from pathlib import Path

from posture_monitor.checks import Finding
from posture_monitor.collect import ProviderError
from posture_monitor.report import dump_state
from posture_monitor.run import NOTIFY_FAILED, OK, PROVIDER_FAILED, run

A = Finding('tunnel-no-access', 'high', 'vault.example.com')
B = Finding('zone-caa', 'low', 'zone')


class Run(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.state_in, self.state_out = self.dir / 'in.json', self.dir / 'out.json'
        self.sent, self.out = [], io.StringIO()

    def go(self, findings_fn, send=None):
        return run(self.state_in, self.state_out, findings_fn, send or self.sent.append, out=self.out)

    def test_provider_failure_keeps_state(self):  # AC5
        def fail():
            raise ProviderError('/zones: URLError')
        self.state_in.write_text(dump_state([A]))
        self.assertEqual(self.go(fail), PROVIDER_FAILED)
        self.assertFalse(self.state_out.exists())
        self.assertEqual(self.sent, [])

    def test_first_run_sends_baseline_and_writes_state(self):
        self.assertEqual(self.go(lambda: ([A, B], set())), OK)
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(len(json.loads(self.state_out.read_text())['findings']), 2)

    def test_unchanged_run_sends_nothing(self):
        self.state_in.write_text(dump_state([A, B]))
        self.assertEqual(self.go(lambda: ([A, B], set())), OK)
        self.assertEqual(self.sent, [])
        self.assertTrue(self.state_out.exists())

    def test_notify_failure_keeps_the_alert_for_the_next_run(self):
        def refuse(text):
            raise OSError('telegram down')
        self.state_in.write_text(dump_state([A], generation=4))
        self.assertEqual(self.go(lambda: ([A, B], set()), send=refuse), NOTIFY_FAILED)
        state = json.loads(self.state_out.read_text())
        self.assertEqual(state['generation'], 5)
        self.assertIn('zone-caa', state['pending_messages'][0])
        # next run: nothing new, the pending alert goes out on its own and is then cleared
        self.state_in.write_text(self.state_out.read_text())
        self.assertEqual(self.go(lambda: ([A, B], set())), OK)
        self.assertEqual(len(self.sent), 1)
        self.assertIn('zone-caa', self.sent[0])
        self.assertNotIn('pending_messages', json.loads(self.state_out.read_text()))

    def test_pending_alerts_stay_separate_bounded_messages(self):
        long = Finding('tls-invalid', 'medium', 'x' * 3900 + '.example.com')
        self.state_in.write_text(dump_state([A], pending_messages=['p' * 3990]))
        self.go(lambda: ([A, long], set()))
        self.assertEqual(len(self.sent), 2)  # pending first, then the new alert, never joined
        self.assertTrue(all(len(m) <= 4000 for m in self.sent))

    def test_pending_queue_is_capped(self):
        def refuse(text):
            raise OSError('telegram down')
        state = dump_state([A], pending_messages=[f'old {i}' for i in range(20)])
        self.state_in.write_text(state)
        self.go(lambda: ([A, B], set()), send=refuse)
        pending = json.loads(self.state_out.read_text())['pending_messages']
        self.assertEqual(len(pending), 5)
        self.assertIn('older undelivered alerts were dropped', pending[0])
        self.assertIn('zone-caa', pending[-1])

    def test_generation_advances_with_every_written_state(self):
        self.state_in.write_text(dump_state([A], generation=7))
        self.go(lambda: ([A], set()))
        self.assertEqual(json.loads(self.state_out.read_text())['generation'], 8)

    def test_unreachable_host_keeps_its_probe_finding(self):
        tls = Finding('tls-invalid', 'medium', 'old.example.com')
        self.state_in.write_text(dump_state([A, tls]))
        self.assertEqual(self.go(lambda: ([A], {'old.example.com'})), OK)
        self.assertEqual(self.sent, [])  # nothing resolved
        self.assertIn(tls.id, self.state_out.read_text())

    def test_failed_audit_events_are_kept_with_their_generation_and_retried_first(self):
        posted = []

        def flaky(events):
            posted.extend(events[:1])
            return events[1:]  # the second event failed

        tls = Finding('tls-invalid', 'medium', 'old.example.com')
        self.state_in.write_text(dump_state([A, tls], generation=3))
        code = run(self.state_in, self.state_out, lambda: ([A, B], set()), self.sent.append, out=self.out,
                   audit=flaky)
        self.assertEqual(code, PROVIDER_FAILED)
        state = json.loads(self.state_out.read_text())
        self.assertEqual(state['pending_audit'], [{'change': 'resolved', 'id': tls.id, 'generation': 3}])
        self.assertEqual(len(self.sent), 1)  # the alert still goes out
        # next run: the finding set is unchanged, but the unposted transition is posted first
        self.state_in.write_text(self.state_out.read_text())
        seen = []
        code = run(self.state_in, self.state_out, lambda: ([A, B], set()), self.sent.append, out=self.out,
                   audit=lambda events: seen.extend(events) or [])
        self.assertEqual(code, OK)
        self.assertEqual(seen, [{'change': 'resolved', 'id': tls.id, 'generation': 3}])
        self.assertNotIn('pending_audit', json.loads(self.state_out.read_text()))

    def test_audit_gets_the_changes_with_the_current_generation(self):
        seen = []
        self.state_in.write_text(dump_state([A], generation=2))
        run(self.state_in, self.state_out, lambda: ([A, B], set()), self.sent.append, out=self.out,
            audit=lambda events: seen.extend(events) or [])
        self.assertEqual(seen, [{'change': 'opened', 'id': B.id, 'generation': 2}])

    def test_public_output_has_no_hostname(self):  # AC6
        self.go(lambda: ([A, B], set()))
        self.assertNotIn('example.com', self.out.getvalue())


if __name__ == '__main__':
    unittest.main()


class RequireAudit(unittest.TestCase):
    def test_missing_audit_key_fails_before_any_provider_call(self):
        from unittest import mock

        from posture_monitor import run as run_module

        d = Path(tempfile.mkdtemp())
        with mock.patch.dict('os.environ', {}, clear=True), \
                mock.patch.object(run_module, 'live_findings', side_effect=AssertionError('must not run')):
            code = run_module.main(['--require-audit', '--no-notify', '--state-in', str(d / 'a'),
                                    '--state-out', str(d / 'b')])
        self.assertEqual(code, PROVIDER_FAILED)
        self.assertFalse((d / 'b').exists())
