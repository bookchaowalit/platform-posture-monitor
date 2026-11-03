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

    def test_notify_failure_keeps_state(self):
        def refuse(text):
            raise OSError('telegram down')
        self.state_in.write_text(dump_state([A]))
        self.assertEqual(self.go(lambda: ([A, B], set()), send=refuse), NOTIFY_FAILED)
        self.assertFalse(self.state_out.exists())

    def test_unreachable_host_keeps_its_probe_finding(self):
        tls = Finding('tls-invalid', 'medium', 'old.example.com')
        self.state_in.write_text(dump_state([A, tls]))
        self.assertEqual(self.go(lambda: ([A], {'old.example.com'})), OK)
        self.assertEqual(self.sent, [])  # nothing resolved
        self.assertIn(tls.id, self.state_out.read_text())

    def test_public_output_has_no_hostname(self):  # AC6
        self.go(lambda: ([A, B], set()))
        self.assertNotIn('example.com', self.out.getvalue())


if __name__ == '__main__':
    unittest.main()
