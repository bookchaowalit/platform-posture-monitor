import json
import unittest

from posture_monitor.checks import Finding
from posture_monitor.report import diff, dump_state, load_state, message, public_summary

A = Finding('tunnel-no-access', 'high', 'vault.example.com')
B = Finding('zone-caa', 'low', 'zone')
C = Finding('tls-invalid', 'medium', 'old.example.com')


class Diff(unittest.TestCase):  # AC4
    def test_opened_and_resolved(self):
        opened, resolved = diff({A.id: A.as_dict(), C.id: C.as_dict()}, [A, B])
        self.assertEqual([f.id for f in opened], [B.id])
        self.assertEqual([f['id'] for f in resolved], [C.id])

    def test_unchanged_has_no_message(self):
        opened, resolved = diff({A.id: A.as_dict()}, [A])
        self.assertEqual((opened, resolved), ([], []))
        self.assertIsNone(message(opened, resolved, [A], first_run=False))

    def test_message_lists_highest_first(self):
        text = message([B, A], [C.as_dict()], [A, B], first_run=False)
        self.assertLess(text.index('vault.example.com'), text.index('zone-caa'))
        self.assertIn('old.example.com', text)

    def test_message_stays_under_telegram_limit(self):
        long = [Finding('tls-invalid', 'medium', 'x' * 200 + f'{i}.example.com') for i in range(39)]
        self.assertLessEqual(len(message(long, [], long, first_run=True)), 4000)

    def test_first_run_sends_baseline(self):
        text = message([A, B], [], [A, B], first_run=True)
        self.assertIn('baseline', text.lower())

    def test_state_round_trip(self):
        self.assertEqual(load_state(dump_state([A, B])), {A.id: A.as_dict(), B.id: B.as_dict()})
        self.assertIsNone(load_state(''))


class PublicSummary(unittest.TestCase):  # AC6
    def test_counts_only(self):
        summary = public_summary([A, B, C], opened=1, resolved=0)
        self.assertEqual(json.loads(summary), {'high': 1, 'medium': 1, 'low': 1, 'opened': 1, 'resolved': 0})
        self.assertNotIn('example.com', summary)


if __name__ == '__main__':
    unittest.main()
