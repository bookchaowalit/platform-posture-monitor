import base64
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from posture_monitor.audit import AuditSink, assertion, event_target, idempotency_key
from posture_monitor.checks import Finding

A = Finding('tunnel-no-access', 'high', 'vault.example.com')


def b64json(part):
    return json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))


class Assertion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        d = Path(tempfile.mkdtemp())
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048',
                        '-out', d / 'k.pem'], check=True, capture_output=True)
        subprocess.run(['openssl', 'pkey', '-in', d / 'k.pem', '-pubout', '-out', d / 'pub.pem'],
                       check=True, capture_output=True)
        cls.key, cls.pub = (d / 'k.pem').read_text(), d / 'pub.pem'

    def test_claims_follow_identity_rules(self):
        jwt = assertion('posture-monitor', 'https://id.example/v1/token', self.key, now=1000)
        header, claims, _ = jwt.split('.')
        self.assertEqual(b64json(header)['alg'], 'RS256')
        c = b64json(claims)
        self.assertEqual((c['iss'], c['sub'], c['aud']), ('posture-monitor', 'posture-monitor',
                                                          'https://id.example/v1/token'))
        self.assertLessEqual(c['exp'] - c['iat'], 300)
        self.assertTrue(c['jti'])

    def test_signature_verifies_with_public_key(self):
        jwt = assertion('posture-monitor', 'https://id.example/v1/token', self.key, now=1000)
        signing_input, sig = jwt.rsplit('.', 1)
        d = Path(tempfile.mkdtemp())
        (d / 'sig').write_bytes(base64.urlsafe_b64decode(sig + '=' * (-len(sig) % 4)))
        r = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', self.pub, '-signature', d / 'sig'],
                           input=signing_input.encode(), capture_output=True)
        self.assertEqual(r.returncode, 0)


class Events(unittest.TestCase):
    def test_target_fits_the_64_character_column(self):
        self.assertEqual(event_target(A.id), 'tunnel-no-access.vault.example.com')
        self.assertEqual(event_target('dangling-target:*.example.com'), 'dangling-target.wildcard.example.com')
        long = Finding('tls-invalid', 'medium', 'x' * 80 + '.example.com')
        t = event_target(long.id)
        self.assertRegex(t, r'^[a-z][a-z0-9_.-]{0,63}$')
        self.assertNotEqual(t, event_target(Finding('tls-invalid', 'medium', 'y' * 80 + '.example.com').id))

    def test_a_rebuilt_state_lineage_never_reuses_keys(self):
        self.assertNotEqual(idempotency_key('opened', A.id, 0, 'e1'), idempotency_key('opened', A.id, 0, 'e2'))
        self.assertNotEqual(idempotency_key('opened', A.id, 0, 'e1'), idempotency_key('opened', A.id, 0))
        self.assertEqual(idempotency_key('opened', A.id, 0, ''), idempotency_key('opened', A.id, 0))

    def test_idempotency_key_is_stable_for_a_retried_run(self):
        self.assertEqual(idempotency_key('opened', A.id, 3), idempotency_key('opened', A.id, 3))
        # the same finding reopening later (a later generation) is a new event, not a duplicate
        self.assertNotEqual(idempotency_key('opened', A.id, 3), idempotency_key('opened', A.id, 5))
        self.assertLessEqual(len(idempotency_key('opened', A.id, 0)), 128)

    def test_sink_posts_one_event_per_change(self):
        calls = []
        sink = AuditSink(token=lambda: 'T', post=lambda body, key, token: calls.append((body, key, token)))
        left = sink([{'change': 'opened', 'id': A.id, 'generation': 0},
                     {'change': 'resolved', 'id': 'zone-caa:zone', 'generation': 0}])
        self.assertEqual(left, [])
        self.assertEqual([c[0]['action'] for c in calls], ['posture.opened', 'posture.resolved'])
        self.assertEqual(calls[0][0]['target'], 'tunnel-no-access.vault.example.com')
        self.assertEqual(calls[0][2], 'T')


class Partial(unittest.TestCase):
    def test_returns_the_events_from_the_first_failure_on(self):
        from posture_monitor.collect import ProviderError

        calls = []

        def post(body, key, token):
            calls.append(body)
            if len(calls) == 2:
                raise ProviderError('/v1/audit: HTTPError')

        events = [{'change': 'opened', 'id': f'r:{i}', 'generation': 1} for i in range(3)]
        self.assertEqual(AuditSink(token=lambda: 'T', post=post)(events), events[1:])

    def test_token_failure_keeps_everything(self):
        from posture_monitor.collect import ProviderError

        def no_token():
            raise ProviderError('/v1/token: HTTPError')

        events = [{'change': 'opened', 'id': 'r:1', 'generation': 1}]
        self.assertEqual(AuditSink(token=no_token)(events), events)

    def test_signing_failure_keeps_everything(self):
        events = [{'change': 'opened', 'id': 'r:1', 'generation': 1}]
        for exc in (subprocess.CalledProcessError(1, ['openssl']), FileNotFoundError('openssl')):
            def no_sign(exc=exc):
                raise exc
            with self.subTest(type(exc).__name__):
                self.assertEqual(AuditSink(token=no_sign)(events), events)
        bad = AuditSink(token=lambda: __import__('posture_monitor.audit').audit.service_token('not a pem'))
        self.assertEqual(bad(events), events)  # real openssl rejects the key: kept, not raised


if __name__ == '__main__':
    unittest.main()
