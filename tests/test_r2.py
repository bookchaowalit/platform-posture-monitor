import unittest
from datetime import UTC, datetime

from posture_monitor.r2 import signed_request

NOW = datetime(2026, 11, 3, 1, 2, 3, tzinfo=UTC)


class Signing(unittest.TestCase):
    def req(self, method='GET', body=b''):
        return signed_request(method, 'https://acct.r2.cloudflarestorage.com', 'posture-monitor', 'state.json',
                              'AKID', 'SECRET', body=body, now=NOW)

    def test_url_and_scope(self):
        r = self.req()
        self.assertEqual(r.full_url, 'https://acct.r2.cloudflarestorage.com/posture-monitor/state.json')
        auth = r.get_header('Authorization')
        self.assertIn('Credential=AKID/20261103/auto/s3/aws4_request', auth)
        self.assertIn('SignedHeaders=host;x-amz-content-sha256;x-amz-date', auth)
        self.assertNotIn('SECRET', auth)

    def test_deterministic_and_body_bound(self):
        self.assertEqual(self.req().get_header('Authorization'), self.req().get_header('Authorization'))
        self.assertNotEqual(self.req('PUT', b'a').get_header('Authorization'),
                            self.req('PUT', b'b').get_header('Authorization'))
        self.assertIsNone(self.req().data)
        self.assertEqual(self.req('PUT', b'a').data, b'a')


if __name__ == '__main__':
    unittest.main()
