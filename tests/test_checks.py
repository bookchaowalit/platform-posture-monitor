import unittest
from datetime import UTC, datetime, timedelta

from posture_monitor.checks import Probe, ZoneSettings, evaluate

NOW = datetime(2026, 11, 3, tzinfo=UTC)
GOOD_ZONE = ZoneSettings(ssl='strict', min_tls_version='1.2', always_use_https='on', hsts_enabled=True,
                         dnssec_status='active', has_caa=True)


def rec(name, content, rtype='CNAME', proxied=False):
    return {'type': rtype, 'name': name, 'content': content, 'proxied': proxied}


def healthy(**kw):
    base = dict(reachable=True, tls_error=None, cert_not_after=NOW + timedelta(days=60), status=200,
                vercel_error=None, railway_not_found=False)
    base.update(kw)
    return Probe(**base)


def ids(findings):
    return sorted(f.id for f in findings)


class TunnelAccess(unittest.TestCase):  # AC1
    def run_with(self, access):
        records = [rec('vault.example.com', 'abc.cfargotunnel.com', proxied=True)]
        return evaluate(records, access, GOOD_ZONE, [], {}, NOW)

    def test_missing_access_is_high(self):
        [f] = self.run_with([])
        self.assertEqual((f.id, f.severity), ('tunnel-no-access:vault.example.com', 'high'))

    def test_exact_app_covers(self):
        self.assertEqual(self.run_with(['vault.example.com']), [])

    def test_path_scoped_app_does_not_cover_host(self):
        self.assertEqual(len(self.run_with(['vault.example.com/admin'])), 1)

    def test_whole_host_paths_cover(self):
        self.assertEqual(self.run_with(['vault.example.com/']), [])
        self.assertEqual(self.run_with(['vault.example.com/*']), [])

    def test_wildcard_app_covers(self):
        self.assertEqual(self.run_with(['*.example.com']), [])

    def test_other_host_does_not_cover(self):
        self.assertEqual(len(self.run_with(['home.example.com'])), 1)


class ProbeRules(unittest.TestCase):  # AC2
    def run_probe(self, probe):
        records = [rec('app.example.com', 'cname.vercel-dns.com')]
        return evaluate(records, [], GOOD_ZONE, [], {'app.example.com': probe}, NOW)

    def test_healthy_has_no_findings(self):
        self.assertEqual(self.run_probe(healthy()), [])
        self.assertEqual(self.run_probe(healthy(status=308)), [])

    def test_unresolvable_target_is_dangling(self):
        self.assertEqual(self.run_probe(healthy(reachable=False, status=None)), [])  # no verdict, no finding

    def test_dangling_cname_from_resolver(self):
        found = evaluate([], [], GOOD_ZONE, [], {}, NOW, dangling=['old.example.com'])
        self.assertEqual(ids(found), ['dangling-target:old.example.com'])

    def test_certificate_failure(self):
        self.assertEqual(ids(self.run_probe(healthy(tls_error='CERTIFICATE_VERIFY_FAILED', status=None,
                                                    cert_not_after=None))), ['tls-invalid:app.example.com'])

    def test_certificate_expiring_soon(self):
        found = self.run_probe(healthy(cert_not_after=NOW + timedelta(days=20)))
        self.assertEqual(ids(found), ['tls-expiring:app.example.com'])
        self.assertEqual(self.run_probe(healthy(cert_not_after=NOW + timedelta(days=21))), [])

    def test_vercel_and_railway_markers(self):
        self.assertEqual(ids(self.run_probe(healthy(status=404, vercel_error='DEPLOYMENT_NOT_FOUND'))),
                         ['deployment-missing:app.example.com'])
        self.assertEqual(ids(self.run_probe(healthy(status=404, railway_not_found=True))),
                         ['deployment-missing:app.example.com'])
        [paused] = self.run_probe(healthy(status=503, vercel_error='DEPLOYMENT_PAUSED'))
        self.assertEqual((paused.rule, paused.severity), ('deployment-paused', 'low'))

    def test_tunnel_530_is_not_a_probe_finding(self):
        # A down tunnel is an availability matter for the uptime monitor, not posture.
        self.assertEqual(self.run_probe(healthy(status=530)), [])


class ZoneRules(unittest.TestCase):  # AC3
    def zone(self, **kw):
        values = GOOD_ZONE._asdict()
        values.update(kw)
        return ids(evaluate([], [], ZoneSettings(**values), [], {}, NOW))

    def test_expected_values_have_no_findings(self):
        self.assertEqual(self.zone(), [])

    def test_each_setting(self):
        self.assertEqual(self.zone(ssl='full'), ['zone-ssl:zone'])
        self.assertEqual(self.zone(min_tls_version='1.0'), ['zone-min-tls:zone'])
        self.assertEqual(self.zone(min_tls_version='1.3'), [])
        self.assertEqual(self.zone(always_use_https='off'), ['zone-https:zone'])
        self.assertEqual(self.zone(hsts_enabled=False), ['zone-hsts:zone'])
        self.assertEqual(self.zone(dnssec_status='disabled'), ['zone-dnssec:zone'])
        self.assertEqual(self.zone(has_caa=False), ['zone-caa:zone'])

    def test_workers_dev(self):
        found = evaluate([], [], GOOD_ZONE, ['monitor'], {}, NOW)
        self.assertEqual(ids(found), ['workers-dev:monitor'])


class Ordering(unittest.TestCase):
    def test_sorted_by_severity_then_id(self):
        records = [rec('b.example.com', 'x.cfargotunnel.com', proxied=True)]
        zone = ZoneSettings(**{**GOOD_ZONE._asdict(), 'has_caa': False})
        found = evaluate(records, [], zone, [], {}, NOW)
        self.assertEqual([f.severity for f in found], ['high', 'low'])


if __name__ == '__main__':
    unittest.main()
