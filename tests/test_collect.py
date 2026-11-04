import io
import json
import unittest
from unittest import mock

from posture_monitor.collect import (
    Cloudflare,
    ProviderError,
    dangling_cnames,
    enforcing_domains,
    target_exists,
    web_hosts,
)


def rec(name, content, rtype='CNAME', proxied=False):
    return {'type': rtype, 'name': name, 'content': content, 'proxied': proxied}


class Selection(unittest.TestCase):
    def test_web_hosts_skip_mail_and_wildcards(self):
        records = [rec('app.x.com', 'cname.vercel-dns.com'), rec('send.x.com', 'send.forge.rmta.net'),
                   rec('_dc.x.com', 'a.vercel-dns.com'), rec('*.x.com', 'cname.vercel-dns.com'),
                   rec('x.com', '1.2.3.4', 'A', True), rec('mail.x.com', '5.6.7.8', 'A'),
                   rec('vault.x.com', 'id.cfargotunnel.com', proxied=True)]
        self.assertEqual(web_hosts(records), ['app.x.com', 'vault.x.com', 'x.com'])

    def test_dangling_checks_every_cname_target(self):
        records = [rec('a.x.com', 'gone.up.railway.app'), rec('b.x.com', 'ok.vercel-dns.com', proxied=True),
                   rec('*.x.com', 'gone.vercel-dns.com'), rec('x.com', '1.2.3.4', 'A')]
        gone = {'gone.up.railway.app', 'gone.vercel-dns.com'}
        self.assertEqual(dangling_cnames(records, exists=lambda t: t not in gone), ['*.x.com', 'a.x.com'])


class AccessApps(unittest.TestCase):
    OWNER = {'decision': 'allow', 'include': [{'email': {'email': 'owner@example.com'}}]}

    def app(self, policies, type_='self_hosted', **kw):
        return {'type': type_, 'domain': 'vault.x.com', 'policies': policies, **kw}

    def test_owner_only_app_enforces(self):
        self.assertEqual(enforcing_domains([self.app([self.OWNER])]), ['vault.x.com'])

    def test_self_hosted_domains_count(self):
        app = self.app([self.OWNER], self_hosted_domains=['vault.x.com', 'home.x.com'])
        self.assertEqual(enforcing_domains([app]), ['home.x.com', 'vault.x.com'])

    def test_open_apps_do_not_count(self):
        everyone = {'decision': 'allow', 'include': [{'everyone': {}}]}
        bypass = {'decision': 'bypass', 'include': [{'everyone': {}}]}
        self.assertEqual(enforcing_domains([self.app([everyone])]), [])
        self.assertEqual(enforcing_domains([self.app([self.OWNER, bypass])]), [])
        self.assertEqual(enforcing_domains([self.app([])]), [])
        self.assertEqual(enforcing_domains([self.app([self.OWNER], type_='warp')]), [])

    def test_everyone_narrowed_by_require_enforces(self):
        narrowed = {'decision': 'allow', 'include': [{'everyone': {}}],
                    'require': [{'email': {'email': 'owner@example.com'}}]}
        self.assertEqual(enforcing_domains([self.app([narrowed])]), ['vault.x.com'])
        still_open = {'decision': 'allow', 'include': [{'everyone': {}}], 'require': [{'everyone': {}}]}
        self.assertEqual(enforcing_domains([self.app([still_open])]), [])

    def test_service_auth_enforces(self):
        service = {'decision': 'non_identity', 'include': [{'service_token': {'token_id': 't1'}}]}
        any_token = {'decision': 'non_identity', 'include': [{'any_valid_service_token': {}}]}
        self.assertEqual(enforcing_domains([self.app([service])]), ['vault.x.com'])
        self.assertEqual(enforcing_domains([self.app([any_token])]), ['vault.x.com'])
        open_service = {'decision': 'non_identity', 'include': [{'everyone': {}}]}
        self.assertEqual(enforcing_domains([self.app([self.OWNER, open_service])]), [])


class Doh(unittest.TestCase):
    def status(self, code):
        body = FakeResp(json.dumps({'Status': code}).encode())
        with mock.patch('urllib.request.urlopen', return_value=body):
            return target_exists('t.example.com')

    def test_noerror_exists_nxdomain_does_not(self):
        self.assertTrue(self.status(0))
        self.assertFalse(self.status(3))

    def test_other_status_fails_the_run(self):
        with self.assertRaises(ProviderError):
            self.status(2)  # SERVFAIL


class FakeResp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): self.close()


class Api(unittest.TestCase):  # AC5 at the provider edge
    def test_failure_raises_without_details(self):
        def boom(req, timeout):
            raise OSError('connection to secret-host refused')
        with self.assertRaises(ProviderError) as ctx:
            Cloudflare('t', 'acct', 'x.com', opener=boom).get('/zones?name=x.com')
        self.assertNotIn('secret-host', str(ctx.exception))

    def test_unsuccessful_body_raises(self):
        opener = lambda req, timeout: FakeResp(json.dumps({'success': False}).encode())  # noqa: E731
        with self.assertRaises(ProviderError):
            Cloudflare('t', 'acct', 'x.com', opener=opener).get('/zones')

    def test_paging_follows_total_pages(self):
        pages = {1: [1, 2], 2: [3]}
        def opener(req, timeout):
            page = int(req.full_url.rsplit('page=', 1)[1])
            return FakeResp(json.dumps({'success': True, 'result': pages[page],
                                        'result_info': {'total_pages': 2}}).encode())
        self.assertEqual(Cloudflare('t', 'acct', 'x.com', opener=opener).paged('/r'), [1, 2, 3])


if __name__ == '__main__':
    unittest.main()
