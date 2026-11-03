import io
import json
import unittest

from posture_monitor.collect import Cloudflare, ProviderError, dangling_cnames, web_hosts


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
                   rec('x.com', '1.2.3.4', 'A')]
        self.assertEqual(dangling_cnames(records, exists=lambda t: t != 'gone.up.railway.app'), ['a.x.com'])


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
