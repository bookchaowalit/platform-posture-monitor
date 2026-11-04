"""Live inventory: Cloudflare API reads and one HTTPS GET per web hostname (SPEC-001 R1, R5)."""
import http.client
import json
import socket
import ssl
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from .checks import Probe, ZoneSettings

API = 'https://api.cloudflare.com/client/v4'
DOH = 'https://cloudflare-dns.com/dns-query'
NOERROR, NXDOMAIN = 0, 3
WEB_TARGETS = ('.vercel-dns.com', '.vercel-dns-017.com', '.up.railway.app', '.cfargotunnel.com',
               '.workers.dev', '.pages.dev')
TIMEOUT = 10
WORKERS = 8


class ProviderError(Exception):
    """A provider call failed; the run must not replace state (SPEC-001 R4)."""


class Cloudflare:
    def __init__(self, token, account_id, zone_name, opener=urllib.request.urlopen):
        self.token, self.account, self.zone_name, self.open = token, account_id, zone_name, opener

    def get(self, path):
        req = urllib.request.Request(API + path, headers={'Authorization': f'Bearer {self.token}'})
        try:
            with self.open(req, timeout=30) as resp:
                body = json.load(resp)
        except Exception as exc:  # noqa: BLE001  only the path and type leave this function
            raise ProviderError(f'{path.split("?")[0]}: {type(exc).__name__}') from None
        if not body.get('success'):
            raise ProviderError(f'{path.split("?")[0]}: unsuccessful')
        return body

    def paged(self, path):
        page, out = 1, []
        while True:
            sep = '&' if '?' in path else '?'
            body = self.get(f'{path}{sep}per_page=100&page={page}')
            out += body['result']
            info = body.get('result_info') or {}
            if page >= info.get('total_pages', 1):
                return out
            page += 1

    def inventory(self):
        zone = self.get(f'/zones?name={self.zone_name}')['result']
        if len(zone) != 1:
            raise ProviderError('/zones: zone not found')
        zid = zone[0]['id']
        records = [{k: r[k] for k in ('type', 'name', 'content', 'proxied')}
                   for r in self.paged(f'/zones/{zid}/dns_records')]
        setting = lambda name: self.get(f'/zones/{zid}/settings/{name}')['result']['value']  # noqa: E731
        hsts = setting('security_header').get('strict_transport_security', {})
        zone_settings = ZoneSettings(
            ssl=setting('ssl'), min_tls_version=setting('min_tls_version'),
            always_use_https=setting('always_use_https'), hsts_enabled=bool(hsts.get('enabled')),
            dnssec_status=self.get(f'/zones/{zid}/dnssec')['result']['status'],
            has_caa=any(r['type'] == 'CAA' and r['name'] == self.zone_name for r in records))
        access = enforcing_domains(self.paged(f'/accounts/{self.account}/access/apps'))
        workers_dev = []
        for script in self.get(f'/accounts/{self.account}/workers/scripts')['result']:
            sub = self.get(f'/accounts/{self.account}/workers/scripts/{script["id"]}/subdomain')['result']
            if sub.get('enabled'):
                workers_dev.append(script['id'])
        return records, access, zone_settings, sorted(workers_dev)


def _everyone(policy):
    return any('everyone' in rule for rule in policy.get('include', []))


def _limits(policy):
    """Does this policy let only some callers in? include narrows it, and so does a require rule."""
    if not policy.get('include'):
        return False
    if not _everyone(policy):
        return True
    return any('everyone' not in rule for rule in policy.get('require', []))


def _open_to_all(policy):
    return _everyone(policy) and not policy.get('require')


def enforcing_domains(apps):
    """Domains of self-hosted Access apps that actually require a login.

    An app counts only if it has an allow (login) or non_identity (Service Auth) rule limited to
    someone - by include, or by a require rule when include is `everyone` - and no bypass or
    non_identity rule that lets everyone through; anything else would hide an open host behind an app.
    """
    domains = []
    for app in apps:
        if app.get('type') != 'self_hosted':
            continue
        policies = app.get('policies', [])
        if any(p.get('decision') in ('bypass', 'non_identity') and _open_to_all(p) for p in policies):
            continue
        # allow = a login; non_identity = Service Auth (a service token or mTLS credential)
        if not any(p.get('decision') in ('allow', 'non_identity') and _limits(p) for p in policies):
            continue
        domains += [d for d in {app.get('domain'), *app.get('self_hosted_domains', [])} if d]
    return sorted(domains)


def web_hosts(records):
    """Hostnames worth an HTTPS probe: proxied records and CNAMEs to known web hosts."""
    hosts = set()
    for r in records:
        name = r['name']
        if name.startswith(('_', '*')) or r['type'] not in ('A', 'AAAA', 'CNAME'):
            continue
        if r['proxied'] or (r['type'] == 'CNAME' and r['content'].endswith(WEB_TARGETS)):
            hosts.add(name)
    return sorted(hosts)


def target_exists(name):
    """False only for NXDOMAIN. A target with just TXT/MX records (mail, DKIM) still exists."""
    url = f'{DOH}?{urllib.parse.urlencode({"name": name, "type": "A"})}'
    req = urllib.request.Request(url, headers={'accept': 'application/dns-json'})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            status = json.load(resp)['Status']
    except Exception as exc:  # noqa: BLE001
        raise ProviderError(f'dns-query: {type(exc).__name__}') from None
    if status not in (NOERROR, NXDOMAIN):
        # SERVFAIL, REFUSED…: no verdict, so the run must fail rather than call the target healthy.
        raise ProviderError(f'dns-query: status {status}')
    return status == NOERROR


def dangling_cnames(records, exists=target_exists):
    """CNAME names whose target is NXDOMAIN (proxied ones included: Cloudflare hides the target)."""
    cnames = [r for r in records if r['type'] == 'CNAME']  # wildcards too: the target is what can dangle
    with ThreadPoolExecutor(WORKERS) as pool:
        alive = list(pool.map(lambda r: exists(r['content']), cnames))
    return sorted(r['name'] for r, ok in zip(cnames, alive, strict=True) if not ok)


def probe(host):
    unreachable = Probe(False, None, None, None, None, False)
    try:
        socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        # Could be a transient resolver failure; NXDOMAIN targets are caught by dangling_cnames.
        return unreachable
    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(host, timeout=TIMEOUT, context=ctx)
    try:
        conn.request('GET', '/', headers={'User-Agent': 'posture-monitor/1'})
        cert = conn.sock.getpeercert()
        resp = conn.getresponse()
        body = resp.read(4096).decode('utf-8', 'replace')
    except ssl.SSLCertVerificationError as exc:
        return Probe(True, exc.verify_message or 'verify-failed', None, None, None, False)
    except (OSError, http.client.HTTPException) as exc:
        # Unreachable is availability (uptime monitor), not posture: no TLS verdict, no finding.
        return unreachable if not isinstance(exc, ssl.SSLError) \
            else Probe(True, type(exc).__name__, None, None, None, False)
    finally:
        conn.close()
    not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert['notAfter']), UTC) if cert else None
    railway = 'railway' in (resp.getheader('server') or '') and 'Application not found' in body
    return Probe(True, None, not_after, resp.status, resp.getheader('x-vercel-error'), railway)


def probe_all(hosts, prober=probe):
    with ThreadPoolExecutor(WORKERS) as pool:
        return dict(zip(hosts, pool.map(prober, hosts), strict=True))
