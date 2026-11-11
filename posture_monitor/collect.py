"""Live inventory: Cloudflare API reads and one HTTPS GET per web hostname (SPEC-001 R1, R5)."""
import http.client
import json
import socket
import ssl
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

from .checks import Probe, R2Usage, ZoneSettings

API = 'https://api.cloudflare.com/client/v4'
DOH = 'https://cloudflare-dns.com/dns-query'
NOERROR, NXDOMAIN = 0, 3
WEB_TARGETS = ('.vercel-dns.com', '.vercel-dns-017.com', '.up.railway.app', '.cfargotunnel.com',
               '.workers.dev', '.pages.dev')
TIMEOUT = 10
# R2 pricing classes by GraphQL actionType. Anything not listed as Class B or free counts as
# Class A, so a new write action can only make the trigger fire early, never late.
R2_CLASS_B = frozenset({'HeadBucket', 'HeadObject', 'GetObject', 'UsageSummary', 'GetBucketEncryption',
                        'GetBucketLocation', 'GetBucketCors', 'GetBucketLifecycleConfiguration'})
R2_FREE = frozenset({'DeleteObject', 'DeleteObjects', 'DeleteBucket', 'AbortMultipartUpload'})
R2_QUERY = '''query($account: String!, $since: Time!, $until: Time!, $recent: Time!) {
  viewer { accounts(filter: {accountTag: $account}) {
    ops: r2OperationsAdaptiveGroups(limit: 10000, filter: {datetime_geq: $since, datetime_leq: $until}) {
      sum { requests } dimensions { actionType } }
    storage: r2StorageAdaptiveGroups(limit: 10000, filter: {datetime_geq: $recent, datetime_leq: $until},
                                     orderBy: [datetime_DESC]) {
      max { payloadSize metadataSize } dimensions { bucketName datetime } } } } }'''
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

    def r2_usage(self, now):
        """R2 use over the last 30 days for the ADR-0013 §7 triggers (Account Analytics Read)."""
        fmt = '%Y-%m-%dT%H:%M:%SZ'
        variables = {'account': self.account, 'since': (now - timedelta(days=30)).strftime(fmt),
                     'until': now.strftime(fmt), 'recent': (now - timedelta(days=2)).strftime(fmt)}
        req = urllib.request.Request(API + '/graphql', data=json.dumps({'query': R2_QUERY, 'variables': variables}).encode(),
                                     headers={'Authorization': f'Bearer {self.token}', 'Content-Type': 'application/json'})
        try:
            with self.open(req, timeout=30) as resp:
                body = json.load(resp)
            if body.get('errors'):
                raise ValueError('graphql errors')
            acc = body['data']['viewer']['accounts'][0]
        except Exception as exc:  # noqa: BLE001  only the path and type leave this function
            raise ProviderError(f'/graphql r2: {type(exc).__name__}') from None
        class_a = class_b = 0
        for row in acc['ops']:
            action, n = row['dimensions']['actionType'], row['sum']['requests']
            if action in R2_CLASS_B:
                class_b += n
            elif action not in R2_FREE:
                class_a += n
        newest = {}
        for row in acc['storage']:
            bucket, at = row['dimensions']['bucketName'], row['dimensions']['datetime']
            if bucket not in newest or at > newest[bucket][0]:
                newest[bucket] = (at, row['max']['payloadSize'] + row['max']['metadataSize'])
        return R2Usage(storage_bytes=sum(size for _, size in newest.values()), class_a=class_a, class_b=class_b)

    def full_policies(self, apps):
        """Apps whose policies are only references (reusable policies, no include) get the full list,
        so a protected app is never judged on a summary."""
        out = []
        for app in apps:
            if app.get('id') and any('include' not in p for p in app.get('policies', [])):
                app = {**app, 'policies': self.paged(f"/accounts/{self.account}/access/apps/{app['id']}/policies")}
            out.append(app)
        return out

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
        access = enforcing_domains(self.full_policies(self.paged(f'/accounts/{self.account}/access/apps')))
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


def _open(policy):
    """A rule that lets anyone through: the same test as _limits, so the two never disagree."""
    return bool(policy.get('include')) and not _limits(policy)


CREDENTIAL_RULES = {'service_token', 'any_valid_service_token', 'certificate', 'common_name'}


def _needs_credential(policy):
    """Service Auth counts only when a rule demands a credential; ip/geo/everyone alone do not."""
    # include rules are alternatives (OR): every one must demand a credential, else e.g. an ip
    # alternative lets callers in without one. A require rule (AND) demanding one is enough.
    def demands(rule):
        return any(key in CREDENTIAL_RULES for key in rule)
    include = policy.get('include', [])
    return (bool(include) and all(demands(r) for r in include)) or any(demands(r) for r in policy.get('require', []))


def enforcing_domains(apps):
    """Domains of self-hosted Access apps that actually require a login.

    An app counts only if it has an allow (login) rule limited to someone - by include, or by a
    require rule when include is `everyone` - or a non_identity (Service Auth) rule that demands a
    credential, and no allow, bypass or non_identity rule that lets everyone through; anything else
    would hide an open host behind an app.
    """
    domains = []
    for app in apps:
        if app.get('type') != 'self_hosted':
            continue
        policies = app.get('policies', [])
        # any rule open to everyone opens the app, whatever the other rules say
        if any(p.get('decision') in ('allow', 'bypass', 'non_identity') and _open(p) for p in policies):
            continue
        # allow = a login limited to someone; non_identity = Service Auth with a real credential
        if not any((p.get('decision') == 'allow' and _limits(p)) or
                   (p.get('decision') == 'non_identity' and _limits(p) and _needs_credential(p)) for p in policies):
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
