"""Posture rules (SPEC-001): pure functions from a live inventory to findings."""
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import NamedTuple

SEVERITY_ORDER = {'high': 0, 'medium': 1, 'low': 2}
EXPIRY_WARNING = timedelta(days=21)  # providers renew at 30 days; under 21 means renewal is failing
TLS_VERSIONS = ('1.0', '1.1', '1.2', '1.3')
# ADR-0013 §7 cost triggers over a rolling 30 days; each one reopens the data-platform ADR.
R2_CLASS_B_LIMIT = 3_000_000       # 30 % of the 10 M free reads: write the compaction job
R2_CLASS_A_LIMIT = 300_000         # 30 % of the 1 M free writes: batch writes first
R2_STORAGE_LIMIT = 10 * 1000 ** 3  # past the 10 GB free allowance: run the IA cost comparison
PROBE_RULES = frozenset({'tls-invalid', 'tls-expiring', 'deployment-missing', 'deployment-paused'})


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    subject: str

    @property
    def id(self):
        return f'{self.rule}:{self.subject}'

    def as_dict(self):
        return {'id': self.id, 'rule': self.rule, 'severity': self.severity, 'subject': self.subject}


class ZoneSettings(NamedTuple):
    ssl: str
    min_tls_version: str
    always_use_https: str
    hsts_enabled: bool
    dnssec_status: str
    has_caa: bool


class Probe(NamedTuple):
    reachable: bool                # False: no verdict this run (DNS or network failure)
    tls_error: str | None          # certificate verification failure, if any
    cert_not_after: datetime | None
    status: int | None             # HTTP status of one GET without following redirects
    vercel_error: str | None       # value of the x-vercel-error header
    railway_not_found: bool        # Railway's "Application not found" fallback


class R2Usage(NamedTuple):
    storage_bytes: int  # newest payload + metadata size, summed over all buckets
    class_a: int        # Class A requests in the last 30 days
    class_b: int        # Class B requests in the last 30 days


def _r2_rules(u):
    if u.class_b > R2_CLASS_B_LIMIT:
        yield Finding('r2-class-b', 'low', 'account')
    if u.class_a > R2_CLASS_A_LIMIT:
        yield Finding('r2-class-a', 'low', 'account')
    if u.storage_bytes > R2_STORAGE_LIMIT:
        yield Finding('r2-storage', 'low', 'account')


def access_covers(host, access_domains):
    """True when an app protects the whole host: a path-scoped app (`host/admin`) leaves the rest open."""
    for domain in access_domains:
        app_host, _, path = domain.lower().partition('/')
        if path not in ('', '*'):
            continue
        if app_host == host or (app_host.startswith('*.') and host.endswith(app_host[1:])):
            return True
    return False


def _tunnel_rules(records, access_domains):
    for r in records:
        if r['type'] == 'CNAME' and r['content'].endswith('.cfargotunnel.com'):
            if not access_covers(r['name'].lower(), access_domains):
                yield Finding('tunnel-no-access', 'high', r['name'])


def _probe_rules(host, p, now):
    if not p.reachable:
        return
    if p.tls_error:
        yield Finding('tls-invalid', 'medium', host)
    elif p.cert_not_after and p.cert_not_after - now < EXPIRY_WARNING:
        yield Finding('tls-expiring', 'medium', host)
    if p.vercel_error == 'DEPLOYMENT_PAUSED':
        yield Finding('deployment-paused', 'low', host)
    elif p.vercel_error == 'DEPLOYMENT_NOT_FOUND' or p.railway_not_found:
        yield Finding('deployment-missing', 'medium', host)


def _zone_rules(z):
    if z.ssl != 'strict':
        yield Finding('zone-ssl', 'high', 'zone')
    if z.min_tls_version not in TLS_VERSIONS[2:]:
        yield Finding('zone-min-tls', 'medium', 'zone')
    if z.always_use_https != 'on':
        yield Finding('zone-https', 'medium', 'zone')
    if not z.hsts_enabled:
        yield Finding('zone-hsts', 'low', 'zone')
    if z.dnssec_status != 'active':
        yield Finding('zone-dnssec', 'low', 'zone')
    if not z.has_caa:
        yield Finding('zone-caa', 'low', 'zone')


def evaluate(records, access_domains, zone, workers_dev, probes, now, dangling=(), r2=None):
    """All findings for one inventory, highest severity first, then by id."""
    found = list(_tunnel_rules(records, access_domains))
    found.extend(Finding('dangling-target', 'high', name) for name in dangling)
    for host, probe in probes.items():
        found.extend(_probe_rules(host, probe, now))
    found.extend(_zone_rules(zone))
    found.extend(Finding('workers-dev', 'low', name) for name in workers_dev)
    if r2 is not None:
        found.extend(_r2_rules(r2))
    return sorted(set(found), key=lambda f: (SEVERITY_ORDER[f.severity], f.id))
