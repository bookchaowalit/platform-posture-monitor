---
title: "SPEC-001 Security posture monitor"
status: accepted
created: 2026-11-03
updated: 2026-11-03
description: Scheduled read-only check of the bookchaowalit.com edge (DNS, TLS, Access, zone settings, Workers) that alerts only on changes.
---

# SPEC-001 Security posture monitor

## Problem

The network review of 2026-11-02 (architecture-docs `systems/architecture/network-architecture.md`,
findings NET-01…NET-12) was done by hand. Nine hostnames had served expired certificates
for months (NET-02) and three tunnel hostnames had no Cloudflare Access (NET-01); nothing
noticed. A manual review is a snapshot: the next stale record or unprotected host appears
silently again.

Owner decision 2026-11-03: build the monitor as a running system, not another document.

## Outcome

Every 6 hours a job rebuilds the edge inventory from the live providers, evaluates fixed
rules, compares the result with the previous run and sends a Telegram message only when a
finding opens or resolves. A missed run alerts through the uptime Worker heartbeat.

## Scope (v1)

| Rule | Severity | Fires when |
|---|---|---|
| `tunnel-no-access` | high | a DNS record points to `*.cfargotunnel.com` and no Cloudflare Access app covers the hostname |
| `dangling-target` | high | a CNAME target is NXDOMAIN (subdomain takeover risk); a resolver error fails the run, and an unreachable web host keeps its previous probe findings |
| `tls-invalid` | medium | the HTTPS certificate fails verification (expired, wrong name, untrusted) |
| `tls-expiring` | medium | the certificate is valid but expires in fewer than 21 days (providers renew at 30, so renewal is failing) |
| `deployment-missing` | medium | Vercel answers `DEPLOYMENT_NOT_FOUND`, or Railway answers "Application not found" |
| `deployment-paused` | low | Vercel answers `DEPLOYMENT_PAUSED` |
| `zone-ssl` | high | SSL mode is not `strict` |
| `zone-min-tls` | medium | minimum TLS version is below 1.2 |
| `zone-https` | medium | Always Use HTTPS is off |
| `zone-hsts` | low | zone HSTS is off |
| `zone-dnssec` | low | DNSSEC is not active |
| `zone-caa` | low | the apex has no CAA record |
| `workers-dev` | low | a Worker script has its `workers.dev` route enabled |

Out of scope for v1: Neon IP allowlists (the only Neon credential is account-wide with
write rights, too broad for a public-repo job; NET-05 is an owner decision), response
security headers (NET-07, provider-wide) and Railway/Vercel project settings.

**Audit trail (added 2026-11-03).** Each opened or resolved finding is appended to
`security-api` `POST /v1/audit` (`action=posture.opened|posture.resolved`,
`target=<rule>.<subject>` or `<rule>.h<hash>` when the subject does not fit the identifier
rule). The monitor is platform-identity service client `posture-monitor`
(`client_credentials` + `private_key_jwt`, audience `security-api`, scope `audit:write`,
system workspace). Events are written before the Telegram message and before state, with an
`Idempotency-Key` derived from the change, the finding id and the previous state, so a
retried run never duplicates an event. An audit failure exits 2 and keeps the old state.

## Requirements

- **R1 Read-only.** The job never changes provider state. Its Cloudflare token holds only
  read permissions plus object write on one R2 bucket (`posture-monitor`) for its state.
- **R2 Public log stays quiet.** The repository is public, so the job log and step
  summary print only counts per severity and the exit status — never hostnames, rule
  hits or provider errors. Details go only to Telegram.
- **R3 Alert on change.** A finding has a stable id `<rule>:<subject>`. The message lists
  opened findings (highest severity first) and resolved findings. No message when nothing
  changed. The first run (no state) sends one baseline message.
- **R4 Fail loudly.** If any provider call fails, the run exits non-zero, keeps the old
  state (a partial inventory must not "resolve" findings) and the heartbeat reports
  `ok: false`. A missed run alerts after 13 hours (uptime Worker `posture-monitor`).
- **R5 Bounded.** Each HTTPS probe has a 10 s timeout; probes run in parallel (8 workers);
  a run finishes within 5 minutes for ~150 hostnames.
- **R6 No third-party runtime dependencies.** Standard library only, so the job has no
  supply-chain surface beyond Python itself.

## Acceptance criteria

- AC1 Given a tunnel CNAME without an Access app, a `tunnel-no-access` high finding is produced;
  with an Access app for the exact host (or a matching `*.` wildcard app) none is.
- AC2 Given probe results, certificate failures, expiry under 21 days and the Vercel/Railway
  error markers map to the rules above; a healthy 2xx/3xx with a valid certificate maps to none.
- AC3 Zone settings outside the expected values each produce their rule; expected values produce none.
- AC4 Diffing previous and current findings yields exactly the opened and resolved sets; an
  unchanged set yields no message.
- AC5 A provider error leaves the state file untouched and exits with code 2.
- AC6 The public summary contains no hostname.

## Later

- Neon allowlist rule with a read-only credential.
- Registry drift: hostnames in DNS with no system in `online-systems.yaml`.
