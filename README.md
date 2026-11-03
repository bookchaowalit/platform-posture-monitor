---
title: "Security posture monitor"
tags: [security, network, monitoring, infra]
created: 2026-11-03
updated: 2026-11-03
description: "Scheduled read-only check of the bookchaowalit.com edge that alerts on Telegram only when a finding opens or resolves."
---

# Security posture monitor

Every 6 hours a GitHub Actions job rebuilds the edge inventory of `bookchaowalit.com` from the
live providers, evaluates fixed rules, compares the result with the previous run and sends a
Telegram message only when a finding opens or resolves. It turns the manual network review of
2026-11-02 (architecture-docs `systems/architecture/network-architecture.md`, NET-01…NET-12)
into a running system. Requirements and acceptance criteria:
[SPEC-001](docs/specs/001-posture-monitor.md).

## What it checks

| Rule | Severity | Fires when |
|---|---|---|
| `tunnel-no-access` | high | a record points to `*.cfargotunnel.com` and no Cloudflare Access app covers it |
| `dangling-target` | high | a CNAME target is NXDOMAIN (subdomain takeover risk) |
| `tls-invalid` / `tls-expiring` | medium | the certificate fails verification, or expires in under 21 days |
| `deployment-missing` | medium | Vercel `DEPLOYMENT_NOT_FOUND` or Railway "Application not found" |
| `deployment-paused` | low | Vercel `DEPLOYMENT_PAUSED` |
| `zone-ssl`, `zone-min-tls`, `zone-https` | high / medium | SSL not `strict`, TLS below 1.2, Always Use HTTPS off |
| `zone-hsts`, `zone-dnssec`, `zone-caa` | low | zone HSTS off, DNSSEC not active, no CAA at the apex |
| `workers-dev` | low | a Worker script has `workers.dev` enabled |

HTTPS probes go to proxied records and CNAMEs that point to web hosts (Vercel, Railway, the
tunnel, Workers, Pages). Mail and DKIM records only get the NXDOMAIN check. An unreachable host
is not a posture finding; the uptime Worker covers availability.

## How it runs

- `.github/workflows/posture.yml`, cron `23 */6 * * *` and manual dispatch, GitHub-hosted
  runner (public repository). The log prints only counts per severity.
- State: `state.json` in the private R2 bucket `posture-monitor`. It is replaced only after a
  complete inventory and a delivered alert, so a provider outage never "resolves" findings and
  an undelivered alert is retried next run.
- Exit codes: `0` ok, `2` provider or R2 failure, `3` Telegram failure. Anything but `0` sends
  `ok: false` to the uptime Worker heartbeat `posture-monitor`; no report for 13 hours alerts too.
- Standard library only: no third-party runtime dependency.

## Credentials

All in Infisical `/posture-monitor` and mirrored to this repository's Actions secrets.

| Secret | What |
|---|---|
| `CLOUDFLARE_API_TOKEN` | account token `posture-monitor (…)`: Zone, DNS and Zone Settings Read on the zone; Access Apps and Workers Scripts Read on the account; R2 object read/write on bucket `posture-monitor` only |
| `CLOUDFLARE_ACCOUNT_ID` | account id |
| `POSTURE_R2_ACCESS_KEY_ID`, `POSTURE_R2_SECRET_ACCESS_KEY`, `POSTURE_R2_ENDPOINT` | S3 credentials derived from the same token (id, SHA-256 of the value) |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | infra bot (Infisical `/telegram`) |
| `HEARTBEAT_TOKEN` | uptime Worker heartbeat (Infisical `/monitoring`) |

Rotation: create a new token with the same policies, update Infisical and the Actions
secrets, run the workflow once, then delete the old token.

## Local run

```bash
python3 -m unittest discover -s tests
infisical run --path /posture-monitor -- python3 -m posture_monitor \
  --state-in /tmp/none.json --state-out /tmp/state.json --no-notify
```

`--no-notify` prints the alert to stderr instead of sending it.

## Not covered yet

Neon IP allowlists, response security headers and writing findings to `security-api`; see
"Later" in SPEC-001.
