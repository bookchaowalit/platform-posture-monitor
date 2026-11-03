# 10 — Sequences

## S1 — Scheduled run, happy path with a change

```mermaid
sequenceDiagram
  participant GH as GitHub schedule
  participant WF as posture.yml
  participant R2 as R2 posture-monitor
  participant PM as posture_monitor
  participant CF as Cloudflare API
  participant DOH as cloudflare-dns.com
  participant H as Web hosts
  participant SEC as security-api via gateway
  participant TG as Telegram
  participant UP as Uptime Worker
  GH->>WF: cron 23 */6 * * *
  WF->>R2: GET state.json (SigV4)
  R2-->>WF: previous.json or 404
  WF->>PM: --require-audit --state-in --state-out
  PM->>CF: zones, dns_records, settings, dnssec, access/apps, workers/scripts, subdomain
  CF-->>PM: inventory
  PM->>DOH: A query per CNAME target, 8 parallel
  DOH-->>PM: NOERROR or NXDOMAIN
  PM->>H: GET / per web host, 8 parallel, 10 s
  H-->>PM: cert, status, x-vercel-error, server
  PM->>PM: evaluate, carry_forward, diff
  PM->>SEC: pending audit events then new ones
  SEC-->>PM: 2xx
  PM->>TG: pending messages then new message
  TG-->>PM: ok true
  PM->>PM: write current.json generation + 1
  PM-->>WF: stdout counts-only summary, exit 0
  WF->>R2: PUT state.json
  WF->>UP: POST /heartbeat/posture-monitor ok true
```

Sources: `.github/workflows/posture.yml`, `posture_monitor/run.py`, `posture_monitor/collect.py` (`Cloudflare.inventory`, `dangling_cnames`, `probe_all`), `posture_monitor/audit.py`, `posture_monitor/r2.py`

## S2 — Provider failure (AC5)

```mermaid
sequenceDiagram
  participant WF as posture.yml
  participant PM as posture_monitor
  participant CF as Cloudflare API
  participant UP as Uptime Worker
  WF->>PM: run
  PM->>CF: GET /zones/.../dns_records
  CF-->>PM: error or success false
  PM-->>WF: provider_failed with path and error type, exit 2
  Note over WF: no current.json, so no PUT, old state stays
  WF->>UP: heartbeat ok false
```

Sources: `posture_monitor/collect.py` (`Cloudflare.get`, `ProviderError`), `posture_monitor/run.py` (`run`), `.github/workflows/posture.yml`, `tests/test_run.py` (`test_provider_failure_keeps_state`)

## S3 — Audit token exchange and idempotent post

```mermaid
sequenceDiagram
  participant AS as AuditSink
  participant OS as openssl binary
  participant ID as identity-api /v1/token
  participant GW as gateway /v1/platform-security
  AS->>OS: dgst -sha256 -sign key, header.claims
  OS-->>AS: RS256 signature
  AS->>ID: grant_type client_credentials, client_assertion, audience security-api, scope audit:write
  ID-->>AS: access_token
  loop each event in order
    AS->>GW: POST /v1/audit, Bearer, Idempotency-Key posture-sha256
    alt ProviderError
      GW-->>AS: error
      Note over AS: return this and later events as unposted
    else ok
      GW-->>AS: 2xx
    end
  end
```

Sources: `posture_monitor/audit.py` (`assertion`, `service_token`, `post_event`, `AuditSink`, `idempotency_key`), `tests/test_audit.py`

## S4 — Telegram failure keeps alert for next run

```mermaid
sequenceDiagram
  participant PM as posture_monitor
  participant TG as Telegram
  participant WF as posture.yml
  PM->>TG: sendMessage queue item n
  TG-->>PM: exception or ok false
  PM->>PM: unsent = queue from n, state pending_messages capped at 5
  PM-->>WF: status notify_failed, exit 3
  WF->>WF: PUT state.json anyway
```

Sources: `posture_monitor/run.py` (`run`, `telegram`), `posture_monitor/report.py` (`cap_pending`), `.github/workflows/posture.yml`, `tests/test_run.py` (`test_notify_failure_keeps_the_alert_for_the_next_run`, `test_pending_queue_is_capped`)
