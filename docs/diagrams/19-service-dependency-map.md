# 19 — Service dependency map (runtime)

```mermaid
flowchart TD
  PM["posture-monitor job"]
  subgraph Hard["Hard: failure means exit 2 and no new verdict"]
    CF["Cloudflare API"]
    DOH["Cloudflare DoH"]
    R2["R2 posture-monitor"]
  end
  subgraph Retry["Retried next run: exit 2 or 3, state still written"]
    ID["identity-api, Railway"]
    GW["edge gateway, Cloudflare proxy to Railway"]
    SEC["security-api, Railway"]
    TG["Telegram Bot API"]
  end
  subgraph Soft["Soft: no finding on failure"]
    HOSTS["Web hosts on Vercel, Railway, tunnel, Workers, Pages"]
  end
  subgraph Report["Reporting"]
    UP["uptime Worker heartbeat"]
  end
  GH["GitHub Actions runner and schedule"] --> PM
  PM --> CF
  PM --> DOH
  PM --> R2
  PM --> ID
  PM --> GW --> SEC
  PM --> TG
  PM --> HOSTS
  PM --> UP
  RT["Runner openssl binary"] --> PM
```

Sources: `posture_monitor/run.py`, `posture_monitor/collect.py`, `posture_monitor/audit.py`, `posture_monitor/r2.py`, `.github/workflows/posture.yml`, `README.md` (How it runs), ops record: api-gateway-edge (2026-11-03)

ไม่มี database, CDN หรือ SDK ของ third-party; ทุก dependency เป็น HTTPS ด้วย stdlib

## Open questions

- gateway มี rate-limit 60 req / 10 s ต่อ IP (ops record api-gateway-edge): จำนวน audit event ต่อ run (เช่น baseline หลาย finding) อาจชนหรือไม่ — repo ไม่มี throttle
