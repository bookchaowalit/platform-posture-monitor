# 16 — Deployment

ไม่มี hosted runtime, Worker route หรือ custom domain ของตัวเอง โค้ดรันบน GitHub-hosted runner ชั่วคราวทุก 6 ชั่วโมง

```mermaid
flowchart TB
  subgraph GH["GitHub"]
    REPO["bookchaowalit/platform-posture-monitor, public, branch main"]
    SECRETS["Actions secrets: CLOUDFLARE_*, POSTURE_R2_*, TELEGRAM_*, HEARTBEAT_TOKEN, POSTURE_IDENTITY_PRIVATE_KEY_PEM"]
    RUNNER["ubuntu-24.04 runner, Python 3.13, timeout 10 min, concurrency posture-monitor"]
  end
  INF["Infisical /posture-monitor"] -.->|"mirrored by owner"| SECRETS
  REPO --> RUNNER
  SECRETS --> RUNNER
  subgraph CFA["Cloudflare"]
    API["api.cloudflare.com"]
    R2["R2 bucket posture-monitor"]
    DOH["cloudflare-dns.com"]
    GWD["gateway.bookchaowalit.com, proxied"]
    UPW["monitor.bookchaowalit.com"]
  end
  subgraph RW["Railway"]
    IDA["identity-api-production-fad1.up.railway.app"]
    SECA["security-api"]
  end
  RUNNER --> API
  RUNNER --> R2
  RUNNER --> DOH
  RUNNER --> GWD --> SECA
  RUNNER --> IDA
  RUNNER --> UPW
  RUNNER --> TGA["api.telegram.org"]
```

Sources: `.github/workflows/posture.yml`, `posture_monitor/audit.py` (`IDENTITY`, `SECURITY_API`, rollback URL comment), `posture_monitor/collect.py`, `posture_monitor/r2.py`, `README.md` (Credentials), ops record: api-gateway-edge (2026-11-03)

| Env / config | Value source |
|---|---|
| Zone | `POSTURE_ZONE` env, default `bookchaowalit.com` (`run.py`) |
| R2 endpoint / keys | Actions secrets `POSTURE_R2_*` |
| Identity / security URLs | constants in `audit.py` (not env) |
| Heartbeat URL | literal in `posture.yml` |

## Open questions

- การ mirror Infisical → Actions secrets ทำมือหรือมี automation (README บอกแค่ "mirrored")
