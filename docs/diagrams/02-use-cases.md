# 02 — Use cases

ไม่มี user login หรือ UI; actor คือ trigger, ผู้รับผล และ service ที่ job เรียก ตามโค้ดและ workflow

```mermaid
flowchart LR
  CRON(["Actor: GitHub schedule cron"])
  OWNER(["Actor: Owner"])
  SEC(["Actor: security-api"])
  UP(["Actor: uptime Worker"])

  subgraph PM["platform-posture-monitor"]
    UC1["UC1 Run scheduled posture check"]
    UC2["UC2 Run check on demand"]
    UC3["UC3 Receive alert on opened or resolved finding"]
    UC4["UC4 Receive baseline on first run"]
    UC5["UC5 Record audit event posture.opened or posture.resolved"]
    UC6["UC6 Report run health heartbeat"]
    UC7["UC7 Run locally with --no-notify"]
  end

  CRON --> UC1
  OWNER --> UC2
  OWNER --> UC7
  UC1 --> UC3
  UC1 --> UC4
  UC3 --> OWNER
  UC4 --> OWNER
  UC1 --> UC5
  UC5 --> SEC
  UC1 --> UC6
  UC6 --> UP
  UP -->|"alert when ok false or no report in 13 h"| OWNER
```

Sources: `.github/workflows/posture.yml` (`schedule`, `workflow_dispatch`, Heartbeat step), `posture_monitor/run.py` (`main`, `--no-notify`, `--require-audit`), `posture_monitor/audit.py`, `PRODUCT.md` (Users), `README.md` (Local run)

| Use case | Actor | Auth level in code |
|---|---|---|
| UC1 / UC2 | GitHub cron, owner (Actions UI) | repo Actions secrets; `permissions: contents: read` |
| UC3 / UC4 | owner via Telegram | bot token + chat id (`TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`) |
| UC5 | security-api | identity service client `posture-monitor`, `private_key_jwt`, audience `security-api`, scope `audit:write` |
| UC6 | uptime Worker | `HEARTBEAT_TOKEN` bearer |
| UC7 | owner on own machine | `infisical run --path /posture-monitor` |

## Open questions

- ไม่พบผู้อ่าน audit event `posture.*` ใน security-api จาก repo นี้ (มีแค่ฝั่งเขียน); ใครใช้ข้อมูลนี้ต่อ
