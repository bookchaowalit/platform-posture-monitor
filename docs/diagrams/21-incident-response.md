# 21 — Incident response

มีสอง incident class: (A) edge posture finding เปิด (เป็น "incident" ของระบบอื่นที่ monitor ตรวจเจอ) และ (B) ตัว monitor เองล้มหรือหาย ไม่มี runbook / postmortem template ใน repo; flow ด้านล่างประกอบจาก alert channel ที่มีจริง

```mermaid
flowchart TD
  subgraph A["A: Posture finding"]
    A1["Telegram: Opened line with severity icon"] --> A2{"Severity"}
    A2 -->|"high: tunnel-no-access, dangling-target, zone-ssl"| A3["Fix now at Cloudflare Access, DNS or zone settings"]
    A2 -->|"medium or low"| A4["Plan fix"]
    A3 --> A5["workflow_dispatch to verify"]
    A4 --> A5
    A5 --> A6["Telegram Resolved line and security-api posture.resolved"]
    A6 --> A7["Record in architecture-docs network review NET item"]
  end
  subgraph B["B: Monitor failure"]
    B1["Uptime Worker: heartbeat ok false or silent 13 h"] --> B2["Open last Posture monitor run, read status in summary"]
    B2 --> B3{"status"}
    B3 -->|"provider_failed"| B4["Check Cloudflare token, DoH; local run with infisical and --no-notify"]
    B3 -->|"audit_failed"| B5["Check identity-api, gateway, security-api"]
    B3 -->|"notify_failed"| B6["Check Telegram bot token and chat"]
    B3 -->|"no run"| B7["Check GitHub schedule, workflow disabled"]
    B4 --> B8["Fix, then dispatch; pending queues drain on the next good run"]
    B5 --> B8
    B6 --> B8
    B7 --> B8
  end
```

Sources: `posture_monitor/report.py` (`message`, `ICON`), `posture_monitor/checks.py` (severities), `posture_monitor/run.py` (status values), `.github/workflows/posture.yml`, `README.md` (How it runs, Local run, Rotation), central doc [network-architecture.md §10](https://github.com/bookchaowalit/architecture-docs/blob/main/systems/architecture/network-architecture.md)

ขั้น A7 มาจาก network-architecture.md §10 ("close or re-date each finding") ที่ยังใช้เป็น manual review คู่กัน

## Open questions

- ไม่มี severity → response time target (เช่น high ต้องแก้ภายในกี่ชั่วโมง)
- ไม่มี postmortem template หรือที่เก็บ postmortem
- GitHub ปิด scheduled workflow อัตโนมัติใน public repo ที่ไม่มี activity 60 วัน — ตอนนั้น heartbeat จะเป็นตัวจับ แต่ไม่มีขั้นตอนเขียนไว้
