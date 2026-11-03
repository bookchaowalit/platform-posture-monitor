# 01 — Business process (As-Is / To-Be)

repo นี้คือ scheduled job (GitHub Actions ทุก 6 ชั่วโมง, Python standard library) ที่ตรวจ security posture ของ edge `bookchaowalit.com` แบบ read-only แล้วแจ้ง Telegram เฉพาะเมื่อ finding เปิดหรือปิด เป็นรูปแบบ "running system" ของ network review แบบ manual วันที่ 2026-11-02 (NET-01…NET-12)

## As-Is (จากโค้ดวันนี้)

```mermaid
flowchart TD
  T["Trigger: cron 23 */6 * * * or workflow_dispatch"] --> G["r2 get state.json"]
  G -->|"exit != 0"| HB
  G -->|"ok or 404 = first run"| INV["Cloudflare inventory: zone, DNS records, zone settings, DNSSEC, Access apps, Workers subdomains"]
  INV -->|"ProviderError"| FAIL["exit 2, no state written"]
  INV --> DOH["DoH NXDOMAIN check for every CNAME target"]
  DOH -->|"resolver error"| FAIL
  DOH --> PROBE["HTTPS GET per web host, 8 workers, 10 s timeout"]
  PROBE --> EVAL["evaluate rules to findings"]
  EVAL --> CF["carry forward probe findings of unreachable hosts"]
  CF --> DIFF["diff with previous state: opened / resolved"]
  DIFF --> AUD["post audit events to security-api: pending first"]
  AUD --> TG["send Telegram queue: pending first, then new message"]
  TG --> WS["write current.json with generation + 1, unposted audit, unsent alerts"]
  WS --> PUT["r2 put state.json"]
  PUT --> SUM["print counts-only summary to step summary"]
  SUM --> HB["Heartbeat to uptime Worker: ok true or false"]
  FAIL --> HB
```

Sources: `.github/workflows/posture.yml`, `posture_monitor/run.py`, `posture_monitor/collect.py`, `posture_monitor/checks.py`, `posture_monitor/report.py`, `posture_monitor/audit.py`, `posture_monitor/r2.py`, `README.md`

ประเด็นสำคัญของ As-Is
- owner เป็นคนแก้ปัญหาเอง (out of scope: automatic remediation — `PRODUCT.md`)
- ไม่มี message เมื่อไม่มีอะไรเปลี่ยน; รอบแรก (ไม่มี state) ส่ง baseline หนึ่งข้อความ (SPEC-001 R3)
- inventory ล้มเหลว = ไม่เขียน state เลย จึงไม่มีอะไร "resolve" เพราะ provider ล่ม (R4)

## To-Be (จาก `docs/specs/001-posture-monitor.md` "Later" และ `PRODUCT.md`)

```mermaid
flowchart LR
  NOW["v1 rules: DNS, TLS, Access, zone settings, Workers"] --> NEON["Neon allowlist rule with a read-only credential"]
  NOW --> DRIFT["Registry drift: DNS hostnames with no system in online-systems.yaml"]
  NOW -.->|"not covered yet, README"| HDR["Response security headers NET-07"]
```

Sources: `docs/specs/001-posture-monitor.md` (Later, Out of scope), `PRODUCT.md` (Capabilities and Constraints), `README.md` (Not covered yet)

## Open questions

- Response security headers (NET-07) อยู่ใน "Not covered yet" ของ README แต่ SPEC-001 บอกว่า out of scope เพราะ provider-wide: จะเป็น rule ในอนาคตหรือไม่
- ไม่มีวันเป้าหมายของ Neon allowlist rule และ registry drift
