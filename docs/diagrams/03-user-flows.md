# 03 — User flows

ไม่มี route หรือ page; "flow" คือเส้นทางที่ owner เจอจริงผ่าน Telegram, GitHub Actions และ CLI

## Flow A — Owner ได้รับ alert แล้วแก้ edge

```mermaid
flowchart TD
  A1["Telegram: Posture monitor: changes, open counts"] --> A2{"Opened lines?"}
  A2 -->|"yes"| A3["Read rule and subject per line, highest severity first"]
  A3 --> A4["Owner fixes at Cloudflare, Vercel or Railway"]
  A4 --> A5["Wait for next run or dispatch workflow"]
  A5 --> A6["Telegram: Resolved line with check mark"]
  A2 -->|"only Resolved"| A6
```

Sources: `posture_monitor/report.py` (`message`, `ICON`, `MAX_LINES`), `.github/workflows/posture.yml` (`workflow_dispatch`), `PRODUCT.md` (out of scope: automatic remediation)

## Flow B — Owner ได้ heartbeat alert (run ล้มหรือหายไป)

```mermaid
flowchart TD
  B1["Uptime Worker alert: posture-monitor not ok or silent 13 h"] --> B2["Open Actions run of Posture monitor"]
  B2 --> B3{"Step summary status"}
  B3 -->|"provider_failed"| B4["Public log shows endpoint path and error type only"]
  B3 -->|"audit_failed"| B5["Check identity-api or security-api via gateway"]
  B3 -->|"notify_failed"| B6["Check Telegram bot token"]
  B4 --> B7["Re-run locally with infisical run and --no-notify"]
  B5 --> B7
  B6 --> B7
```

Sources: `posture_monitor/run.py` (status values, exit codes), `posture_monitor/collect.py` (`ProviderError` message), `README.md` (How it runs, Local run)

## Flow C — Local run

```mermaid
flowchart LR
  C1["python3 -m unittest discover -s tests"] --> C2["infisical run --path /posture-monitor -- python3 -m posture_monitor --state-in ... --state-out ... --no-notify"]
  C2 --> C3["Alert text printed to stderr, summary to stdout"]
```

Sources: `README.md` (Local run), `posture_monitor/run.py` (`--no-notify`)

## Open questions

- ไม่มี runbook ที่เขียนไว้ว่า owner ต้องทำอะไรต่อ rule แต่ละตัว (เช่น `tunnel-no-access` ต้องสร้าง Access app แบบไหน)
