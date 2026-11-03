# ADR-0005 — Heartbeat instead of Sentry (reasoned waiver)

- Status: accepted (retro-documented, 2026-11-03)

## Context

repo อื่นในพอร์ตใช้ Sentry; job นี้เป็น stdlib-only และ log เป็น public

## Decision

ไม่ใส่ error reporter: ทุก run ส่ง heartbeat `posture-monitor` ไป uptime Worker (`ok: true` เมื่อ exit 0, ไม่งั้น `ok: false`) และ Worker แจ้งเมื่อไม่มี report ใน 13 ชั่วโมง

```mermaid
flowchart LR
  RUN["Check posture step"] -->|"exit_code"| HB["Heartbeat step, if always"]
  HB -->|"POST /heartbeat/posture-monitor"| UP["Uptime Worker"]
  UP -->|"ok false or silent 13 h"| ALERT["Alert"]
```

## Consequences

- ไม่มี stack trace รวมศูนย์; รายละเอียด error อยู่ใน `stderr.log` บน runner ที่หายไปหลัง job จบ
- ถ้า step ก่อนหน้าไม่ตั้ง `exit_code` (เช่น checkout ล้ม) heartbeat ส่ง `ok: false` เพราะ `CODE` ว่าง

Evidence / Sources: `PRODUCT.md` (Sentry waiver), `.github/workflows/posture.yml` (Heartbeat), `README.md`, commit `d5cda69`
