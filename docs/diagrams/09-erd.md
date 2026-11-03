# 09 — ERD (persisted data)

ไม่มี database; ข้อมูลที่ persist มีอย่างเดียวคือ object `state.json` (version 3) ใน R2 bucket `posture-monitor` นอกจากนั้นคือ audit event ที่ถูกเขียนลง security-api (ระบบอื่นเป็นเจ้าของ schema)

```mermaid
erDiagram
  STATE_JSON ||--o{ FINDING : findings
  STATE_JSON ||--o{ PENDING_AUDIT : pending_audit
  STATE_JSON ||--o{ PENDING_MESSAGE : pending_messages
  PENDING_AUDIT }o--|| FINDING : "id refers to"
  PENDING_AUDIT ||--o| AUDIT_EVENT : "posted as"

  STATE_JSON {
    int version "3"
    int generation "bumped on every written state"
  }
  FINDING {
    string id PK "rule:subject"
    string rule
    string severity "high, medium, low"
    string subject "hostname, zone or script id"
  }
  PENDING_AUDIT {
    string change "opened or resolved"
    string id FK "finding id"
    int generation "generation first seen"
  }
  PENDING_MESSAGE {
    string text "max 4000 chars, max 5 kept"
  }
  AUDIT_EVENT {
    string action "posture.opened or posture.resolved"
    string target "rule.subject or rule.h hash16"
    string idempotency_key "posture- sha256"
  }
```

Sources: `posture_monitor/report.py` (`dump_state`, `load_state`, `load_meta`, `bound`, `cap_pending`, `MAX_CHARS`, `MAX_PENDING`), `posture_monitor/checks.py` (`Finding.as_dict`), `posture_monitor/run.py` (events), `posture_monitor/audit.py` (`event_target`, `idempotency_key`, `AuditSink`), `posture_monitor/r2.py` (`BUCKET`)

หมายเหตุ: `load_meta` ยังอ่าน state version 2 ได้ (field `pending_message` แบบ string เดียว)

ข้อมูลชั่วคราว (ไม่ persist): `ZoneSettings`, `Probe`, DNS records list และ Access domains อยู่ใน memory ระหว่าง run เท่านั้น

## Open questions

- schema ฝั่ง security-api ของ audit event (workspace, actor, timestamps) อยู่ใน platform-security repo ไม่ได้อ่านในรอบนี้
