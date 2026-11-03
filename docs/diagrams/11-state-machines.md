# 11 — State machines

## Finding lifecycle (across runs)

```mermaid
stateDiagram-v2
  [*] --> Open: rule fires, opened, audit posture.opened, alert line
  Open --> Open: still fires
  Open --> CarriedForward: host unreachable this run and rule in PROBE_RULES
  CarriedForward --> Open: host reachable and rule still fires
  CarriedForward --> Resolved: host reachable and rule no longer fires
  Open --> Resolved: rule no longer fires on complete inventory
  Resolved --> [*]: audit posture.resolved, alert line
  Resolved --> Open: fires again later, new generation gives new event
```

Sources: `posture_monitor/run.py` (`carry_forward`), `posture_monitor/checks.py` (`PROBE_RULES`), `posture_monitor/report.py` (`diff`), `posture_monitor/audit.py` (`idempotency_key`), `tests/test_run.py` (`test_unreachable_host_keeps_its_probe_finding`)

## Run outcome (exit code to heartbeat)

```mermaid
stateDiagram-v2
  [*] --> FetchState
  FetchState --> Failed2: r2 get error
  FetchState --> Inventory
  Inventory --> Failed2: ProviderError, no state written
  Inventory --> Audit
  Audit --> Notify
  Notify --> WriteState
  WriteState --> Put
  Put --> Failed2: r2 put error
  Put --> OK: no unposted, no unsent
  Put --> Failed2: unposted audit events
  Put --> Failed3: unsent alerts
  OK --> [*]: heartbeat ok true
  Failed2 --> [*]: heartbeat ok false
  Failed3 --> [*]: heartbeat ok false
```

Sources: `posture_monitor/run.py` (`OK`, `PROVIDER_FAILED`, `NOTIFY_FAILED`), `.github/workflows/posture.yml`

## Pending alert / audit queues

```mermaid
stateDiagram-v2
  [*] --> Queued: send or post failed
  Queued --> Delivered: next run sends or posts first
  Queued --> Queued: fails again
  Queued --> Dropped: more than 5 pending messages, older collapse into a note
  Delivered --> [*]
  Dropped --> [*]
```

Sources: `posture_monitor/run.py`, `posture_monitor/report.py` (`cap_pending`, `MAX_PENDING`), `tests/test_run.py` (`test_pending_queue_is_capped`, `test_failed_audit_events_are_kept_with_their_generation_and_retried_first`)

หมายเหตุ: `pending_audit` ไม่มี cap (มีแค่ `pending_messages` ที่ cap ที่ 5)
