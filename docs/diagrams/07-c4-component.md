# 07 — C4 Component

```mermaid
C4Component
  title Components of python -m posture_monitor
  Container_Boundary(pkg, "posture_monitor package") {
    Component(main, "__main__ / run.main", "argparse", "Flags, env, wiring, --require-audit")
    Component(run, "run.run", "orchestrator", "findings, carry_forward, diff, audit, queue, write state")
    Component(collect, "collect", "urllib, ssl, http.client", "Cloudflare client, enforcing_domains, web_hosts, dangling_cnames, probe_all")
    Component(checks, "checks", "pure functions", "Finding, ZoneSettings, Probe, evaluate, access_covers")
    Component(report, "report", "json", "load_state, load_meta, diff, message, dump_state, public_summary")
    Component(audit, "audit", "openssl subprocess", "assertion, service_token, AuditSink, idempotency_key, event_target")
    Component(r2, "r2", "hmac, hashlib", "SigV4 signed_request, get and put CLI")
  }
  System_Ext(cf, "Cloudflare API and DoH")
  System_Ext(hosts, "Web hosts")
  System_Ext(idp, "identity-api")
  System_Ext(sec, "security-api via gateway")
  System_Ext(tg, "Telegram")
  System_Ext(r2b, "R2 bucket")

  Rel(main, run, "calls")
  Rel(main, audit, "builds AuditSink")
  Rel(run, collect, "live_findings")
  Rel(run, checks, "evaluate, PROBE_RULES")
  Rel(run, report, "diff, message, state")
  Rel(run, audit, "AuditSink(events)")
  Rel(run, tg, "telegram send")
  Rel(collect, checks, "builds Probe, ZoneSettings")
  Rel(collect, cf, "GET")
  Rel(collect, hosts, "GET")
  Rel(audit, idp, "token")
  Rel(audit, sec, "POST /v1/audit")
  Rel(r2, r2b, "GET / PUT")
```

Sources: `posture_monitor/__main__.py`, `posture_monitor/run.py`, `posture_monitor/collect.py`, `posture_monitor/checks.py`, `posture_monitor/report.py`, `posture_monitor/audit.py`, `posture_monitor/r2.py`

หมายเหตุ: `audit.py` import `ProviderError` จาก `collect.py` ทำให้ audit failure ใช้ exception ชนิดเดียวกับ provider failure
