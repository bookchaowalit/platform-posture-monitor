# 06 — C4 Container

```mermaid
C4Container
  title Container view - platform-posture-monitor
  Person(owner, "Owner")
  System_Boundary(gh, "GitHub Actions, ubuntu-24.04 runner") {
    Container(wf, "posture.yml job monitor", "bash + Python 3.13", "Orchestrates get, run, put, heartbeat")
    Container(cli, "python -m posture_monitor", "Python stdlib", "Inventory, rules, diff, audit, alert, state")
    Container(r2cli, "python -m posture_monitor.r2", "Python stdlib SigV4", "get or put state.json")
    ContainerDb(tmp, "RUNNER_TEMP files", "previous.json, current.json, stderr.log", "Private to the runner")
  }
  System_Ext(cf, "Cloudflare API and DoH")
  System_Ext(hosts, "Web hosts")
  ContainerDb_Ext(r2, "R2 bucket posture-monitor", "S3 API", "state.json")
  System_Ext(tg, "Telegram")
  System_Ext(idp, "identity-api")
  System_Ext(gw, "gateway.bookchaowalit.com")
  System_Ext(up, "Uptime Worker")

  Rel(wf, r2cli, "runs")
  Rel(wf, cli, "runs with --require-audit")
  Rel(r2cli, r2, "GET / PUT")
  Rel(r2cli, tmp, "reads, writes")
  Rel(cli, tmp, "reads previous, writes current")
  Rel(cli, cf, "GET")
  Rel(cli, hosts, "GET /")
  Rel(cli, idp, "POST /v1/token")
  Rel(cli, gw, "POST /v1/platform-security/v1/audit")
  Rel(cli, tg, "sendMessage")
  Rel(wf, up, "curl POST /heartbeat/posture-monitor")
  Rel(tg, owner, "alert")
```

Sources: `.github/workflows/posture.yml`, `posture_monitor/__main__.py`, `posture_monitor/run.py`, `posture_monitor/r2.py`, `posture_monitor/audit.py`, `posture_monitor/collect.py`

หมายเหตุ: `$GITHUB_STEP_SUMMARY` ได้แค่ stdout (counts-only summary); stderr ไปเก็บใน `$RUNNER_TEMP/stderr.log` เพื่อไม่ให้ขึ้น public log (R2)
