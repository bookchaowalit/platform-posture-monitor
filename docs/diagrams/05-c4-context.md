# 05 — C4 Context

```mermaid
C4Context
  title System Context - platform-posture-monitor
  Person(owner, "Owner", "Gets Telegram alerts, fixes the edge")
  System(pm, "Posture monitor", "Scheduled read-only edge check, GitHub Actions every 6 h")
  System_Ext(cf, "Cloudflare API", "Zone, DNS, settings, DNSSEC, Access apps, Workers")
  System_Ext(doh, "Cloudflare DoH", "cloudflare-dns.com dns-query")
  System_Ext(hosts, "Web hosts", "bookchaowalit.com hostnames on Vercel, Railway, tunnel, Workers, Pages")
  System_Ext(r2, "Cloudflare R2", "bucket posture-monitor, state.json")
  System_Ext(tg, "Telegram Bot API", "sendMessage")
  System_Ext(idp, "identity-api", "client_credentials token")
  System_Ext(gw, "Edge API gateway", "gateway.bookchaowalit.com")
  System_Ext(sec, "security-api", "POST /v1/audit")
  System_Ext(up, "Uptime Worker", "heartbeat posture-monitor")

  Rel(pm, cf, "Reads inventory", "HTTPS GET")
  Rel(pm, doh, "Resolves CNAME targets", "HTTPS")
  Rel(pm, hosts, "One GET per web host", "HTTPS")
  Rel(pm, r2, "Get and put state", "S3 SigV4")
  Rel(pm, tg, "Alerts on change", "HTTPS")
  Rel(pm, idp, "Exchanges private_key_jwt", "HTTPS")
  Rel(pm, gw, "Audit events", "HTTPS")
  Rel(gw, sec, "Proxies /v1/platform-security")
  Rel(pm, up, "Heartbeat ok true or false", "HTTPS")
  Rel(tg, owner, "Message")
  Rel(up, owner, "Alert on fail or silence")
```

Sources: `posture_monitor/collect.py` (`API`, `DOH`, `probe`), `posture_monitor/r2.py`, `posture_monitor/run.py` (`telegram`), `posture_monitor/audit.py` (`IDENTITY`, `SECURITY_API`), `.github/workflows/posture.yml` (Heartbeat URL), ops record: api-gateway-edge (2026-11-03)

## Open questions

- uptime Worker ส่ง alert ไปช่องทางไหน (Telegram ตัวเดียวกันหรือไม่) ไม่ได้ระบุใน repo นี้
