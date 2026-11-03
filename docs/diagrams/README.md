# Core 22 SDLC diagram pack — platform-posture-monitor

ชุดภาพ Core 22 ตาม SDLC Diagram Catalog v2 วาดจากโค้ดและ config ใน repo นี้ (ณ `origin/main` `6019521`, 2026-11-03)
repo นี้คือ scheduled job (GitHub Actions ทุก 6 ชั่วโมง, Python standard library) ที่ตรวจ security posture ของ edge `bookchaowalit.com` แบบ read-only, เก็บ state ใน R2, แจ้ง Telegram เมื่อ finding เปิด/ปิด และเขียน audit event ไป security-api ผ่าน edge gateway ไม่ใช่ Cloudflare Worker และไม่มี hosted runtime

ทุกไฟล์มี `Sources:` ใต้ภาพ และ "Open questions" สำหรับสิ่งที่ยืนยันจากโค้ดไม่ได้ requirement หลักอยู่ที่ [SPEC-001](../specs/001-posture-monitor.md) และ [README](../../README.md) / [PRODUCT.md](../../PRODUCT.md) (reuse โดย link ไม่ copy)

| # | Item | Status | File | Sources read |
|---|---|---|---|---|
| 01 | Business process As-Is / To-Be | done | [01-business-process.md](01-business-process.md) | `posture.yml`, `run.py`, `collect.py`, SPEC-001 Later, `PRODUCT.md` |
| 02 | Use cases | done | [02-use-cases.md](02-use-cases.md) | `posture.yml`, `run.py`, `audit.py`, `PRODUCT.md` |
| 03 | User flows | done | [03-user-flows.md](03-user-flows.md) | `report.py`, `run.py`, `README.md` |
| 04 | Traceability (RTM) | done | [04-traceability.md](04-traceability.md) | SPEC-001, `posture_monitor/`, `tests/`, workflows |
| 05 | C4 Context | done | [05-c4-context.md](05-c4-context.md) | `collect.py`, `audit.py`, `r2.py`, `posture.yml`, ops record api-gateway-edge |
| 06 | C4 Container | done | [06-c4-container.md](06-c4-container.md) | `posture.yml`, package modules |
| 07 | C4 Component | done | [07-c4-component.md](07-c4-component.md) | `posture_monitor/*.py` |
| 08 | ADRs | done (5) | [08-adr/](08-adr/) | workflows, SPEC-001, `PRODUCT.md`, `audit.py`, `r2.py`, `run.py`, git log |
| 09 | ERD | done (R2 state object) | [09-erd.md](09-erd.md) | `report.py`, `checks.py`, `audit.py`, `r2.py` |
| 10 | Sequences | done (4) | [10-sequences.md](10-sequences.md) | `run.py`, `collect.py`, `audit.py`, `posture.yml`, tests |
| 11 | State machines | done (3) | [11-state-machines.md](11-state-machines.md) | `run.py`, `checks.py`, `report.py` |
| 12 | API & integrations | done | [12-api-integration.md](12-api-integration.md) | `collect.py`, `audit.py`, `run.py`, `r2.py`, `posture.yml` |
| 13 | Threat model | done | [13-threat-model.md](13-threat-model.md) | workflows, all modules, README Credentials, branch protection API |
| 14 | Backup & DR | done | [14-backup-dr.md](14-backup-dr.md) | `report.py`, `r2.py`, `run.py`, README Rotation |
| 15 | CI/CD pipeline | done | [15-cicd-pipeline.md](15-cicd-pipeline.md) | `ci.yml`, `posture.yml`, platform-ci-workflows @ `87dc5e1c` |
| 16 | Deployment | done | [16-deployment.md](16-deployment.md) | `posture.yml`, `audit.py`, README Credentials |
| 17 | Test coverage matrix | done | [17-test-coverage-matrix.md](17-test-coverage-matrix.md) | `tests/*.py`, `ci.yml` |
| 18 | Git & release workflow | done | [18-git-release-workflow.md](18-git-release-workflow.md) | `git log`, `gh pr list`, `gh run list` |
| 19 | Service dependency map | done | [19-service-dependency-map.md](19-service-dependency-map.md) | `run.py`, `collect.py`, `audit.py`, `r2.py` |
| 20 | Observability | done | [20-observability.md](20-observability.md) | `run.py`, `posture.yml`, `PRODUCT.md` |
| 21 | Incident response | done | [21-incident-response.md](21-incident-response.md) | `report.py`, `run.py`, README, architecture-docs network-architecture §10 |
| 22 | DORA | done (recovery time not computable) | [22-dora.md](22-dora.md) | `git log`, `gh run list`, `gh pr list` |

ADRs: [0001 GitHub Actions scheduled job](08-adr/ADR-0001-github-actions-scheduled-job.md) · [0002 stdlib only](08-adr/ADR-0002-standard-library-only.md) · [0003 R2 state, fail closed](08-adr/ADR-0003-r2-state-fail-closed.md) · [0004 audit via identity + gateway](08-adr/ADR-0004-audit-via-identity-and-gateway.md) · [0005 heartbeat instead of Sentry](08-adr/ADR-0005-heartbeat-instead-of-sentry.md)

Central reference (read-only): [network-architecture.md](https://github.com/bookchaowalit/architecture-docs/blob/main/systems/architecture/network-architecture.md) (NET-01…NET-12, §10 Keeping this current)

Validate: `node ~/work/core22/tools/validate.mjs docs/diagrams/*.md docs/diagrams/08-adr/*.md`
