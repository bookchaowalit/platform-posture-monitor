# 15 — CI/CD pipeline

```mermaid
flowchart TD
  PUSH["push to main"] --> CI
  PR["pull_request"] --> CI
  subgraph CI["ci.yml - CI"]
    PYJ["job python: uses ci-python.yml @87dc5e1c v1.1.1"]
    SECJ["job security: uses security.yml @87dc5e1c v1.1.1"]
  end
  PYJ --> PY1["checkout, setup-uv, Python 3.13"]
  PY1 --> PY2["Lint Ruff with ruff.toml"]
  PY2 --> PY3["Test: python -m unittest discover -s tests -v"]
  SECJ --> S1["gitleaks"]
  SECJ --> S2["semgrep"]
  SECJ --> S3["osv-scanner"]
  SECJ --> S4["trivy-fs"]

  CRON["schedule 23 */6 * * *"] --> MON
  DISP["workflow_dispatch"] --> MON
  subgraph MON["posture.yml - Posture monitor, job monitor"]
    M1["checkout persist-credentials false"] --> M2["setup-python 3.13"]
    M2 --> M3["Check posture: r2 get, run --require-audit, r2 put"]
    M3 --> M4["Heartbeat if always"]
  end
```

Sources: `.github/workflows/ci.yml`, `.github/workflows/posture.yml`, platform-ci-workflows `.github/workflows/ci-python.yml` and `security.yml` @ `87dc5e1c` (step names), `ruff.toml`

Inputs ที่ repo ส่งให้ `ci-python`: `python-version: "3.13"`, `format-check: false` (follow-up: ruff format), `typecheck-command: ""` (ไม่มี type check), `test-command: python -m unittest discover -s tests -v`; ไม่มี coverage gate, ไม่มี Postgres

**ไม่มี deploy job:** CI ไม่ใช่ gate ของ `posture.yml` — run ถัดไปใช้ `main` ล่าสุดเสมอ ไม่ว่า CI ผ่านหรือไม่ (ดู 18)

## Open questions

- จะเปิด type check / coverage gate (TDD+SDD standard ADR-0004 opt-in) หรือไม่
