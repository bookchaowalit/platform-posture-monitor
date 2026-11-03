# 18 — Git & release workflow

```mermaid
gitGraph
  commit id: "63eccfe feat monitor"
  commit id: "c5fb094 fix fail-open"
  commit id: "93bd5fe fix unreachable"
  commit id: "db7af24 feat audit"
  branch ci/shared-ci-product
  commit id: "d5cda69 ci shared"
  commit id: "b6840c0 docs product"
  checkout main
  merge ci/shared-ci-product id: "PR 1 fast-forward"
  commit id: "3022ef5 feat gateway"
  commit id: "6d613f6 fix queues"
  commit id: "6019521 docs queues"
```

หมายเหตุ: PR #1 ถูก merge แบบ fast-forward (ไม่มี merge commit ใน `git log --first-parent`); gitGraph ต้องมี merge node จึงแสดงเป็น merge

```mermaid
flowchart LR
  DEV["Commit locally"] --> PATH{"Direct or PR"}
  PATH -->|"most commits"| MAIN["push to main"]
  PATH -->|"PR 1"| PRR["PR, CI on pull_request"] --> MERGE["merge locally and push"] --> MAIN
  MAIN --> CI["ci.yml push run"]
  MAIN --> DISP["optional workflow_dispatch of posture.yml"]
  MAIN --> NEXT["next scheduled posture.yml run uses main"]
  CI -.->|"not a gate"| NEXT
```

Sources: `git log --first-parent origin/main`, `gh pr list -R bookchaowalit/platform-posture-monitor --state all` (PR #1 `ci/shared-ci-product`, merged 2026-11-03 05:21 UTC), `gh run list -R bookchaowalit/platform-posture-monitor`, `.github/workflows/ci.yml`, `.github/workflows/posture.yml`, `gh api .../branches/main/protection` (404), ops record: merge-locally (2026-11-03)

- ไม่มี tag / GitHub release
- ไม่มี branch protection: CI ไม่ block push เข้า `main`

## Open questions

- ต้องการให้ `posture.yml` รันเฉพาะ SHA ที่ CI ผ่าน (เช่น `workflow_run`) หรือไม่
