# Product

<!-- impeccable:product-schema 1 -->

## Platform

scheduled job (GitHub Actions, every 6 hours), standard-library Python

## Users

- The owner, who gets a Telegram message only when an edge finding opens or resolves.
- `security-api`, which receives every opened or resolved finding as an audit event.

## Product Purpose

Keep the `bookchaowalit.com` edge from drifting into an unsafe state without anyone noticing:
rebuild the inventory from Cloudflare plus one HTTPS GET per web hostname, evaluate fixed rules
(README "What it checks"), diff with the previous run and report only the change.

Success: every opened or resolved finding reaches Telegram and `security-api` within one run,
and nothing is reported when nothing changed. Requirements: [SPEC-001](docs/specs/001-posture-monitor.md).

## Positioning

The running form of the manual network review of 2026-11-02 (architecture-docs
`systems/architecture/network-architecture.md`, NET-01…NET-12). Read-only toward providers.

## Operating Context

- Runs in `.github/workflows/posture.yml` (`23 */6 * * *`) on a GitHub-hosted runner. The repository
  is public, so the job log prints only counts per severity and an error type; findings go only
  to Telegram, state lives in the private R2 bucket `posture-monitor`.
- Credentials: its own read-only Cloudflare token, R2 keys, Telegram and the platform-identity
  service client `posture-monitor` (Infisical `/posture-monitor`, mirrored to Actions secrets).
- CI: shared `ci-python` (Ruff with `ruff.toml`, the unittest suite) and the shared security
  workflow.

Sentry waiver: a failed or missed run already alerts through the uptime Worker heartbeat `posture-monitor` (13 h) and Telegram; the job is standard-library only and its log is public by design, so it ships no error reporter or extra secret.

## Capabilities and Constraints

- Never writes to Cloudflare, Vercel or Railway; the only writes are its R2 state, Telegram and
  audit events.
- Never resolves a finding on an unreachable host (a failed probe is not a fix).
- Out of scope (SPEC-001 "Later"): automatic remediation.

## Measures

- Heartbeat `posture-monitor` reports `ok: true` at least every 13 hours (target: always).
- Findings open at the latest run (baseline 2026-11-03: 10 low).
