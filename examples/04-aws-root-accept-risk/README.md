# Example 04 — AWS Root Account Accept-Risk

**Archetype:** FP that cannot be filtered at the field level — risk accepted with re-review  
**Decision:** `accept-risk`  
**Rule:** AWS Root Account Usage (CloudTrail)

## Scenario

AWS root account is used quarterly for break-glass DR testing per corporate policy. The alert cannot be suppressed via Sigma Filter because the event fields for a legitimate break-glass login and a genuine root compromise are identical (`userIdentity.type: Root`).

The correct control is a triage workflow: SOC is notified 48h before each drill and correlates the alert with the advance-notice ticket.

## Why `accept-risk` instead of `suppress`

- `suppress` would blind the detection entirely for all root usage — including actual compromises
- The FP is structurally indistinguishable from the true-positive at the event field level
- The risk is accepted with an explicit process control (advance notification) and a hard `expires_on`

This is the canonical DDR `accept-risk` use case: **you know the FP exists, you choose not to suppress, and you document the compensating control**.

## Files

| File | Purpose |
|------|---------|
| `sigma-rule.yml` | Vendored Sigma rule |
| `ddr.yml` | The Detection Decision Record (no `sigma-filter.yml` — accept-risk has no tuning block) |

## Key design notes

- No `sigma-filter.yml` — `accept-risk` decisions do not export filters
- `expires_on` is 1 year out; `review_cadence_days: 90` enforces quarterly check-ins
- `approved_by` is set — risk acceptance is signed off by the security manager
- Two evidence refs: runbook (compensating control) and the formal risk acceptance ticket
