# Example 05 — Legacy Rule Deprecation

**Archetype:** Rule retirement tombstone with a replacement pointer  
**Decision:** `deprecate`  
**Rule:** Suspicious WMI Event Subscription (Legacy, Sysmon EventID 19 only)

## Scenario

The original WMI persistence rule (EventID 19 alone) generated ~20 FPs/day from SolarWinds, SCOM, and CrowdStrike Falcon — all of which create WMI subscriptions for legitimate monitoring. There was no feasible suppression path without maintaining a fragile allowlist of every monitoring agent binary.

The v2 rule (ID `c9e4d7f8-5678-4bcd-9012-000000000099`) correlates EventIDs 19, 20, and 21 together (subscription + consumer + binding), which eliminates the FP class structurally. The legacy rule was retired after v2 was validated in production.

## Why `deprecate` instead of `suppress`

- No suppression filter could address the FP without maintaining an unbounded agent allowlist
- The structural fix (EventID correlation) lives in the replacement rule
- `deprecate` creates a versioned tombstone explaining *why* the rule was retired and *where to go next*

## Files

| File | Purpose |
|------|---------|
| `sigma-rule.yml` | Vendored Sigma rule (status: deprecated in the rule itself) |
| `ddr.yml` | The Detection Decision Record |

## Key design notes

- `lifecycle.status: retired` — the DDR is itself retired, matching the rule's deprecated status
- `replacement_rule_id` points to the v2 rule UUID — consumers can look it up
- `superseded_by` in the lifecycle points to the DDR record for the v2 rule
- `retirement_reason: replaced` — explicit enum value, not a free-text field
- No `sigma-filter.yml` — `deprecate` decisions do not export filters
