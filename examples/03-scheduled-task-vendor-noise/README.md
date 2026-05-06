# Example 03 — Scheduled Task Vendor Noise

**Archetype:** Windows event log FP from known-benign software vendors  
**Decision:** `suppress`  
**Rule:** Suspicious Scheduled Task Creation (Windows `process_creation`)

## Scenario

Adobe Acrobat, Microsoft Teams, and CrowdStrike create scheduled tasks during installation and updates. These fire ~15 alerts/day. The vendor binaries live under `C:\Program Files\` — a path standard users cannot write to without elevation.

Suppression filters by `ParentImage|startswith` for vendor install paths. Attacker-created scheduled tasks typically originate from `%TEMP%`, `%APPDATA%`, or shell parents — none of which are covered by this filter.

## Files

| File | Purpose |
|------|---------|
| `sigma-rule.yml` | Vendored Sigma rule |
| `ddr.yml` | The Detection Decision Record |
| `sigma-filter.yml` | Exported Sigma Filter |

## Key design notes

- Multiple vendor path prefixes in one selection block (`known_fp_vendor_paths`)
- `review_cadence_days: 90` — shorter cadence because vendor paths change with software updates
- Rationale explicitly states **why** Program Files is a safe filter anchor (requires admin elevation to write)
- Two reviewers signed off — high-volume rule warrants a second pair of eyes

## Reproducing the filter export

```bash
ddr export-sigma-filter ddr.yml
```
