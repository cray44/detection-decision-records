# Example 08 — Multi-Rule Deprecation (WMI Lateral Movement Cluster)

**Decision kind:** `deprecate`  
**Target kind:** `sigma` — three rule refs  
**DDR version:** `0.5`

## Scenario

A detection team accumulated three overlapping WMI detection rules over the years:

| Rule | Category | Sigma ID |
|---|---|---|
| `sigma-rule-wmi-process.yml` | `process_creation` | `a1f2e3d4-...` |
| `sigma-rule-wmi-registry.yml` | `registry_event` | `b2f3e4d5-...` |
| `sigma-rule-wmi-network.yml` | `network_connection` | `c3f4e5d6-...` |

All three fire on the same WMI lateral movement activity. They had overlapping FP classes (SCCM agents, monitoring tools) that were being tuned separately, creating duplicate suppression records and inconsistent coverage.

A consolidated replacement rule `win_wmi_consolidated_lateral_movement.yml` was written to cover all three variants in a single detection with a tighter, unified FP filter.

This DDR records the governance decision to retire the three legacy rules as a single action — one record, one approval, one ticket. Without multi-rule targeting (v0.5+), three separate DDRs would have been required.

## Usage

```bash
# Validate
ddr validate ddr.yml

# List: shows 3 in the REFS column
ddr list .

# Check hashes are current (rules are static in this example)
ddr refresh-hash ddr.yml
```

## What multi-rule targeting adds

Before v0.5, `target` held a single `rule_ref`. The v0.5 change to `rule_refs: [...]` makes this pattern explicit in the schema and allows `ddr list` to surface the ref count, `ddr refresh-hash` to iterate all refs in one pass, and `ddr validate --strict` to warn on per-ref hash drift.

## Key fields

```yaml
target:
  kind: sigma
  rule_refs:        # plural — all three rules in one record
    - rule_id: ...
    - rule_id: ...
    - rule_id: ...
decision:
  kind: deprecate
  replacement_rule_id: d4f5e6a7-...   # points to the consolidated replacement
```
