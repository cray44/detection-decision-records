# Example 10 — Sentinel brute-force suppress (authorized red team)

**Target:** Microsoft Sentinel Analytics Rule  
**Decision:** suppress  
**Tuning:** `kusto_filter` — Kusto `has_any` to exclude red team IP range

## Rule

[Sign-ins from IPs that attempt sign-ins to disabled accounts](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/SigninAttempts_UnknownUser.yaml)  
Detects IPs with a high volume of failed sign-ins to disabled accounts — a brute-force / password spray indicator.

## Why this FP

The corporate red team operates from a dedicated IP range (`10.50.0.0/16`) under an approved Rules of Engagement. During scheduled pentest windows they generate exactly the sign-in pattern this rule targets. Alerts during those windows are authorized FPs.

## Files

| File | Purpose |
|---|---|
| `sentinel-rule.json` | ARM export of the Sentinel Analytics Rule (volatile fields present; stripped during canonicalization) |
| `ddr.yml` | DDR record — suppress decision with `kusto_filter` |
| `sentinel-exclusion.kql` | Exported Kusto fragment (`ddr export-kql ddr.yml`) |

## Export

```
ddr export-kql ddr.yml
```

Paste the `| where not (...)` line into the Sentinel rule's KQL query to exclude the red team IP range.

## Hash refresh

```
ddr refresh-hash ddr.yml
```

Re-run after any change to `sentinel-rule.json` to verify the rule logic hasn't drifted.
