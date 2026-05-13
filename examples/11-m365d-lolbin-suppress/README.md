# Example 11 — M365D LOLBin suppress (IT admin service accounts)

**Target:** M365D Advanced Hunting custom detection  
**Decision:** suppress  
**Tuning:** `kusto_filter` — Kusto `has_any` to exclude IT admin service accounts

## Rule

Custom M365D Advanced Hunting detection: "LOLBin — regsvr32.exe with suspicious parent"  
Detects `regsvr32.exe` spawned by an unusual parent process — a common LOLBin abuse technique for bypassing application control.

## Why this FP

IT admin service accounts `svc-patching` and `svc-deploy` call `regsvr32.exe` to install an approved COM component (`CorpPatchAgent.dll`) during the weekly patch deployment cycle. The activity pattern matches this detection exactly but is fully authorized and documented in change management.

## Files

| File | Purpose |
|---|---|
| `m365d-detection.json` | M365D custom detection JSON export (volatile fields present; stripped during canonicalization) |
| `ddr.yml` | DDR record — suppress decision with `kusto_filter` |
| `m365d-exclusion.kql` | Exported Kusto fragment (`ddr export-kql ddr.yml`) |

## Export

```
ddr export-kql ddr.yml
```

Paste the `| where not (...)` line into the detection's `queryCondition` to exclude the authorized service accounts.

## Hash refresh

```
ddr refresh-hash ddr.yml
```

Re-run after any change to `m365d-detection.json` to verify rule logic hasn't drifted.
