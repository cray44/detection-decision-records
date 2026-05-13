# DDR Spec — v0.7 (KQL Targets)

**Status:** Released  
**Date:** 2026-05-13  
**Theme:** Complete the four-SIEM target union — Microsoft Sentinel and M365D Advanced Hunting

---

## 1. Overview

v0.7 adds two new target kinds: `"kql-sentinel"` and `"kql-m365d"`. Together with `"sigma"`, `"splunk"`, and `"elastic"` (established in v0.1–v0.6), DDR can now govern FP-tuning decisions across all four major SIEM/XDR platforms from a single record format.

The field `kusto_filter` is used (not `kql_filter`) to disambiguate Kusto Query Language (Sentinel/M365D) from Elastic's Kibana Query Language (`kql_filter`). Both KQL-target kinds share the same exporter (`ddr export-kql`) because the output format — a Kusto `| where not (...)` fragment — is identical.

All v0.1–v0.6 records validate unchanged under v0.7.

---

## 2. New Models

### `KqlSentinelQueryRef`

```yaml
rule_id: string         # ARM resource name or GUID (required)
name: string            # Display name (required)
workspace: string|null  # Log Analytics workspace name (optional context)
content_hash: string|null  # sha256:<64 hex> (optional)
path_or_url: string|null   # local path to ARM export JSON or Sentinel API response
source: RuleSource
```

### `KqlSentinelTarget`

```yaml
kind: kql-sentinel      # discriminator
query_refs:             # list[KqlSentinelQueryRef], min length 1
  - ...
```

### `KqlSentinelTuning`

```yaml
kind: kql-sentinel      # discriminator — must match target.kind
filter_title: string|null
filter_description: string|null
kusto_filter: string    # required, non-empty Kusto WHERE clause
```

### `KqlM365DQueryRef`

Same structure as `KqlSentinelQueryRef`; `table` (str | None) replaces `workspace` to capture the primary Advanced Hunting table (e.g., `DeviceProcessEvents`).

### `KqlM365DTarget` / `KqlM365DTuning`

Same structure as Sentinel counterparts with `kind: "kql-m365d"`.

---

## 3. Sentinel Canonicalization Algorithm v1

Used by `KqlSentinelQueryRef.content_hash`.

1. Load JSON from `path_or_url` (local path only; remote URLs are skipped).
2. If the top-level object has a `"properties"` key (ARM resource envelope), extract `obj["properties"]` and strip envelope-level keys: `id`, `name`, `type`, `systemData`.
3. Strip volatile Sentinel/ARM body fields: `etag`, `lastModifiedUtc`, `lastRunTime`, `nextRunTime`, `lastDeploymentStatusMessage`, `lastDeploymentStatus`, `alertRuleTemplateName`, `templateVersion`.
4. Sort mapping keys recursively.
5. Serialize to compact JSON: `json.dumps(rule_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
6. UTF-8 encode → SHA-256 → `sha256:` prefix.

**Rationale:** `lastModifiedUtc`, `lastRunTime`, `nextRunTime` change on every rule execution. `etag` changes on every ARM save. The algorithm tracks rule logic (`query`, `severity`, `triggerOperator`, `triggerThreshold`, `suppressionDuration`, threat intelligence fields) — not Sentinel's bookkeeping.

---

## 4. M365D Canonicalization Algorithm v1

Used by `KqlM365DQueryRef.content_hash`.

1. Load JSON from `path_or_url` (local path only).
2. If top-level is an array (bulk export), use first element and print a note to stderr.
3. Strip volatile Defender/Graph API fields: `id`, `createdDateTime`, `lastModifiedDateTime`, `lastRunTime`, `nextRunTime`, `isEnabled`, `createdBy`, `lastModifiedBy`.
4. Sort mapping keys recursively.
5. Serialize to compact JSON → UTF-8 → SHA-256 → `sha256:` prefix.

**Rationale:** `lastModifiedDateTime` and `lastRunTime` change on every scheduled execution. `isEnabled` toggles without changing rule logic. The algorithm tracks `queryCondition`, `detectionAction`, `severity`, and `mitreTechniques`.

---

## 5. `ddr export-kql`

```
ddr export-kql <ddr.yml> [--output <file.kql>]
```

- Validates DDR; exits 1 if `target.kind` is not `"kql-sentinel"` or `"kql-m365d"`.
- Exits 1 with clear error if `decision.kind != "suppress"`.
- Outputs a Kusto exclusion fragment:

```kusto
// DDR: <ddr.title>
// Rationale: <decision.rationale (first 120 chars)>
// Expires: <lifecycle.expires_on>
| where not (<tuning.kusto_filter>)
```

- If `--output` is given, writes to that file; otherwise prints to stdout.
- `kusto_filter` is emitted as-is — no parsing. The engineer is responsible for its correctness; DDR is governance, not a Kusto parser.

---

## 6. `ddr new --target kql-sentinel / kql-m365d`

- `--target kql-sentinel` and `--target kql-m365d` are now valid options.
- No extension inference (both Sentinel ARM exports and M365D API exports are `.json`; ambiguous with Elastic). Explicit `--target` flag required.
- If a source JSON file is provided, `rule_id` and `name` are extracted; falls back to placeholder values.

---

## 7. `ddr refresh-hash` (KQL branches)

Iterates `query_refs` for both KQL target kinds. For each ref with a local `path_or_url`:
- Applies the appropriate canonicalization algorithm (Sentinel v1 or M365D v1).
- Prints per-ref drift status.
- Writes updated hashes.

`--rule` override applies to single-ref targets only (consistent with all other target kinds).

---

## 8. `ddr validate --strict` (KQL drift check)

Drift check now covers `kql-sentinel` and `kql-m365d` targets. Warns per-ref on hash drift. Warns if ref count > 10.

---

## 9. Version Pattern

`ddr_version` pattern updated from `^0\.[123456]$` to `^0\.[1234567]$`.

Records with `"0.1"` through `"0.6"` remain valid.

---

## 10. Back-Compat Notes

- No existing field removed or renamed. v0.1–v0.6 records validate unchanged.
- `export-sigma-filter`, `export-splunk`, and `export-elastic-exception` all correctly exit 1 on KQL targets.
- `export-kql` exits 1 on non-KQL targets.
