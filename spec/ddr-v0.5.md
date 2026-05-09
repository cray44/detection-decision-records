# DDR Spec — v0.5

**Status:** Released  
**Date:** 2026-05-08  
**Schema:** `spec/ddr-v0.5.schema.json`  
**Back-compat:** All v0.1, v0.2, v0.3, v0.4 records validate unchanged.

---

## Changes from v0.4

### 1. Multi-rule targeting — plural refs

`target.kind = "sigma"` now carries `rule_refs: list[RuleRef]` (minimum length 1) instead of the singular `rule_ref: RuleRef`.

`target.kind = "splunk"` now carries `query_refs: list[SplunkQueryRef]` (minimum length 1) instead of the singular `query_ref: SplunkQueryRef`.

**Example — three refs:**

```yaml
target:
  kind: sigma
  rule_refs:
    - rule_id: a1f2e3d4-0000-0001-0000-000000000001
      content_hash: sha256:<64 hex>
      source: internal
      path_or_url: rules/wmi-process.yml
    - rule_id: b2f3e4d5-0000-0002-0000-000000000002
      content_hash: sha256:<64 hex>
      source: internal
      path_or_url: rules/wmi-registry.yml
    - rule_id: c3f4e5d6-0000-0003-0000-000000000003
      content_hash: sha256:<64 hex>
      source: internal
      path_or_url: rules/wmi-network.yml
```

#### Back-compat: singular `rule_ref` / `query_ref`

v0.1–v0.4 records that use the singular field names continue to load without modification. The parser coerces `rule_ref: {...}` to `rule_refs: [{...}]` transparently. No file edits are required.

Records written by v0.5 tooling always emit the plural form.

#### Constraint: minimum one ref

`rule_refs: []` and `query_refs: []` are schema errors. Every DDR must target at least one rule or savedsearch.

#### Soft limit: >10 refs triggers a warning

`ddr validate --strict` warns when a record has more than 10 refs. This is advisory — it encourages splitting large retirement clusters into smaller, more reviewable decisions. It is not a validation failure.

---

### 2. `ddr list` command

New read-only summary command. Always exits 0.

```
ddr list <path> [--status draft|active|retired]
                [--target sigma|splunk|...]
                [--decision suppress|accept-risk|deprecate]
                [--expired] [--due]
                [--format table|json]
```

**Table output columns:** `STATUS | TARGET | DECISION | REFS | ID | TITLE`

The `REFS` column shows the number of entries in `rule_refs` or `query_refs`. Expired records are annotated `[EXPIRED]`; overdue-for-review records are annotated `[DUE]`.

`--expired` and `--due` are filters (subset of rows), not standalone checks. They do not cause a non-zero exit code. Use `ddr expire-check` for CI gating.

---

### 3. CLI changes

| Command | Change |
|---|---|
| `ddr new` | Scaffold emits `rule_refs: [...]` / `query_refs: [...]` (plural). |
| `ddr refresh-hash` (sigma) | Iterates all `rule_refs`. Prints per-ref old/new. `--rule` override requires single ref; fails with a clear error on multi-ref records. |
| `ddr refresh-hash` (splunk) | Iterates all `query_refs`. `--conf` override requires single ref. |
| `ddr validate --strict` | Drift check iterates all `query_refs`, warns per-ref. New: warns when ref count > 10. |
| `ddr list` | New command (see §2). |

---

## Unchanged from v0.4

- `tuning` models (`SigmaTuning`, `SplunkTuning`) — no change.
- `Decision` union (`suppress`, `accept-risk`, `deprecate`) — no change.
- `Lifecycle` model — no change.
- `Provenance` / `Evidence` / `Scope` / `extensions` — no change.
- Content hash algorithm (`sha256:` prefix, canonicalization algorithm v1) — no change.
- SPL canonicalization algorithm v1 — no change.
- `export-sigma-filter` export format — no change (now includes all rule IDs in `filter.rules`).
- `export-splunk` — no change.
- `expire-check` — no change.

---

## Migration: v0.1–v0.4 → v0.5

**No action required.** All existing records validate unchanged. The CLI coerces singular `rule_ref` / `query_ref` fields on load.

Optional: update records to use the plural form for clarity. Change:

```yaml
target:
  kind: sigma
  rule_ref:
    rule_id: ...
```

to:

```yaml
target:
  kind: sigma
  rule_refs:
    - rule_id: ...
```

and bump `ddr_version` to `"0.5"`.
