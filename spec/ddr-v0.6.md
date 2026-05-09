# DDR Spec — v0.6

**Status:** Released
**Date:** 2026-05-08
**Schema:** `spec/ddr-v0.6.schema.json`
**Back-compat:** All v0.1, v0.2, v0.3, v0.4, v0.5 records validate unchanged.

---

## Changes from v0.5

### 1. Elastic Security target (`target.kind: "elastic"`)

New target kind for Elastic Security detection rules (EQL, KQL, threshold, etc.).
Follows the v0.5 plural-refs shape from day one — no coercion shim needed.

**`ElasticQueryRef`** fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `rule_id` | string | yes | Elastic detection rule ID (UUID; string type to accommodate format variations across Elastic versions) |
| `name` | string | yes | Elastic rule display name |
| `index_pattern` | string | yes | Data stream pattern, e.g. `logs-endpoint.events.process-*` |
| `content_hash` | string | no | `sha256:<64 hex>` — computed by Elastic canonicalization algorithm v1 |
| `path_or_url` | string | no | Local NDJSON path or Kibana API URL |
| `source` | enum | yes | `sigmahq` \| `internal` \| `vendor` |

**`ElasticTarget`** — discriminated on `kind: "elastic"`:

```yaml
target:
  kind: elastic
  query_refs:
    - rule_id: "96b9fc2a-cbd5-4a3e-b7d7-3d9d6a6e8d5c"
      name: "Windows Defender Antivirus Threats Detected"
      index_pattern: "logs-endpoint.events.process-*"
      content_hash: "sha256:<64 hex>"
      source: internal
      path_or_url: "rules/elastic/windows-defender-av.ndjson"
```

`query_refs` minimum length is 1. An empty list is a schema error.

---

### 2. Elastic tuning (`tuning.kind: "elastic"`)

New tuning kind for Elastic suppress decisions. Parallel to `SplunkTuning`.

**`ElasticTuning`** fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `kind` | literal | yes | `"elastic"` |
| `kql_filter` | string | yes | Raw KQL filter clause (FP condition). Must not be empty or whitespace. |
| `filter_title` | string | no | Used as the exception list item name. Falls back to DDR title. |
| `filter_description` | string | no | Included in the exception item description. |

**Example:**

```yaml
tuning:
  kind: elastic
  filter_title: "Suppress Nessus scanner AV alerts"
  kql_filter: 'source.ip : "10.0.100.0/24" and agent.name : nessus*'
```

Cross-field constraint: when `decision.kind == "suppress"`, `tuning.kind` must equal
`target.kind`. An Elastic target requires Elastic tuning.

---

### 3. Elastic canonicalization algorithm v1

Used by `content_hash` to produce a stable hash of an Elastic detection rule
NDJSON file. Answers one question: *"has this rule's detection logic changed since
the DDR was authored?"*

**Steps:**

1. **Load NDJSON.** Read the file, find the first non-empty line that parses as a
   JSON object.
2. **Unwrap.** If the top-level object has a `"rule"` key (Kibana Rules API GET
   format), extract `obj["rule"]`.
3. **Strip volatile fields.** Remove fields that Kibana updates on import/export
   or on prebuilt rule version bumps, without changing rule logic:
   `created_at`, `updated_at`, `created_by`, `updated_by`, `revision`,
   `version`, `id`, `immutable`, `related_integrations`, `required_fields`,
   `setup`.
4. **Sort keys recursively.** Deterministic key order regardless of insertion order.
5. **Serialize.** `json.dumps(rule, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
6. **Hash.** UTF-8 encode → SHA-256 → `sha256:` prefix.

**Rationale for stripping volatile fields:** Elastic prebuilt rule library updates
increment `revision` and `version` even for cosmetic changes. Stripping them means
`content_hash` tracks rule logic (`query`, `filters`, `threat`, `severity`),
not Elastic's internal bookkeeping.

---

### 4. `ddr export-elastic-exception` command (new)

Emits a Kibana 8.x-importable exception list item NDJSON from a suppress DDR record.

```
ddr export-elastic-exception <ddr.yml> [--output <file.ndjson>] [--list-id <str>]
```

**Requirements:** `target.kind == "elastic"` and `decision.kind == "suppress"`.
Exits 1 with a clear error if either constraint is not met.

**KQL parsing (best-effort):**

The parser handles simple AND-chains of field-condition pairs:

| KQL pattern | Entry type |
|---|---|
| `field.name : "value"` | `match` |
| `field.name : wildcard*` | `wildcard` |
| `cond1 and cond2` | two entries (both must match) |

Anything more complex (OR, NOT, nested parentheses, functions) produces a
`MANUAL:` warning on stderr and an empty `entries: []` in the output. The
raw `kql_filter` is always preserved in the item's `description` field for
human review.

**Output format:** One NDJSON line per DDR record, compatible with Kibana's
**Security → Rules → Exception Lists → Import** workflow.

---

### 5. `ddr new` updates

`--target elastic` option added. If the positional argument is a `.ndjson` file,
`--target elastic` is inferred automatically.

When a valid NDJSON is provided, `ddr new` extracts `rule_id` and `name` from
the first parseable rule object. Falls back to placeholders if parsing fails.

Scaffold includes:
- `query_refs: [...]` (plural, consistent with v0.5)
- `filter_title` placeholder in tuning block (prevents double-prefix in export)
- `kql_filter` placeholder with example syntax

---

### 6. `ddr refresh-hash` (Elastic branch)

Iterates `target.query_refs`. For each ref:
- Loads NDJSON from `path_or_url`
- Applies canonicalization algorithm v1
- Prints per-ref old/new hash
- Skips refs without `path_or_url` or with remote URLs (with a note)

`--rule` override is restricted to single-ref records. Multi-ref Elastic DDRs
must update `path_or_url` in each ref directly.

---

### 7. `ddr validate --strict` (Elastic drift check)

Warns per-ref when `content_hash` doesn't match the local NDJSON file.
Warns when ref count > 10 (same advisory as Sigma/Splunk).

---

## Unchanged from v0.5

- `SigmaTarget` / `SigmaQueryRef` — no change.
- `SplunkTarget` / `SplunkQueryRef` — no change.
- `SigmaTuning` / `SplunkTuning` — no change.
- `Decision` union (`suppress`, `accept-risk`, `deprecate`) — no change.
- `Lifecycle` model — no change.
- `Provenance` / `Evidence` / `Scope` / `extensions` — no change.
- Sigma canonicalization algorithm v1 — no change.
- SPL canonicalization algorithm v1 — no change.
- `export-sigma-filter` — exits 1 on Elastic targets (unchanged).
- `export-splunk` — exits 1 on non-suppress decisions (unchanged).
- `expire-check` / `list` — work unchanged; `list` shows `elastic` in TARGET column.

---

## Migration: v0.1–v0.5 → v0.6

**No action required.** All existing records validate unchanged.
`ddr_version` pattern now accepts `"0.6"`. Records with `"0.1"` through `"0.5"`
remain valid.

To use Elastic-native DDRs, set `ddr_version: "0.6"` in new records.
