# DDR Spec v0.1

> **Status:** Implemented. Schema generated from `src/ddr/models/record.py`; machine-readable JSON Schema at `ddr-v0.1.schema.json`.

Detection Decision Records (DDR) is a governance format for post-deployment decisions about Sigma detection rules. It answers: *who suppressed this, why, until when, and how to tell if it's still right.*

## 1. Scope

DDR v0.1 records **post-deployment governance decisions** about Sigma detection rules: suppressions, accepted-risk acknowledgments, and deprecations. v0.1 is Sigma-coupled; multi-format support (Splunk-native, Elastic) is v0.2+ scope.

**Non-goals (v0.1):** UI, database backend, pre-deployment decisions, analytics, multi-tenant storage.

## 2. Top-level fields

| Field | Required | Type | Notes |
|-------|----------|------|-------|
| `ddr_version` | yes | `"0.1"` (string) | Quote in YAML: `ddr_version: "0.1"` |
| `id` | yes | UUID | DDR's own ID, distinct from the Sigma rule ID |
| `target` | yes | object | `kind: "sigma"` is the only valid value in v0.1 |
| `title` | yes | string | Human-readable label |
| `description` | yes | string | Context; no raw log samples (see §7) |
| `decision` | yes | discriminated union | `suppress \| accept-risk \| deprecate` |
| `lifecycle` | yes | object | See §6 |
| `provenance` | yes | object | See §7 |
| `scope` | no | object | `environments[]`, `data_sources[]` |
| `extensions` | no | object | `x-*` prefixed keys only |

Extra top-level fields are rejected (`additionalProperties: false`).

## 3. Decision semantics

Three decision kinds, each with distinct operational outcome:

### `suppress`
Excludes known-benign matches via an exportable Sigma Filter. The workhorse — expected ~80% of records.

- **Has** a `tuning` block (required).
- `ddr export-sigma-filter` produces a Sigma Filter YAML from the tuning block.
- Use when you can write a field-level filter that separates the FP from the TP.

### `accept-risk`
FP exists but cannot be filtered; risk is accepted explicitly.

- **No** tuning block.
- `expires_on` in the lifecycle is **required** — no immortal risk acceptances.
- Use when the FP is structurally indistinguishable from a true positive at the field level.

### `deprecate`
Rule retirement tombstone.

- **No** tuning block.
- Optional `replacement_rule_id` (UUID of the successor rule).
- Use when a rule is being removed and you want a versioned record explaining why.

## 4. Tuning IR

The `tuning` block is a DDR-native IR that is **losslessly exportable to a Sigma Filter** for all v0.1 content.

```yaml
tuning:
  filter_title: "Optional override for the exported filter title"
  filter_description: "Optional description for the exported filter"
  logsource:            # mirrors Sigma logsource — at least one of category/product/service
    category: process_creation
    product: windows
  selections:           # named selection blocks (mirrors Sigma filter: blocks)
    selection_name:
      FieldName|modifier:
        - value1
        - value2
  condition: "not selection_name"   # Sigma filter condition string
```

### Export lowering

`ddr export-sigma-filter` maps the tuning block to a Sigma Filter document:

| DDR tuning field | Sigma Filter field |
|------------------|--------------------|
| `filter_title` (or auto-generated) | `title` |
| `filter_description` (or `description`) | `description` |
| `logsource` | `logsource` |
| `target.rule_ref.rule_id` | `rules[0]` |
| `selections` | `filter` |
| `condition` | `condition` |

## 5. Rule reference and content hashing

```yaml
target:
  kind: sigma
  rule_ref:
    rule_id: <sigma-rule-uuid>       # required: Sigma rule's own ID
    content_hash: sha256:<hex>       # required: see algorithm below
    source: sigmahq | internal | vendor
    path_or_url: <locator>           # URL or local path
    commit: <optional metadata>      # human-readable, not used by validation
```

### Canonicalization algorithm v1

`content_hash` is computed as follows:

1. Load the Sigma rule with a **safe YAML loader** (strips comments).
2. **Sort mapping keys recursively** (deterministic key order).
3. Dump to UTF-8 string with deterministic YAML style.
4. **Normalize line endings** to LF (`\n`).
5. SHA-256 the UTF-8 bytes.
6. Prefix with `sha256:`.

Format: `sha256:<64 lowercase hex chars>`

**Implication:** Cosmetic changes (comment edits, whitespace) do **not** change the hash (comments are stripped in step 1). Semantic changes (field values, new fields) do change it. Use `ddr refresh-hash` to update after a confirmed cosmetic-only upstream change.

## 6. Lifecycle

### Stored states

| State | Meaning |
|-------|---------|
| `draft` | Created, not yet active in production |
| `active` | Live in production |
| `retired` | Removed from production |

`expired` and `due-for-review` are **computed** by `ddr expire-check` from dates — not stored.

### Fields

| Field | Required | Notes |
|-------|----------|-------|
| `status` | yes | `draft \| active \| retired` |
| `created_on` | yes | RFC 3339 datetime |
| `activated_on` | if status is `active` or `retired` | When record went live |
| `retired_on` | if status is `retired` | |
| `expires_on` | **required if status is `active`** | No immortal suppressions |
| `review_cadence_days` | no | If set, `expire-check` flags `last_reviewed_on + cadence < today` |
| `last_reviewed_on` | no | Date of last human review |
| `superseded_by` | no | DDR UUID of the replacement; only valid when `retired` |
| `retirement_reason` | no | `rule-deprecated \| fp-source-removed \| replaced \| other`; only valid when `retired` |

### State transitions

```
draft → active    (records activated_on)
active → retired  (records retired_on; optionally superseded_by)
draft → retired   (rare: decided not to deploy)
```

## 7. Provenance and evidence

```yaml
provenance:
  author: user@example.com       # required
  reviewers: []                  # optional list
  approved_by: null              # optional; advisory, not enforced
  ticket_refs: []                # optional list (Jira, ServiceNow, etc.)
  evidence: []                   # optional list
```

### Evidence

Evidence is **by-reference only**. The schema rejects inline content fields.  
*"DDRs reference evidence; they don't contain it."*

```yaml
evidence:
  - type: splunk_query | log_sample_uri | ticket | runbook | dashboard | pcap | other
    ref: "<URL, file path, ticket ID, S3 URI>"
    note: "<required: one sentence explaining what this evidence shows>"
```

`note` is required. If you can't say in one sentence what the evidence shows, it isn't evidence.

## 8. Extensibility

`extensions` accepts `x-*` prefixed keys only. Other keys are rejected at validation time.

```yaml
extensions:
  x-vendor-classification: "low-priority"
  x-siem-target: "splunk-es"
```

## 9. Versioning

- The spec is versioned independently from the CLI.
- Within a major version, changes are **additive only** (new optional fields).
- Removing or repurposing a field requires a major bump and a documented migration.
- The CLI ships migration shims for one major version back, minimum.
- `ddr_version` must be quoted in YAML (e.g., `"0.1"` not `0.1`) to avoid YAML float parsing.
