# DDR Spec Changelog

## [0.7.1] — 2026-05-28

### Added
- `LATEST_DDR_VERSION` constant in `cli.py` (single source of truth for scaffolded `ddr_version`).
- `--source-url` flag on `ddr new` + automatic relative `path_or_url` logic across all target kinds (UX-01).
- Per-target regression tests for the new path handling.

### Changed
- All `ddr new` scaffolds now emit the current latest version via the constant (no more scattered hardcoded strings).
- `qa/QA-FINDINGS.md` updated with "Closed in v0.7.1" section.

### Fixed
- SCHEMA-01: `evidence.type` now accepts `"note"`.
- SCHEMA-02: `deprecate` + `status: active` no longer requires `expires_on`.
- UX-03: reproduction confirmed current `--strict` regex no longer false-positives on bare infrastructure IPs in prose.

## [0.7.0] — 2026-05-13

Additive schema change. All v0.1–v0.6 records validate unchanged.

### Added
- `ddr_version` pattern updated to `^0\.[1234567]$`; records with `"0.1"`–`"0.6"` remain valid.
- **KQL targets**: `target.kind: "kql-sentinel"` and `"kql-m365d"` — new `KqlSentinelTarget`, `KqlM365DTarget` with `query_refs: list[...]` (plural shape, min length 1).
- **`KqlSentinelQueryRef`**: `rule_id` (ARM name or GUID), `name`, optional `workspace`, optional `content_hash` (`sha256:<64 hex>`), optional `path_or_url`, `source`.
- **`KqlM365DQueryRef`**: same shape; optional `table` instead of `workspace` (primary Advanced Hunting table).
- **`KqlSentinelTuning` / `KqlM365DTuning`**: `kind`, `kusto_filter` (Kusto WHERE clause, required non-empty), optional `filter_title`, optional `filter_description`.
- **`kusto_filter` not `kql_filter`**: disambiguates Kusto (Sentinel/M365D) from Elastic's Kibana Query Language (`kql_filter` on `ElasticTuning`).
- **Sentinel canonicalization algorithm v1** (`spec/ddr-v0.7.md §3`): unwrap ARM envelope → strip volatile fields (`etag`, `lastModifiedUtc`, `lastRunTime`, `nextRunTime`, `lastDeploymentStatus*`, `alertRuleTemplateName`, `templateVersion`, envelope `id`/`name`/`type`/`systemData`) → sort keys → compact JSON → SHA-256 → `sha256:` prefix.
- **M365D canonicalization algorithm v1** (`spec/ddr-v0.7.md §4`): handle array bulk export (first element) → strip volatile fields (`id`, `createdDateTime`, `lastModifiedDateTime`, `lastRunTime`, `nextRunTime`, `isEnabled`, `createdBy`, `lastModifiedBy`) → sort keys → compact JSON → SHA-256 → `sha256:` prefix.
- **`ddr export-kql`**: emits Kusto `| where not (<kusto_filter>)` fragment with DDR title, rationale snippet, and expiry in comments. Handles both `kql-sentinel` and `kql-m365d` targets. Exits 1 on non-KQL targets and non-suppress decisions.
- **`ddr new --target kql-sentinel/kql-m365d`**: scaffolds DDR with `kusto_filter` placeholder. No `.json` extension inference (ambiguous with Elastic). Extracts `rule_id` and `name` from source JSON if provided.
- **`ddr refresh-hash`** (KQL branches): iterates `query_refs`, applies appropriate algorithm, prints per-ref drift status.
- **`ddr validate --strict`** (KQL drift check): warns per-ref on hash drift for both KQL kinds; warns on ref count > 10.

### Back-compat notes
- v0.1–v0.6 records using `target.kind: "sigma"`, `"splunk"`, or `"elastic"` continue to parse without modification.
- `export-sigma-filter`, `export-splunk`, and `export-elastic-exception` all exit 1 on KQL targets (same existing behavior for non-matching target kinds).

## [0.6.0] — 2026-05-08

Additive schema change. All v0.1, v0.2, v0.3, v0.4, and v0.5 records validate unchanged.

### Added
- `ddr_version` pattern updated to `^0\.[123456]$`; records with `"0.1"`–`"0.5"` remain valid.
- **Elastic target**: `target.kind: "elastic"` — new `ElasticTarget` with `query_refs: list[ElasticQueryRef]`
  (min length 1, plural shape inherited from v0.5 from day one — no coercion shim needed).
- **`ElasticQueryRef`**: `rule_id` (string), `name`, `index_pattern`, optional `content_hash`, optional
  `path_or_url`, `source`.
- **`ElasticTuning`**: `kind: "elastic"`, `kql_filter` (raw KQL filter clause, required non-empty),
  optional `filter_title`, optional `filter_description`.
- **Elastic canonicalization algorithm v1** (`spec/ddr-v0.6.md §3`): load NDJSON → unwrap `rule` key →
  strip volatile fields (`revision`, `version`, `created_at`, `updated_at`, `created_by`, `updated_by`,
  `id`, `immutable`, `related_integrations`, `required_fields`, `setup`) → sort keys → compact JSON →
  SHA-256 → `sha256:` prefix.
- **`ddr export-elastic-exception`**: emits Kibana 8.x-importable exception list NDJSON. Simple AND-chains
  of `field : "value"` / `field : wildcard*` conditions → structured `entries[]`. Complex KQL → MANUAL
  warning + raw KQL preserved in `description`.
- **`ddr new --target elastic`**: NDJSON inference from `.ndjson` extension; extracts `rule_id` and `name`.
- **`ddr refresh-hash`** (Elastic branch): iterates `query_refs`, applies algorithm v1, prints per-ref.
- **`ddr validate --strict`** (Elastic drift check): warns per-ref on hash drift; warns on ref count > 10.

### Back-compat notes
- v0.1–v0.5 records using `target.kind: "sigma"` or `"splunk"` continue to parse without modification.
- `export-sigma-filter` exits 1 on Elastic targets (same behavior as Splunk targets).
- `export-splunk` exits 1 on Elastic targets (no Splunk export path for Elastic rules).

## [0.5.0] — 2026-05-08

Additive schema change. All v0.1, v0.2, v0.3, and v0.4 records validate unchanged.

### Added
- `ddr_version` pattern updated to `^0\.[12345]$`; records with `"0.1"`–`"0.4"` remain valid.
- **Multi-rule targeting**: `SigmaTarget.rule_refs: list[RuleRef]` (replaces singular `rule_ref`);
  `SplunkTarget.query_refs: list[SplunkQueryRef]` (replaces singular `query_ref`). Minimum length 1.
  Back-compat: singular `rule_ref` / `query_ref` fields in existing records are coerced on load.
- **`ddr list` command**: read-only summary of DDRs by status/target/decision; `REFS` column shows
  ref count; `--format json` for scripting.

### Back-compat notes
- v0.1–v0.4 records using singular `rule_ref` or `query_ref` continue to parse without modification.
  The coercion shim runs at load time; no file edits are required.
- `export-sigma-filter` `filter.rules` list now contains all rule IDs from `rule_refs` (previously
  always one). Single-ref records are unaffected.

## [0.4.0] — 2026-05-06

Additive schema change. All v0.1, v0.2, and v0.3 records validate unchanged.

### Added
- `ddr_version` pattern updated to `^0\.[1234]$`; records with `"0.1"`, `"0.2"`, `"0.3"` remain valid.
- **SPL canonicalization algorithm v1** (`spec/ddr-v0.4.md §6`): strip BOM → CRLF→LF → join
  backslash-continuations → drop comment lines → collapse whitespace → trim → SHA-256 → `sha256:` prefix.
  No keyword lowercasing (preserves field-value semantics).
- **savedsearches.conf parsing spec** (`spec/ddr-v0.4.md §7`): formalizes dialect quirks — BOM, CRLF,
  continuation, `[default]` skip, duplicate-key last-wins, app inference from path.
- **query_hash drift check** (`spec/ddr-v0.4.md §8`): drift is a warning, not a failure; skipped for
  remote `path_or_url`.

### Back-compat notes
- `query_hash` was already an optional field on `SplunkQueryRef` in v0.3. v0.4 formalizes how it is
  computed and refreshed — no structural schema change.

## [0.3.0] — 2026-05-06

Additive schema change. All v0.1 and v0.2 records validate unchanged.

### Added
- `target` is now a discriminated union on `kind`: `"sigma"` (existing) | `"splunk"` (new).
- New `SplunkTarget`: `kind: "splunk"`, `query_ref` (`SplunkQueryRef`).
- New `SplunkQueryRef`: `name` (stanza name), `app` (Splunk app), optional `query_hash` (`sha256:<64 hex>`), optional `path_or_url`.
- `tuning` (inside `suppress` decision) is now a discriminated union on `kind`: `"sigma"` (existing) | `"splunk"` (new).
- New `SplunkTuning`: `kind: "splunk"`, `splunk_filter` (raw SPL filter clause, required non-empty), optional `filter_title`, optional `filter_description`.
- Cross-field validator: when `decision.kind == "suppress"`, `tuning.kind` must equal `target.kind`.
- `ddr_version` pattern updated to `^0\.[123]$`; records with `ddr_version: "0.1"` or `"0.2"` remain valid.

### Back-compat notes
- v0.1/v0.2 `tuning` blocks without a `kind` field default to `kind: "sigma"` during load.
- `Tuning` (Python import) is now an alias for `SigmaTuning`. Existing code that imports `Tuning` is unaffected.
- `ddr export-sigma-filter` now exits 1 with a clear error when `target.kind == "splunk"`.



The DDR **spec** is versioned independently from the CLI. This file records changes to the format itself — fields added, semantics clarified, breaking changes.

## [0.1.0] — 2026-05-06

Initial release. Full design rationale in `docs/design/v0.1-design.md`.

### Added
- Top-level fields: `ddr_version` (pattern `^0\.1$`), `id` (UUID), `target`, `title`, `description`, `decision`, `lifecycle`, `provenance`, `scope`, `extensions`.
- `decision` discriminated union (discriminator: `kind`): `suppress`, `accept-risk`, `deprecate`.
- `target.kind` discriminator; `"sigma"` is the sole v0.1 value. Multi-format reserved for v0.2+.
- `target.rule_ref`: `rule_id` (Sigma UUID), `content_hash` (`sha256:<64 hex>`, required), `source` enum, `path_or_url`, optional `commit`.
- Content-hash canonicalization algorithm v1: safe-load (strips comments) → sort mapping keys → LF-normalize → SHA-256 → `sha256:` prefix.
- `tuning` block (required for `suppress`): `logsource`, `selections` (named blocks), `condition` — losslessly exportable to a Sigma Filter via `ddr export-sigma-filter`.
- Lifecycle stored states `draft | active | retired`; `expired` and `due-for-review` are computed (not stored). `expires_on` required for `active` records.
- `lifecycle.superseded_by` (UUID) and `lifecycle.retirement_reason` enum valid only when `retired`.
- By-reference-only evidence: `type` enum, `ref` (URL/path/ID), `note` (required). No inline content fields.
- `extensions` map: `x-*` prefixed keys only; unknown top-level fields rejected (`additionalProperties: false`).
