# DDR Spec Changelog

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
