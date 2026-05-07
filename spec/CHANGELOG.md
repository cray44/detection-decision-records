# DDR Spec Changelog

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
