# DDR Spec Changelog

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
