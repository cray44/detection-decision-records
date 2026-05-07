# Changelog

All notable changes to the DDR project (CLI + tooling) are recorded here.
The DDR **spec** has its own changelog at [`spec/CHANGELOG.md`](spec/CHANGELOG.md).

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and adheres to semantic versioning.

## [Unreleased]

## [0.4.0] — 2026-05-06

### Added
- New module `ddr._internal.splunk_conf`: pure-Python `savedsearches.conf` parser + SPL canonicalizer + hash utility. Zero new runtime dependencies.
  - `parse_savedsearches_conf(path)` — handles BOM, CRLF, backslash-continuation, `#` comments, `[default]` skip, last-wins duplicate keys.
  - `extract_stanza(conf, name)` — stanza lookup with clear error listing available names.
  - `infer_app_from_path(path)` — infers Splunk app from `.../etc/apps/<app>/(local|default)/savedsearches.conf`.
  - `canonicalize_spl(query)` — canonicalization algorithm v1 (spec §6): no keyword lowercasing.
  - `compute_query_hash(query)` — `sha256:<hex>` of canonicalized SPL.
- `ddr new --target splunk <conf_path> [--name <stanza>]` — parses conf, extracts stanza, computes `query_hash`, fills `path_or_url`, infers `app`. If conf has a single stanza, `--name` is optional.
- `ddr new --target splunk <conf_path>` with multiple stanzas and no `--name` → exit 1, lists available stanzas.
- `ddr refresh-hash` — Splunk branch: re-parses `path_or_url` (or `--conf` override), recomputes `query_hash`, prints old/new (parallel to Sigma `content_hash` behavior).
- `ddr refresh-hash --conf <path>` — new flag to override the conf path for Splunk targets.
- `ddr validate --strict` — new check: warns on `query_hash` drift when `target.kind=splunk` and local conf is reachable. Skipped (note printed) for `http(s)://` URLs.
- Example 07 (`examples/07-splunk-multi-stanza-app/`) — Splunk_TA_windows multi-stanza conf demonstrating stanza selection.
- `spec/ddr-v0.4.md` — formalizes SPL canonicalization algorithm v1, conf parsing spec, drift check semantics.
- `spec/ddr-v0.4.schema.json` — regenerated from Pydantic models.
- 33 new tests (25 parser/canonicalizer unit tests + 8 CLI integration tests).

### Changed
- `ddr new` scaffolds now emit `ddr_version: "0.4"`.
- `ddr refresh-hash` no longer exits 1 for Splunk targets — it branches to the Splunk path instead.
- Example 06 `ddr.yml` updated: `ddr_version: "0.4"`, `query_hash` populated with real SHA-256.
- `ddr_version` pattern updated to `^0\.[1234]$`; v0.1/v0.2/v0.3 records remain valid.

### Notes
- `ddr new --target splunk --name <stanza>` (no conf path) still works — produces a minimal scaffold without `query_hash` (v0.3 behavior preserved).
- `query_hash` is intentionally whitespace-stable: cosmetic SPL reformatting does not change the hash.

## [0.3.0] — 2026-05-06

### Added
- `target` discriminated union: `kind: "sigma"` (existing) | `kind: "splunk"` (new). Existing Sigma-targeted records unchanged.
- New `SplunkTarget` model with `SplunkQueryRef` (stanza `name`, `app`, optional `query_hash`, optional `path_or_url`).
- `tuning` inside `suppress` decisions is now a discriminated union: `kind: "sigma"` (existing `SigmaTuning`) | `kind: "splunk"` (new `SplunkTuning`).
- New `SplunkTuning`: carries a raw SPL filter clause (`splunk_filter`). No Sigma selections required.
- Cross-field validator on `DDRRecord`: `tuning.kind` must equal `target.kind` for suppress decisions.
- `ddr new --target splunk --name <stanza>` — scaffolds a Splunk-native DDR with TODO placeholders. `--app` defaults to `"search"`.
- `ddr export-splunk` branches on `target.kind`: Sigma targets use the sigma-to-spl lowering path (unchanged); Splunk-native targets emit `splunk_filter` wrapped in `NOT (...)` without sigma-to-spl.
- `ddr export-sigma-filter` now exits 1 with a clear error when `target.kind == "splunk"`.
- `ddr refresh-hash` now exits 1 with a clear error when `target.kind == "splunk"`.
- Example 06 (`examples/06-splunk-native-savedsearch/`) — noisy Splunk savedsearch with SPL FP filter, no Sigma rule.
- `spec/ddr-v0.3.schema.json` — regenerated from Pydantic models.
- `spec/ddr-v0.3.md` — prose spec update covering native targets and cross-field validator.
- 28 new tests covering new models, discriminated unions, cross-field validator, native export, CLI commands, back-compat.

### Changed
- `Tuning` is now an alias for `SigmaTuning`. Existing imports unaffected.
- `ddr_version` pattern updated to `^0\.[123]$`; v0.1 and v0.2 records remain valid.
- v0.1/v0.2 `tuning` blocks without a `kind` field default to `kind: "sigma"` on load.

### Notes
- Splunk-native targets are an explicit escape hatch — use them when the detection cannot be expressed in Sigma. Sigma remains the preferred source of truth.
- `ddr export-splunk` on a Splunk-native record works with sigma-to-spl **not** installed.

## [0.2.0] — 2026-05-06

### Added
- CLI command `ddr export-splunk` — emits a SPL `NOT (...)` clause from a `suppress` DDR's tuning block. Lowers selections through sigma-to-spl's `SplunkBackend` + `PostProcessor._apply_field_map()` for Corelight/Zeek-correct field names.
- `--format savedsearches` flag — emits a `savedsearches.conf` stanza instead of a bare fragment.
- `--config <path>` flag — override the default sigma-to-spl config YAML; falls back to `../sigma-to-spl/config/corelight.yml` when sigma-to-spl is installed as a sibling editable install.
- Splunk exporter (`ddr.exporters.splunk`) as a public library API: `build_splunk_suppression()`, `export_to_spl()`.
- `splunk-fragment.spl` artifacts for all three suppress worked examples (PsExec/SCCM, Nessus scanner, scheduled-task vendor noise).
- 13 new tests covering `_strip_not` logic, missing-dependency error, non-suppress guard, savedsearches format, file write, and integration against all suppress examples.

### Notes
- sigma-to-spl is an optional dependency (not on PyPI). `ddr export-splunk` raises a `RuntimeError` with install instructions if it is not available; all other commands are unaffected.
- No schema changes. v0.1 DDR records are fully compatible.

## [0.1.0] — 2026-05-06

### Added
- Pydantic v2 models (`DDRRecord`, `SuppressDecision`, `AcceptRiskDecision`, `DeprecateDecision`, `Lifecycle`, `Tuning`, `Provenance`, `Evidence`, `Scope`, `RuleRef`) with `extra="forbid"` and cross-field validators for all lifecycle constraints.
- JSON Schema export (`python -m ddr._internal.schema_export`) and CI drift check (`python -m ddr._internal.schema_drift_check`). Schema at `spec/ddr-v0.1.schema.json`.
- Content hash utility: canonicalization algorithm v1 (safe-load → sort keys → LF-normalize → SHA-256 with `sha256:` prefix).
- CLI command `ddr new` — scaffolds a DDR from a Sigma rule, computes content hash, prefills `target`.
- CLI command `ddr validate` — validates one file or a directory; skips non-DDR YAMLs; `--strict` warns on free-text patterns resembling raw log data.
- CLI command `ddr expire-check` — reports expired and due-for-review active records; `--format json` for CI; `--days-ahead N` for lead-time warnings.
- CLI command `ddr export-sigma-filter` — emits Sigma Filter YAML from a `suppress` decision's tuning block.
- CLI command `ddr refresh-hash` — recomputes `target.rule_ref.content_hash` after a confirmed cosmetic-only rule change.
- Sigma Filter exporter (`ddr.exporters.sigma_filter`) as a public library API.
- Public library API: `from ddr import DDRRecord` (and all model classes).
- 5 worked examples in `examples/`: PsExec/SCCM suppress, Nessus scanner suppress, scheduled-task vendor noise suppress, AWS root accept-risk, legacy WMI rule deprecate.
- 61 tests covering models, CLI, exporters, and hash utilities.
- Complete spec prose at `spec/ddr-v0.1.md`.
- Repository scaffold: `pyproject.toml`, CI workflow (lint + test matrix + schema-drift + example validation), pre-commit config, `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE` (Apache-2.0).
