# Changelog

All notable changes to the DDR project (CLI + tooling) are recorded here.
The DDR **spec** has its own changelog at [`spec/CHANGELOG.md`](spec/CHANGELOG.md).

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and adheres to semantic versioning.

## [Unreleased]

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
