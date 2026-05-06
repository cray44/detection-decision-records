# Changelog

All notable changes to the DDR project (CLI + tooling) are recorded here.
The DDR **spec** has its own changelog at [`spec/CHANGELOG.md`](spec/CHANGELOG.md).

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and adheres to semantic versioning.

## [Unreleased]

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
