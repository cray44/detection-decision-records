# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repo state

Greenfield. As of 2026-05-05 the only tracked content is `.claude/` (project briefing, slash commands, knowledge, hooks) and `.git/`. No source, schema, tests, or packaging exist yet — bootstrapping is part of the task.

## What DDR is

Detection Decision Records — an open-source governance/operational layer for detection-as-code, sitting between Sigma rules, Sigma Filters/suppressions, and ADS writeups. A versioned record format for FP-tuning decisions, deployment status, and deprecation. Positioned as a companion spec to upstream into the Sigma ecosystem.

**v0.1 deliverables** (see `.claude/knowledge/0.1-vision.md`):
- Official DDR JSON Schema (strict + extensible)
- Python CLI with four commands: `ddr new`, `ddr validate`, `ddr expire-check`, `ddr export-sigma-filter`
- 5+ real-world worked examples against noisy SigmaHQ rules
- Clear upstream path into the Sigma project

Non-goals for v0.1: UI, database backend, analytics. Success = a detection engineer tunes a noisy rule in <5 min and exports a clean filter.

## Tech decisions (locked for v0.1)

- Python 3.11+
- Typer for CLI
- Pydantic v2 + JSON Schema (Pydantic models are source of truth; JSON Schema exported from them)
- Ruff (Python) + Prettier (markdown/JSON) for formatting
- Conventional commits + semver

## Working agreements (from `.claude/CLAUDE.md`)

Every task starts with the **7-section thinking process**: Refined Goal → Proposed Changes → Schema/CLI/Examples Impact → Edge Cases → Testing Strategy → Sigma Compatibility → Final Plan. Do not output code until the user says **IMPLEMENT**. If the user says **PLAN ONLY**, output only the thinking process.

Bias: simplicity, explicit-over-implicit, maximum Sigma compatibility, schema/back-compat correctness over speed.

## Slash commands available in `.claude/`

- `/plan-only` — emit the 7-section thinking process, no code
- `/grill-me` — 15–40 clarifying questions before any plan
- `/design-fp-tuning-spec` — evolve the spec + JSON Schema + examples + migration notes
- `/design-cli-command` — design a `ddr <subcommand>` (Typer + Pydantic + tests)
- `/create-worked-example` — real SigmaHQ rule → DDR record → exported filter
- `/ensure-sigma-compatibility` — audit rule IDs, field names, filter export format, back-compat
- `/code-review` — senior-maintainer review with 1–10 score and exact fixes
- `/release-checklist` — CHANGELOG, version bump, schema validation, CLI tests, docs, GH release draft

## Sibling repos (parent dir context)

This repo lives under `C:\Users\Chris\Documents\projects\github_portfolio\` alongside `detection-notes/`, `sigma-to-spl/`, `spl-coverage-map/`, `cray44/`. DDR is independent of those but worked examples will draw from real SigmaHQ rules; `sigma-to-spl/rules/` is a convenient local source. See the parent `CLAUDE.md` for those repos' commands.

## Conventions

- No `Co-Authored-By: Claude` in commit messages.
- Sigma is source of truth; DDR records reference Sigma rules by ID, never embed them.
- Schema changes are versioned and require a migration note.
- Terse replies preferred (user is Chris Ray, detection/network engineer — caveman mode OK).
