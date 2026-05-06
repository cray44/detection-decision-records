# CLAUDE.md – Detection Decision Records (DDR)

## 1. Project Overview
Detection Decision Records (DDR) is a new open-source governance/operational layer for detection-as-code.  
It fills the gap between:
- Sigma rules
- Sigma Filters / suppressions
- ADS / writeups

DDR provides a structured, versioned record format for FP-tuning decisions, deployment status, and deprecation.  
**v0.1 scope**: FP-tuning spec + official JSON Schema + Python CLI (`ddr new`, `ddr validate`, `ddr expire-check`, `ddr export-sigma-filter`) + worked examples on real noisy SigmaHQ rules.  
Positioned as a companion spec to upstream into the Sigma ecosystem.

## 2. Core Principles (Never violate)
- Think end-to-end before writing any code.
- Prioritize simplicity, maintainability, and maximum Sigma compatibility.
- Excellent documentation and contributor experience are non-negotiable.
- Always prefer explicit over implicit.
- Security, schema validation, and backwards compatibility first.

## 3. Required Thinking Process (use every time)
Before any code, structure your response with:
1. Refined Goal & Success Criteria
2. Proposed Changes / Feature Breakdown
3. Impact on Schema / CLI / Examples
4. Edge Cases & Error Handling
5. Testing Strategy (unit + integration + schema validation)
6. Sigma Compatibility & Ecosystem Fit
7. Final Plan Summary (one paragraph)

Only after I approve or say “IMPLEMENT” → output code with full file paths.

## 4. Architecture & Tech Decisions
- Python 3.11+
- Typer for CLI
- Pydantic v2 + JSON Schema
- Ruff + Prettier for formatting
- Conventional commits + semantic versioning
- Follow the folder structure already in the repo

## 5. When I say “PLAN ONLY”
→ Output only the thinking process. No code.

## 6. When I say “IMPLEMENT”
→ Output clean, ready-to-commit code + tests + updated docs.

You are now fully briefed on DDR. Begin every task with the thinking process.