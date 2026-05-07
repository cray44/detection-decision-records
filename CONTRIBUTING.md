# Contributing to DDR

> DDR is alpha. The spec is stable at v0.4 but may evolve. External contributions are welcome — see locked decisions in the design docs before opening a spec-change PR.

## Before opening an issue or PR

Read [`docs/design/v0.1-design.md`](docs/design/v0.1-design.md). It captures every locked decision and open item with reasoning. If your issue or PR conflicts with a locked decision, open it as a discussion first — locked decisions can move, but only with deliberate review.

## Local setup

```bash
git clone https://github.com/cray44/detection-decision-records.git
cd detection-decision-records
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install
pytest
```

## Code style

- **Python 3.11+.** No backports for older versions.
- **Ruff** for lint + format. CI fails on ruff violations.
- **Pydantic v2** is the source of truth for the schema. Hand-editing `spec/ddr-v0.1.schema.json` is not allowed — the file is regenerated from the models and CI fails on drift.
- **Type hints everywhere.** No `Any` without a comment explaining why.

## Commit style

Conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`. Spec changes get `spec:`. Breaking spec changes get `spec!:`.

## Testing requirements

A PR is mergeable when:
- `ruff check` and `ruff format --check` pass.
- `pytest` passes on Linux and Windows (CI matrix).
- Schema drift check passes (regenerated schema matches checked-in `spec/ddr-v0.1.schema.json`).
- Every example in `examples/` validates.
- If the PR changes the schema: spec doc updated, `spec/CHANGELOG.md` entry added, migration note included.

## What not to add

- Inline log samples or other raw telemetry in DDR records — by design, the schema does not allow it. See Q26 in the design doc.
- Features that could be done in Sigma itself. DDR's value is in what Sigma can't express; not in re-implementing Sigma.
- Dependencies on databases, web services, or non-Python tooling.

## Reporting security issues

See [`SECURITY.md`](SECURITY.md).
