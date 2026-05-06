# Detection Decision Records (DDR)

A versioned record format for detection-engineering governance: who decided to suppress this rule, why, until when, and how to find out if it's still right.

DDR sits between Sigma rules, Sigma Filters/suppressions, and ADS writeups. It records the **operational decisions** made about deployed detections — false-positive tunings, accepted-risk acknowledgments, and rule deprecations — in a format that's checked into git, validates against a JSON Schema, and exports back into Sigma Filters.

> Sigma Filters answer *what* to suppress.  
> DDR answers *who decided, why, until when, and how to find out if it's still right.*

## What DDR is not

- **Not a competitor to Sigma's `falsepositives:` field** — that field is documentation. DDR is governance with lifecycle and exportable suppression logic.
- **Not a competitor to Sigma Filters** — DDR *produces* Sigma Filters and adds the wrapper (who, why, when to revisit).
- **Not a competitor to ADS writeups** — ADS captures detection authorship/intent. DDR captures post-deployment operational decisions.

## Quickstart

```bash
pip install ddr
```

Scaffold a new record from a Sigma rule:

```bash
ddr new rules/windows/proc_creation_win_psexec.yml --output my_suppression.yml
# edit my_suppression.yml — fill rationale, tuning selections, lifecycle dates
ddr validate my_suppression.yml
ddr export-sigma-filter my_suppression.yml
```

Check for expired or due-for-review records across a directory:

```bash
ddr expire-check detections/ --days-ahead 30
```

Use as a library:

```python
from ddr import DDRRecord

record = DDRRecord.model_validate(yaml.safe_load(open("my_suppression.yml")))
```

## v0.1 scope

- JSON Schema (strict + extensible via `x-*` namespace), generated from Pydantic models
- Python 3.11+ CLI: `ddr new`, `ddr validate`, `ddr expire-check`, `ddr export-sigma-filter`, `ddr refresh-hash`
- 5 worked examples covering suppress, accept-risk, and deprecate decisions
- Apache-2.0 license — aligned with SigmaHQ for upstream compatibility

**Non-goals for v0.1:** UI, server, database, analytics, SIEM-specific integrations, automated FP detection.

## Project layout

```
spec/        Human-readable spec + JSON Schema (generated, CI-checked for drift)
src/ddr/     Python package — models, CLI, exporters, internal utilities
examples/    5 worked examples on real noisy rules (PsExec, Nessus, schtasks, AWS root, WMI legacy)
tests/       61 unit + integration tests + invalid-fixture corpus
docs/        Design document with all locked decisions and rationale
```

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). The design rationale for every decision is in [`docs/design/v0.1-design.md`](docs/design/v0.1-design.md).

## License

Apache-2.0 — chosen to align with the SigmaHQ license and keep the upstream path open.
