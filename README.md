# Detection Decision Records (DDR)

A versioned record format for detection-engineering governance: who decided to suppress this rule, why, until when, and how to find out if it's still right.

DDR sits between Sigma rules, Sigma Filters/suppressions, and ADS writeups. It records the **operational decisions** made about deployed detections — false-positive tunings, accepted-risk acknowledgments, and rule deprecations — in a format that's checked into git, validates against a JSON Schema, and exports back into Sigma Filters or SPL.

> Sigma Filters answer *what* to suppress.  
> DDR answers *who decided, why, until when, and how to find out if it's still right.*

## What DDR is not

- **Not a competitor to Sigma's `falsepositives:` field** — that field is documentation. DDR is governance with lifecycle and exportable suppression logic.
- **Not a competitor to Sigma Filters** — DDR *produces* Sigma Filters and adds the wrapper (who, why, when to revisit).
- **Not a competitor to ADS writeups** — ADS captures detection authorship/intent. DDR captures post-deployment operational decisions.

## Quickstart

```bash
pip install "git+https://github.com/cray44/detection-decision-records.git"
```

### Sigma-native target (Sigma rule exists)

```bash
ddr new rules/windows/proc_creation_win_psexec.yml --output my_suppression.yml
# fill rationale, tuning selections, lifecycle dates
ddr validate my_suppression.yml
ddr export-sigma-filter my_suppression.yml
```

### Splunk-native target (detection lives only in the SIEM)

```bash
# Fully automated — parses conf, computes query_hash, infers app
ddr new --target splunk /opt/splunk/etc/apps/MyTA/local/savedsearches.conf \
  --name "Excessive Failed Logins From Single Source" \
  --output my_suppression.yml

# fill rationale, lifecycle dates
ddr validate my_suppression.yml
ddr export-splunk my_suppression.yml
```

If the savedsearch SPL changes later:

```bash
ddr refresh-hash my_suppression.yml        # re-reads conf, recomputes hash
ddr validate --strict my_suppression.yml   # warns on hash drift
```

### Lifecycle management

```bash
ddr expire-check detections/ --days-ahead 30
```

### Library

```python
from ddr import DDRRecord

record = DDRRecord.model_validate(yaml.safe_load(open("my_suppression.yml")))
```

## CLI commands

| Command | Description |
|---|---|
| `ddr new <rule_or_conf>` | Scaffold a DDR from a Sigma rule or `savedsearches.conf` |
| `ddr validate [--strict]` | Validate one file or directory; `--strict` adds hash-drift check |
| `ddr expire-check [--days-ahead N]` | Report expired / due-for-review active records |
| `ddr export-sigma-filter` | Emit a Sigma Filter YAML from a suppress DDR (Sigma targets) |
| `ddr export-splunk [--format savedsearches]` | Emit a SPL `NOT (...)` clause |
| `ddr refresh-hash [--rule / --conf]` | Recompute content/query hash after a cosmetic-only change |

## Target kinds

| `target.kind` | Use when | Hash field |
|---|---|---|
| `sigma` | A Sigma rule exists | `content_hash` (SHA-256 of canonicalized YAML) |
| `splunk` | Detection lives only in Splunk — no Sigma rule | `query_hash` (SHA-256 of canonicalized SPL) |

Splunk targets work with sigma-to-spl **not** installed.

## Version history

| Version | Key addition |
|---|---|
| **v0.4** | `savedsearches.conf` parser, SPL canonicalization, `query_hash` automation, `refresh-hash` Splunk branch, `validate --strict` drift check |
| v0.3 | Splunk-native target (`target.kind: splunk`), `SplunkTuning`, `export-splunk` Splunk-native path |
| v0.2 | `ddr export-splunk` (Sigma targets via sigma-to-spl), `--format savedsearches` |
| v0.1 | JSON Schema, `ddr new/validate/expire-check/export-sigma-filter/refresh-hash`, 5 worked examples |

## Project layout

```
spec/        Human-readable spec + JSON Schema (generated, CI-checked for drift)
src/ddr/     Python package — models, CLI, exporters, internal utilities
examples/    7 worked examples (PsExec, Nessus, schtasks, AWS root, WMI legacy,
             Splunk-native savedsearch, multi-stanza Splunk Add-on)
tests/       157 unit + integration tests + invalid-fixture corpus
docs/        Design documents for each release
```

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Design rationale for each release is in `docs/design/`.

## License

Apache-2.0 — chosen to align with the SigmaHQ license and keep the upstream path open.
