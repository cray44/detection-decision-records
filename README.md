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

### Elastic Security target

```bash
# Infers --target elastic from .ndjson extension; extracts rule_id and name
ddr new rules/elastic/windows-defender-av.ndjson --output my_suppression.yml

# fill rationale, kql_filter, lifecycle dates
ddr validate my_suppression.yml
ddr export-elastic-exception my_suppression.yml   # Kibana-importable NDJSON
```

If the Elastic rule is updated later:

```bash
ddr refresh-hash my_suppression.yml        # recomputes hash, ignores volatile Kibana fields
ddr validate --strict my_suppression.yml   # warns on hash drift
```

### Microsoft Sentinel target

```bash
# ARM export from Sentinel portal or az CLI — explicit --target required (both SIEM exports are .json)
ddr new --target kql-sentinel sentinel-rule.json --output my_suppression.yml

# fill rationale, kusto_filter, lifecycle dates
ddr validate my_suppression.yml
ddr export-kql my_suppression.yml   # Kusto | where not (...) fragment
```

### M365D Advanced Hunting target

```bash
ddr new --target kql-m365d m365d-detection.json --output my_suppression.yml

# fill rationale, kusto_filter, lifecycle dates
ddr validate my_suppression.yml
ddr export-kql my_suppression.yml
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
| `ddr new <rule_or_conf>` | Scaffold a DDR from a Sigma rule, `savedsearches.conf`, Elastic NDJSON, or KQL JSON |
| `ddr list [--status] [--target] [--decision]` | Summary table of DDRs by status/target/decision/ref count |
| `ddr validate [--strict]` | Validate one file or directory; `--strict` adds hash-drift check |
| `ddr expire-check [--days-ahead N]` | Report expired / due-for-review active records |
| `ddr export-sigma-filter` | Emit a Sigma Filter YAML from a suppress DDR (Sigma targets) |
| `ddr export-splunk [--format savedsearches]` | Emit a SPL `NOT (...)` clause |
| `ddr export-elastic-exception [--list-id]` | Emit a Kibana exception list item NDJSON (Elastic targets) |
| `ddr export-kql` | Emit a Kusto `\| where not (...)` fragment (Sentinel and M365D targets) |
| `ddr refresh-hash [--rule / --conf]` | Recompute content/query hash after a cosmetic-only change |

## Target kinds

| `target.kind` | Use when | Hash field | Export command |
|---|---|---|---|
| `sigma` | A Sigma rule exists | `content_hash` (SHA-256 of canonicalized YAML) | `export-sigma-filter` |
| `splunk` | Detection lives only in Splunk — no Sigma rule | `query_hash` (SHA-256 of canonicalized SPL) | `export-splunk` |
| `elastic` | Detection is an Elastic Security rule (EQL/KQL/threshold) | `content_hash` (SHA-256 of canonicalized rule JSON, volatile Kibana fields stripped) | `export-elastic-exception` |
| `kql-sentinel` | Detection is a Microsoft Sentinel Analytics Rule | `content_hash` (SHA-256 of canonicalized ARM JSON, volatile Sentinel fields stripped) | `export-kql` |
| `kql-m365d` | Detection is an M365D Advanced Hunting custom detection | `content_hash` (SHA-256 of canonicalized Graph API JSON, volatile Defender fields stripped) | `export-kql` |

Splunk, Elastic, Sentinel, and M365D native targets have no dependency on sigma-to-spl.

## Multi-rule targeting

One DDR can govern multiple rules of the same target kind. Use `rule_refs` (list) to retire or suppress a cluster of related detections under a single governance decision:

```yaml
target:
  kind: sigma
  rule_refs:
    - rule_id: a1f2e3d4-...
      content_hash: sha256:...
      source: internal
      path_or_url: rules/wmi-process.yml
    - rule_id: b2f3e4d5-...
      content_hash: sha256:...
      source: internal
      path_or_url: rules/wmi-registry.yml
```

v0.1–v0.4 records with the old singular `rule_ref` field continue to load unchanged.

## Version history

| Version | Key addition |
|---|---|
| **v0.7** | KQL targets (`kql-sentinel`, `kql-m365d`), `export-kql`, Sentinel + M365D canonicalization v1 |
| v0.6 | Elastic Security target (`target.kind: elastic`), `export-elastic-exception`, Elastic canonicalization v1 |
| v0.5 | Multi-rule targeting (`rule_refs`/`query_refs`), `ddr list` command, back-compat shim for v0.1–v0.4 |
| v0.4 | `savedsearches.conf` parser, SPL canonicalization, `query_hash` automation, `refresh-hash` Splunk branch |
| v0.3 | Splunk-native target (`target.kind: splunk`), `SplunkTuning`, `export-splunk` Splunk-native path |
| v0.2 | `ddr export-splunk` (Sigma targets via sigma-to-spl), `--format savedsearches` |
| v0.1 | JSON Schema, `ddr new/validate/expire-check/export-sigma-filter/refresh-hash`, 5 worked examples |

## Project layout

```
spec/        Human-readable spec + JSON Schema (generated, CI-checked for drift)
src/ddr/     Python package — models, CLI, exporters, internal utilities
examples/    11 worked examples (PsExec, Nessus, schtasks, AWS root, WMI legacy,
             Splunk-native savedsearch, multi-stanza Splunk Add-on, multi-rule WMI deprecation,
             Elastic Security AV scanner suppress, Sentinel brute-force suppress,
             M365D LOLBin admin suppress)
tests/       313 unit + integration tests + invalid-fixture corpus
docs/        Design documents for each release
```

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Design rationale for each release is in `docs/design/`.

## License

Apache-2.0 — chosen to align with the SigmaHQ license and keep the upstream path open.
