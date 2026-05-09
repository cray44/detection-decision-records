# Worked Examples

8 canonical DDRs spanning all decision kinds and both target kinds. Each example is a directory containing:

- `sigma-rule.yml` — the Sigma rule (vendored, pinned by content hash); Splunk examples use `savedsearch.conf` instead
- `ddr.yml` — the Detection Decision Record
- `sigma-filter.yml` — exported Sigma Filter (suppress + Sigma-target examples only)
- `README.md` — FP scenario explanation and *why this decision over alternatives*

CI validates every `ddr.yml` and re-exports suppress filters on each run. If the spec can't express an example, the spec is wrong.

## Coverage

| # | Directory | Target | FP archetype / scenario | Decision |
| - | --------- | ------ | ----------------------- | -------- |
| 1 | `01-psexec-admin-suppression/` | sigma | SCCM parent chain, ~40/day | `suppress` |
| 2 | `02-nessus-network-scanner/` | sigma | Authorized scanner IPs (Zeek) | `suppress` |
| 3 | `03-scheduled-task-vendor-noise/` | sigma | Vendor installer paths | `suppress` |
| 4 | `04-aws-root-accept-risk/` | sigma | FP indistinguishable from TP | `accept-risk` |
| 5 | `05-legacy-rule-deprecate/` | sigma | Rule superseded by v2 | `deprecate` |
| 6 | `06-splunk-native-savedsearch/` | splunk | Vuln scanner + LDAP health check | `suppress` |
| 7 | `07-splunk-multi-stanza-app/` | splunk | Multi-stanza TA conf | `suppress` |
| 8 | `08-multi-rule-wmi-deprecate/` | sigma (3 refs) | Legacy rule cluster retirement | `deprecate` |

## Quickstart

Validate all examples:

```bash
ddr validate examples/
```

List all examples with ref counts:

```bash
ddr list examples/
```

Re-export a filter:

```bash
ddr export-sigma-filter examples/01-psexec-admin-suppression/ddr.yml
```

Check for expired records:

```bash
ddr expire-check examples/ --days-ahead 30
```
