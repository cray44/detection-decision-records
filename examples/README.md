# Worked Examples

12 canonical DDRs spanning all decision kinds and all five target kinds. Each example is a directory containing:

- Source rule file — `sigma-rule.yml` (Sigma targets), `savedsearch.conf` (Splunk targets), `elastic-rule.ndjson` (Elastic), `sentinel-rule.json` (Sentinel ARM export), or `m365d-detection.json` (M365D Graph API export)
- `ddr.yml` — the Detection Decision Record
- Exported artifact — `sigma-filter.yml`, `elastic-exception.ndjson`, or `.kql` fragment (suppress decisions)
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
| 9 | `09-elastic-av-scanner-suppress/` | elastic | Nessus scanner triggers Defender AV rule | `suppress` |
| 10 | `10-sentinel-brute-force-suppress/` | kql-sentinel | Authorized red team IP range in brute-force rule | `suppress` |
| 11 | `11-m365d-lolbin-suppress/` | kql-m365d | IT admin service accounts trigger LOLBin detection | `suppress` |
| 12 | `12-splunk-cloud-rest-export/` | splunk (Cloud) | Nessus scanner via servicesNS REST export | `suppress` |

## Quickstart

Validate all examples:

```bash
ddr validate examples/
```

List all examples with ref counts:

```bash
ddr list examples/
```

Re-export a suppress artifact:

```bash
ddr export-sigma-filter examples/01-psexec-admin-suppression/ddr.yml
ddr export-elastic-exception examples/09-elastic-av-scanner-suppress/ddr.yml
ddr export-kql examples/10-sentinel-brute-force-suppress/ddr.yml
ddr export-kql examples/11-m365d-lolbin-suppress/ddr.yml
ddr export-splunk examples/12-splunk-cloud-rest-export/ddr.yml
```

Check for expired records:

```bash
ddr expire-check examples/ --days-ahead 30
```
