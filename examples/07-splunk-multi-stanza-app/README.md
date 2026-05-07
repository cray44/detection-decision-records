# Example 07 — Multi-Stanza Splunk Add-on

**Pattern:** Technology Add-on conf with multiple detections — select one stanza by name.

## Scenario

`Splunk_TA_windows/savedsearches.conf` contains three detection savedsearches.
The "Windows Lateral Movement - PsExec" detection fires on every SCCM-initiated
PsExec during weekly maintenance windows — ~40 alerts/week, all benign.

## Generating the DDR

When a conf has multiple stanzas, `ddr new` requires `--name`:

```bash
# Without --name → exit 1, lists available stanzas
ddr new --target splunk savedsearches.conf
# ERROR: savedsearches.conf contains 3 stanzas — use --name to select one:
#   'Windows Lateral Movement - PsExec'
#   'Windows Privileged Account Use - Admin Share Access'
#   'Windows Service Creation - Suspicious Path'

# With --name → fully populated DDR with query_hash
ddr new --target splunk savedsearches.conf \
  --name "Windows Lateral Movement - PsExec" \
  --output ddr.yml
```

`ddr.yml` in this example was generated with that command. The `query_hash` is a
SHA-256 of the canonicalized SPL — whitespace and comment changes won't trigger drift.

## Refreshing the hash

```bash
ddr refresh-hash ddr.yml
# Uses path_or_url to find the conf, re-parses, recomputes.

# Or with an explicit conf path:
ddr refresh-hash ddr.yml --conf /path/to/savedsearches.conf
```

## Drift detection

```bash
ddr validate --strict ddr.yml
# WARN if the SPL has changed since the DDR was authored.
```

## Key differences from example 06

| | Example 06 | Example 07 |
|---|---|---|
| Stanzas in conf | 1 | 3 |
| `--name` required | No (auto-selected) | Yes |
| App inference | No (no etc/apps path) | No (same) |
