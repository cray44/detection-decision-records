# Example 09 — Elastic Security: Suppress Nessus AV Scanner Alerts

**Target:** Elastic Security (`kind: elastic`)
**Decision:** Suppress
**Rule:** Windows Defender Antivirus Threats Detected (EQL)
**Export:** Kibana exception list item (NDJSON)

## Scenario

The Nessus vulnerability scanner on the management VLAN (10.0.100.0/24) triggers
the "Windows Defender Antivirus Threats Detected" detection rule during scheduled
scan windows. Defender flags the scanner's payload delivery mechanism against temp
files created by the scanner agent. All events are confirmed false positives with
zero true-positive events over 90 days of investigation.

## Files

| File | Description |
|---|---|
| `elastic-rule.ndjson` | Elastic Security detection rule (EQL, stripped from Kibana export) |
| `ddr.yml` | DDR governance record — suppress decision with KQL filter |
| `elastic-exception.ndjson` | Exported Kibana exception list item (ready to import) |

## Workflow

```bash
# Create the DDR from the Elastic rule NDJSON
ddr new elastic-rule.ndjson --decision suppress --output ddr.yml
# (Edit ddr.yml — fill in rationale, kql_filter, lifecycle, provenance)

# Validate
ddr validate ddr.yml

# Verify content hash hasn't drifted since DDR was authored
ddr validate --strict ddr.yml

# Export exception list item for Kibana import
ddr export-elastic-exception ddr.yml --output elastic-exception.ndjson
```

## KQL filter

```
source.ip : "10.0.100.0/24" and agent.name : nessus*
```

This AND-chain of simple field conditions is parsed into two structured entries
in the Elastic exception list item — no manual completion required.

## Importing into Kibana

1. Navigate to **Security → Rules → Exception Lists**
2. Click **Import exception list**
3. Upload `elastic-exception.ndjson`
4. Associate the imported exception list with the detection rule

## Hash verification

After a Kibana prebuilt rule update, verify the rule logic hasn't changed:

```bash
ddr refresh-hash ddr.yml
```

Volatile fields (`revision`, `version`, `created_at`) are stripped before
hashing so routine Elastic updates don't cause spurious drift.
