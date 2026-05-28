# Example 12 — Splunk Cloud REST Export

**Target:** Splunk Cloud (`target.kind: splunk`)  
**Decision:** suppress  
**v0.8 feature:** Cloud servicesNS JSON as source artifact

---

## The problem

Splunk Cloud engineers cannot access `savedsearches.conf` on the filesystem — all saved
searches live behind the Splunk REST API. Before v0.8, DDR required a `.conf` file to
compute `query_hash` for Splunk-native targets. Cloud users had no first-class path.

## The workflow

### 1. Export the saved search from the Cloud REST API

```bash
curl -s -H "Authorization: Bearer $SPLUNK_TOKEN" \
  "https://tenant.splunkcloud.com:8089/servicesNS/nobody/DA-ESS-AccessProtection/saved/searches/Excessive%20Failed%20Logins%20From%20Single%20Source?output_mode=json" \
  > cloud-export.json
```

The result is `cloud-export.json` — a servicesNS JSON artifact. This file is the stable
snapshot DDR hashes. Check it in alongside the DDR record.

### 2. Scaffold the DDR

```bash
ddr new --target splunk cloud-export.json \
  --source-url "https://github.com/yourorg/detections/blob/main/splunk/cloud-export.json"
```

DDR auto-detects the servicesNS shape, extracts name + app from ACL, computes `query_hash`
from the SPL string using the same canonicalization algorithm as the `.conf` path. The
`--source-url` flag stores a portable permalink instead of an absolute local path.

### 3. Fill in the DDR

Edit the scaffolded YAML: rationale, `splunk_filter`, lifecycle dates.

### 4. Validate and export

```bash
ddr validate ddr.yml
ddr export-splunk ddr.yml
# → NOT (src_ip>=10.0.100.20 AND src_ip<=10.0.100.30)
```

### 5. Drift detection

When the underlying saved search is updated, re-export from the API and run:

```bash
ddr refresh-hash ddr.yml --conf updated-cloud-export.json
ddr validate --strict ddr.yml  # warns on query_hash mismatch
```

## Hash identity guarantee

The same SPL string produces the same `query_hash` whether it came from a `.conf` stanza
(with backslash line continuations) or a Cloud JSON export (SPL as a single string with
`\n` characters). The canonicalization algorithm normalizes both representations before
hashing, so a detection migrated from Enterprise to Cloud can reuse its existing DDR
without a hash bump.

## Files

| File | Description |
|---|---|
| `cloud-export.json` | Redacted servicesNS REST export (single saved search) |
| `ddr.yml` | DDR record governing the FP suppression |
| `splunk-fragment.spl` | Generated SPL filter fragment |
| `README.md` | This file |
