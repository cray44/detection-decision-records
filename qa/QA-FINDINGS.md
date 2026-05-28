# DDR v0.4 QA Findings

**Date:** 2026-05-07  
**Tester:** Chris Ray  
**Method:** 7 realistic DDR records against real sigma-to-spl rules, full command suite, negative cases, pySigma round-trip

---

## Bug (Fixed)

### BUG-01: `export-sigma-filter` produced invalid Sigma Filter structure
**Severity:** Critical  
**Status:** Fixed in this session

`build_sigma_filter()` placed `condition` and `rules` at the top level of the exported YAML. pySigma's `SigmaGlobalFilter.from_dict()` expects them **inside** the `filter:` block. All exported filters failed `SigmaFilter.from_dict()`.

**Root cause:** `src/ddr/exporters/sigma_filter.py` — `rules` and `condition` were keys in the top-level dict, not inside `filter:`.

**Fix:** Merge `condition` and `rules` into the `filter_block` dict before returning.

**Tests caught it:** No — `test_build_sigma_filter_structure()` was asserting against the wrong (buggy) structure. Updated test now asserts `sigma_filter["filter"]["condition"]` and `sigma_filter["filter"]["rules"]`, and added `test_export_sigma_filter_parses_with_pysigma()` as a true pySigma round-trip regression guard.

**Also fixed:** `examples/01-psexec-admin-suppression/sigma-filter.yml`, `examples/02-nessus-network-scanner/sigma-filter.yml`, `examples/03-scheduled-task-vendor-noise/sigma-filter.yml` — all had the same top-level structure bug.

---

## Schema Issues

### SCHEMA-01: `evidence.type` missing `note` enum value
**Severity:** Medium  
**Status:** Open

Valid evidence types are: `splunk_query`, `log_sample_uri`, `ticket`, `runbook`, `dashboard`, `pcap`, `other`.

The most natural type for vendor KB articles, Oracle Support docs, architecture notes, and internal references is `note`. Engineers will reach for it and get a validation failure. `other` works as a workaround but loses semantic meaning.

**Recommendation:** Add `note` to the `evidence.type` enum, or rename `other` to `note` and use `other` as the true fallback.

**Encountered in:** records 03, 04, 05, 06, 07 (all had to use `other`).

---

### SCHEMA-02: `expires_on` required for `status: active` on `deprecate` records
**Severity:** Low  
**Status:** Open

A deprecation is a permanent decision — it doesn't expire, and requiring `expires_on` is semantically wrong. The current enforcement is a blanket rule on all active records regardless of decision kind.

**Recommendation:** Carve out `deprecate` decisions from the `expires_on` requirement when `status: active`. Or add a distinct lifecycle status (e.g., `deprecated`) that doesn't require it.

**Encountered in:** record 07 — worked around by using `status: draft`.

---

## UX Issues

### UX-01: `ddr new` scaffold `path_or_url` bakes in absolute Windows paths
**Severity:** Medium  
**Status:** Open

`path_or_url` is set to the full Windows path (e.g., `C:\Users\Chris\...\rules\network\dns.yml`). Not portable for team use — a colleague on a different machine or OS gets a stale path immediately.

**Recommendation:** Accept a `--source-url` flag to override with a GitHub URL, or default to relative path from CWD if the rule is a sibling of the DDR.

---

### UX-02: `ddr new` scaffold doesn't include `tuning.filter_title`
**Severity:** Low  
**Status:** Open

The scaffold omits `filter_title` from the tuning block. This field is useful (it controls the exported filter's `title`), but engineers won't know to add it. Without it, the exporter falls back to `"FP Filter: {DDR title}"`, producing double-prefixed titles like `"FP Filter: Suppress: ..."`.

**Recommendation:** Include `filter_title: 'TODO: descriptive filter name'` in the scaffold's tuning block.

---

### UX-03: `--strict` lint false-positive on infrastructure IPs in rationale
**Severity:** Low  
**Status:** Open

`--strict` fired a "may contain raw log data" warning on record 02 (SMB lateral) because the rationale text referenced `10.10.5.20` and `10.10.5.21` as backup server IPs. These are infrastructure context, not raw log samples.

The IPv4 heuristic is too broad — any mention of an IP in rationale triggers it.

**Recommendation:** Narrow the IP regex to match log-line patterns (e.g., `src_ip=x.x.x.x`, `id.orig_h=x.x.x.x`) rather than bare IPs. Or make it warn only when the IP appears alongside timestamps or key=value log patterns.

---

## Closed in v0.7.1 (Chris Ray)

All five open items from the v0.4 QA session were addressed in the 0.7.1 patch release:

- **SCHEMA-01** (`evidence.type: "note"`): Added to `EvidenceType` enum. Regression test added. (commit: placeholder)
- **SCHEMA-02** (deprecate + active no longer requires `expires_on`): Validator relaxed in `DDRRecord`. Existing test `test_lifecycle_active_deprecate_no_expires_on_allowed` covers it. (commit: placeholder)
- **UX-01** (absolute paths on `ddr new`): `--source-url` flag + relative path logic added across all scaffolds. Per-target tests added. (commit: placeholder)
- **UX-02** (`filter_title` in scaffolds): Already present in all suppress scaffolds; confirmed by existing test `test_new_sigma_suppress_scaffold_includes_filter_title`.
- **UX-03** (`--strict` IP heuristic): Reproduction check confirmed current regex (`\w+=...` form) no longer false-positives on bare infrastructure IPs in prose (e.g. "Veeam servers at 10.10.5.20"). Closed as verified non-reproducible. No escape hatch needed.

Negative fixture `missing_expires_on.yml` (accept-risk) continues to fail as expected.

## What worked well

- **`ddr validate`** — correct on all 7 records after fixing the `evidence.type` and `expires_on` issues above. Error messages are specific and actionable.
- **`ddr expire-check`** — table and JSON output both clean; correctly surfaced the two accept-risk records expiring within 200 days. The `--days-ahead` flag is the right UX for a pre-commit or cron context.
- **Negative validation** — all three negative cases (missing `expires_on`, unknown top-level field, bad hash format) rejected with clear error messages.
- **`ddr export-sigma-filter`** (after fix) — round-trip through pySigma `SigmaFilter.from_dict()` passes for all 4 suppress records. Filter applies correctly to base Sigma rule and surfaces as a `NOT (...)` clause in converted SPL.
- **`ddr new` logsource pull** — correctly extracts `category`/`product`/`service` from each rule's logsource, including the Zeek-specific `product: zeek` cases. The `definition:` field in the LSASS logsource was correctly stripped during export.
- **Discriminated union validation** — correct enforcement of `tuning` required for `suppress`, absent for `accept-risk`/`deprecate`.

---

## Scenarios tested

| # | Rule | Decision | Status |
|---|---|---|---|
| 01 | dns-tunneling-high-entropy-subdomains | suppress | OK |
| 02 | smb-lateral-movement-admin-shares | suppress | OK |
| 03 | statistical-beaconing-zeek-conn-log | accept-risk | OK |
| 04 | lsass-process-access-credential-dumping | suppress | OK |
| 05 | kerberoasting-rc4-downgrade | accept-risk | OK |
| 06 | aws-ec2-snapshot-exfiltration | suppress | OK |
| 07 | wmi-event-subscription-persistence | deprecate | OK (status: draft) |

| Negative case | Result |
|---|---|
| accept-risk missing `expires_on` on active record | Correctly rejected |
| Unknown top-level key | Correctly rejected |
| Bad `content_hash` format | Correctly rejected |
