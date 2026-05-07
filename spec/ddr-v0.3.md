# DDR Spec v0.3

> **Status:** Implemented. Schema generated from `src/ddr/models/record.py`; machine-readable JSON Schema at `ddr-v0.3.schema.json`.

v0.3 is additive on top of v0.1/v0.2. This document covers the new features only — read `ddr-v0.1.md` for the base spec.

## What changed

DDR v0.1/v0.2 assume every record targets a Sigma rule. Real detection programs have detections that live only in the SIEM — savedsearches written in SPL, never expressed as Sigma. v0.3 lifts that assumption.

**New in v0.3:**
- `target` is a discriminated union: `kind: "sigma"` (unchanged) or `kind: "splunk"` (new).
- `tuning` inside `suppress` decisions is a discriminated union: `kind: "sigma"` (unchanged) or `kind: "splunk"` (new).
- Cross-field validator: `tuning.kind` must match `target.kind` for suppress decisions.
- `ddr_version` accepts `"0.1"`, `"0.2"`, `"0.3"`.

**Not changed:** Sigma-targeted records, all lifecycle semantics, provenance, scope, extensions.

---

## Splunk-native target

```yaml
target:
  kind: splunk
  query_ref:
    name: Excessive Failed Logins From Single Source  # savedsearch stanza name
    app: DA-ESS-AccessProtection                       # Splunk app context
    query_hash: sha256:<64 hex>                        # optional in v0.3; sha256 of normalized SPL
    path_or_url: path/to/savedsearches.conf            # optional; link to source
```

`query_hash` is optional in v0.3. v0.4 will add `ddr refresh-hash --target splunk` to automate it.

## Splunk-native tuning

Only valid with `target.kind: splunk`. The tuning block carries a raw SPL filter clause — no Sigma selections required.

```yaml
decision:
  kind: suppress
  rationale: "..."
  tuning:
    kind: splunk
    filter_title: "FP Filter: vuln scanner VLAN"         # optional
    filter_description: "Suppresses scanner noise..."    # optional
    splunk_filter: 'src_ip="10.20.30.0/24" OR user=svc_ldap_health'
```

`splunk_filter` must be a non-empty string. The author writes the FP clause in their own field vocabulary. `ddr export-splunk` wraps it in `NOT (...)` on export.

### Accepted forms for `splunk_filter`

The author may write either the raw inner clause or a pre-wrapped form:

```
src_ip="10.0.0.0/8"                    # recommended — inner clause
NOT (src_ip="10.0.0.0/8")              # also accepted — stripped and re-wrapped on export
```

### No sigma-to-spl dependency

`ddr export-splunk` on a Splunk-native record does **not** require `sigma-to-spl` to be installed. The filter is emitted verbatim (normalized). `--config` is silently ignored with a warning.

`ddr export-sigma-filter` on a Splunk-native record exits 1 with a clear error.

## Cross-field validator

For suppress decisions, `tuning.kind` must equal `target.kind`:

```
target.kind="splunk" + tuning.kind="sigma"  → ValidationError
target.kind="sigma"  + tuning.kind="splunk" → ValidationError
```

Non-suppress decisions (`accept-risk`, `deprecate`) carry no tuning and are exempt.

## Back-compat

- v0.1/v0.2 `tuning` blocks without a `kind` field load as `SigmaTuning` (kind defaults to `"sigma"`).
- `Tuning` Python import is an alias for `SigmaTuning`. Existing code unaffected.
- v0.1/v0.2 records remain fully valid under the v0.3 schema.

## When to use Splunk-native targets (escape hatch)

Use `target.kind: splunk` when:
- The detection lives in the SIEM only and was never authored in Sigma.
- Sigma cannot express the detection logic (complex aggregations, subsearches, CIDR stats conditions).
- An org is migrating between SIEMs and wants a forward-portable FP paper trail.

Splunk-native records are inherently non-portable — the `splunk_filter` uses Splunk field names and SPL syntax. The spec documents this explicitly. The preferred path is always Sigma, and this is an intentional escape hatch, not a shortcut.
