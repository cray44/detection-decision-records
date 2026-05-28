# DDR Spec — v0.8 (Splunk Cloud Support)

**Status:** Released  
**Date:** 2026-05-28  
**Theme:** First-class Splunk Cloud support via servicesNS REST JSON export (file-based)

---

## 1. Overview

v0.8 extends the existing `splunk` target to accept servicesNS REST JSON exports in addition
to classic `savedsearches.conf` files. A Splunk Cloud engineer who cannot access the filesystem
can now export a saved search via the REST API and use DDR at full parity with Splunk Enterprise
users — including `query_hash` computation, `ddr refresh-hash`, and `--strict` drift detection.

No new `target.kind` is added. All v0.1–v0.7 records validate unchanged.

---

## 2. Supported Source Formats for `--target splunk`

`ddr new --target splunk <source>` now accepts three source shapes:

### 2.1 Classic Enterprise format (unchanged from v0.3/v0.4)

`savedsearches.conf` INI file, parsed by `splunk_conf.py`. Stanza `search` key is
canonicalized and hashed.

### 2.2 Full servicesNS envelope

Response from `/servicesNS/{owner}/{app}/saved/searches/{name}?output_mode=json`. Top-level
`entry` array; search is in `entry[0].content.search`; app is in `entry[0].acl.app`.

```json
{
  "entry": [
    {
      "name": "My Search",
      "acl": { "app": "DA-ESS-AccessProtection" },
      "content": { "search": "index=auth ...", "disabled": "0" }
    }
  ]
}
```

### 2.3 Content wrapper

Object with top-level `content` dict and optional `acl`:

```json
{
  "name": "My Search",
  "acl": { "app": "SA-ThreatIntelligence" },
  "content": { "search": "index=network ..." }
}
```

### 2.4 Minimal hand-crafted shape (escape hatch)

```json
{ "name": "My Search", "search": "index=auth ...", "app": "search" }
```

---

## 3. Content-Driven Detection

`ddr new --target splunk <source>` dispatches automatically:

- File with `.conf` extension → `savedsearches.conf` parser.
- File that parses as JSON and contains `entry[]`, `content.search`, or top-level `search`
  key → Cloud parser.

**Explicit override:** `--format conf|cloud-json` always wins over content detection and
is recommended when auto-detection could misfire (e.g., a `.json` file named with a `.conf`
extension).

---

## 4. Hash Identity Guarantee

The same SPL string produces the same `query_hash` regardless of source format.

**Why this works:** SPL in `.conf` files uses backslash line continuation (`\<newline>`);
SPL in servicesNS JSON is a single string with embedded `\n` characters. Both representations
pass through `canonicalize_spl` (spec/ddr-v0.4.md §6), which normalizes CRLF→LF, joins
backslash continuations, drops comment lines, and collapses whitespace before hashing.

The result: a detection migrated from Splunk Enterprise to Splunk Cloud retains its existing
DDR and `query_hash` without any modification.

---

## 5. App Precedence

When scaffolding via Cloud export:

1. `--app <value>` flag always wins; a NOTE is emitted to stderr if it overrides an extracted ACL value.
2. ACL app (`entry[0].acl.app` or `acl.app`) from the JSON.
3. Default `"search"`.

---

## 6. `--format` Flag

```
ddr new --target splunk <source> [--format conf|cloud-json]
```

- `--format conf` — force the `savedsearches.conf` parser even for `.json` files.
- `--format cloud-json` — force the Cloud parser even for `.conf`-named files.
- Omitted — content-driven detection (see §3).

---

## 7. `ddr refresh-hash` (Cloud branch)

`refresh-hash` now dispatches on the same heuristic as `ddr new`: if `path_or_url` points
to a local JSON file that matches the Cloud shape, the Cloud parser is used; otherwise the
`.conf` parser is used. The `--conf` flag works for both Enterprise and Cloud artifacts.

Remote `https://` URLs: same behavior as before — NOTE emitted, drift cannot be verified
without a local artifact.

---

## 8. `ddr validate --strict` (Cloud drift check)

`--strict` drift detection for `splunk` targets now covers Cloud JSON exports. If
`path_or_url` points to a local Cloud export, the current SPL is extracted and hashed;
a mismatch triggers the same WARN as the Enterprise path.

---

## 9. `ddr new` Positional Argument Rename

The positional argument in `ddr new` is renamed from `sigma_rule` to `source_path` in
the CLI help text to reflect that it now accepts Sigma rules, `.conf` files, Cloud JSON
exports, Elastic NDJSON, and KQL JSON. The flag semantics are unchanged.

---

## 10. KQL Target `--source-url` Fix

`_cmd_new_kql` now correctly accepts `--source-url` and uses `_compute_path_or_url` to
emit a relative or overridden `path_or_url`. Previously the CLI call passed `source_url`
but the function signature did not accept it (silent bug in v0.7.1 — only triggered when
`--source-url` was used with `--target kql-sentinel` or `--target kql-m365d`).

---

## 11. Version Pattern

`ddr_version` pattern updated from `^0\.[1234567]$` to `^0\.[12345678]$`.

Records with `"0.1"` through `"0.7"` remain valid.

---

## 12. Back-Compat Notes

- No existing field removed or renamed.
- v0.1–v0.7 records validate unchanged under v0.8 models.
- Enterprise `.conf` paths in `path_or_url` continue to work identically.
- `export-splunk` requires zero changes — the filter format is independent of source artifact type.
