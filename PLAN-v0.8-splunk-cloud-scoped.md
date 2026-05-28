# DDR v0.8 — Splunk Cloud Support (File-Based, Scoped)

**Status:** Draft (re-scoped from `PLAN-v0.8-splunk-cloud.md`)
**Date:** 2026-05-27
**Theme:** Make the existing `splunk` target first-class for Splunk Cloud users via servicesNS REST **JSON file** input. No live HTTP fetch (deferred to v0.9 — see `ROADMAP-v0.9-live-fetch.md`).

**Prerequisite:** v0.7.1 shipped (`LATEST_DDR_VERSION` constant in place, UX-01 path handling already generalized across all scaffolds).

---

## Goal

A Splunk Cloud engineer (no `savedsearches.conf` filesystem access) does:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://tenant.splunkcloud.com:8089/servicesNS/nobody/search/saved/searches/MySearch?output_mode=json" \
  > cloud-export.json
ddr new --target splunk cloud-export.json
```

…and gets a fully populated DDR with correct `query_hash`, `name`, `app`, and `path_or_url`. `ddr refresh-hash` and `ddr validate --strict` detect drift correctly.

**Hash identity guarantee (release blocker):** identical SPL produces identical `query_hash` whether sourced from `.conf` or servicesNS JSON.

---

## Scope

### In
- New `src/ddr/_internal/splunk_cloud.py` — parser + extractor for servicesNS JSON.
- `ddr new --target splunk` content-driven dispatch (`.conf` vs JSON).
- `--format conf|cloud-json` explicit override flag.
- `refresh-hash` + `validate --strict` Cloud branches.
- Schema regex bump → `^0\.[12345678]$`.
- `LATEST_DDR_VERSION` constant flip from `"0.7"` to `"0.8"`.
- Convert `test_ddr_version_08_rejected` → `_accepted` + add `_09_rejected`.
- New example `examples/12-splunk-cloud-rest-export/`.
- Design doc `docs/design/v0.8-splunk-cloud.md`.
- Spec delta + CHANGELOG.
- `CLAUDE.md` refresh.
- Stay Alpha (no PyPI classifier bump).

### Out
- Live HTTP fetch (v0.9).
- XML servicesNS exports (later, if requested).
- New target kind (`splunk-cloud`) — extend existing `splunk` target only.
- Bulk-export ingestion (multi-search JSON).
- `--app`/`--splunk-app`/`--splunk-host`/`--splunk-token` flags (all live-fetch flags belong to v0.9).
- `SplunkQueryRef.fetch_url` field — **deferred to v0.9** (couples cleanly with fetch).

---

## Hash Identity — Release Blocker

SPL in `.conf` uses backslash line continuation; SPL in servicesNS JSON is one string with `\n` (or `\r\n`).

**Action before parser work begins:**
1. Audit existing `canonicalize_spl` in `splunk_conf.py` for newline + continuation normalization.
2. If gap exists, extend canonicalizer (not the Cloud parser — keep hashing logic single-sourced).
3. Brutal test: Example 06's SPL → fake servicesNS JSON wrapper → assert identical `sha256:`.
4. Add the same test with `\r\n` line endings and trailing whitespace variants.

If canonicalize already handles these, document the assertion in a comment so future maintainers don't break it.

---

## Detection Logic

Default routing (content-driven):
- `.conf` extension OR INI-shaped (`[stanza]` lines) → `splunk_conf` parser.
- `.json` extension OR JSON-parseable with servicesNS envelope (`entry[]`, `content.search`, `acl`) → `splunk_cloud` parser.
- Minimal hand-crafted JSON (`{"name": ..., "search": ..., "app": ...}`) → accepted as documented escape hatch.

**Explicit override:** `--format conf|cloud-json` always wins. Mention prominently in `--help`. Saves users 20 minutes when sniffing misfires.

---

## CLI Surface (additive only)

```
ddr new --target splunk SOURCE [--format conf|cloud-json] [--app APP] [--source-url URL]
```

- `--app` (existing flag from v0.7) → keep, applies to both Enterprise + Cloud paths.
- **Precedence for `app`:** CLI `--app` wins → else `acl.app` from JSON → else default `"search"`. Emit one-line stderr NOTE when overriding an extracted value.
- `--source-url` (from v0.7.1) → unchanged; metadata-only override for `path_or_url`.

Rename positional `sigma_rule` → `source_path` in `cmd_new` (it's now Sigma OR `.conf` OR JSON OR Elastic NDJSON OR KQL). Update help text.

---

## `refresh-hash` + `validate --strict`

- Extend `_strict_splunk_drift_check` with a JSON branch parallel to the existing `.conf` branch.
- If `path_or_url` ends `.json` and content matches servicesNS shape → use cloud parser → `compute_query_hash`.
- Same NOTE behavior as today for remote HTTPS URLs (drift cannot be verified).

---

## Schema & Versioning

- `ddr_version` regex → `^0\.[12345678]$`.
- `spec/ddr-v0.8.schema.json` regenerated from models (only delta: regex pattern).
- No model field additions.
- All v0.1–v0.7 records remain valid (additive change only).
- `LATEST_DDR_VERSION = "0.8"` (single edit; v0.7.1 already wired this).

---

## Example 12

`examples/12-splunk-cloud-rest-export/`:
- `cloud-export.json` — realistic redacted servicesNS response (single search).
- `ddr.yml` — DDR record pointing at the export.
- `splunk-fragment.spl` — generated filter.
- `README.md` — workflow: curl → `ddr new` → tune → export → drift check.

Existing 11 examples unchanged.

---

## Tests

New `tests/test_splunk_cloud.py` (~15 tests):
- Parser happy paths (2–3 servicesNS shapes from `tests/fixtures/cloud/`).
- Extraction of `name`, `search`, `app`.
- Hash identity round-trip (Example 06 SPL ↔ fake JSON).
- `\r\n` + trailing whitespace variants.
- Idempotency.
- Error cases: missing `search`, empty `search`, malformed JSON, XML, bulk array.
- Minimal hand-crafted shape acceptance.

CLI integration (`tests/test_cli.py`, ~10 tests):
- `ddr new --target splunk cloud-export.json` end-to-end.
- `--format` override (both directions, including misrouted input).
- `--app` precedence + NOTE emission.
- `refresh-hash` on a Cloud DDR with local export.
- `validate --strict` drift detection on stale Cloud export.

Model/schema:
- `test_ddr_version_08_accepted` (new — replaces rejection test).
- `test_ddr_version_09_rejected` (new — guards the next bump).
- Schema drift check passes after regen.

---

## Documentation

- `docs/design/v0.8-splunk-cloud.md` — content-driven detection, hash identity guarantee, escape hatch, scoping rationale (why no live fetch in 0.8).
- `README.md` — "Splunk Cloud" section with curl one-liner + `ddr new` invocation.
- `spec/ddr-v0.8.md` — regex bump note + cloud JSON shape support.
- `spec/CHANGELOG.md` + root `CHANGELOG.md` — 0.8.0 section.
- `CLAUDE.md` — current state + v0.8 scope summary.

---

## Order

1. **Canonicalize audit + extend if needed.** Brutal hash-identity test passes first. Without this, nothing else matters.
2. New `splunk_cloud.py` parser + unit tests.
3. CLI dispatch (`--format` override + content sniff) + `--app` precedence + NOTE.
4. `refresh-hash` + `--strict` cloud branches + tests.
5. Schema regex bump → regen schema → flip `LATEST_DDR_VERSION` → version regression tests.
6. Example 12 + fixtures.
7. Design doc + README + spec delta + CHANGELOG + CLAUDE.md.
8. `pyproject.toml` → `0.8.0`. Final `ruff` + `pytest` + `ddr validate examples/` + schema drift check.
9. Tag `v0.8.0`.

---

## Risk Register

| Risk | Mitigation |
|---|---|
| Canonicalize doesn't already normalize newline continuations | Audit first (step 1), extend if gap exists, add hash-identity tests as release blocker |
| Content sniff misroutes ambiguous JSON | `--format` explicit override available + documented in `--help` |
| User adds live-fetch flags before v0.9 | Plan explicitly excludes; reject any flag addition that smells like HTTP |
| Existing Splunk examples (06–08) break under new dispatch | Test suite covers existing `.conf` paths unchanged |
