# DDR v0.8 — Splunk Cloud Support + Polish + Doc Refresh (Locked Plan)

**Status:** Plan locked after review with author (Chris Ray)  
**Date:** 2026-05-14  
**Theme:** Make the existing `splunk` target first-class for Splunk Cloud (servicesNS REST JSON + live fetch) while extending the Enterprise path, fixing the five visible QA findings from qa/QA-FINDINGS.md, and delivering full minor-release polish + documentation refresh.  
**Decided approach:** Extend the existing `splunk` target (no new `splunk-cloud` kind). Use automatic content/structure detection. Primary Cloud artifact = full servicesNS REST JSON. Live fetch supported in `ddr new`.

---

## 1. Refined Goal & Success Criteria

### Primary Goal
A detection engineer using **Splunk Cloud** (no filesystem access to `savedsearches.conf`) can treat DDR as a first-class governance tool at parity with Splunk Enterprise users:

- `ddr new --target splunk cloud-export.json` (or live fetch) produces a fully-populated DDR with correct `query_hash`, `name`, `app`, and `path_or_url`.
- `ddr refresh-hash` and `ddr validate --strict` correctly detect drift when the Cloud-side search definition changes.
- `ddr export-splunk` works identically (raw SPL filter → `NOT (...)` or savedsearches stanza).
- The same logical search produces **identical** `query_hash` whether the source artifact was a classic Enterprise `savedsearches.conf` or a Cloud servicesNS export (critical for migration/portability stories).

### Secondary Goals (Polish + Flagship Quality)
- Close the five still-visible items from `qa/QA-FINDINGS.md` (v0.4 era) that remain relevant in v0.7.
- Eliminate all hardcoded old `ddr_version` strings in scaffolds (`"0.6"` etc.).
- Update stale in-repo documentation (CLAUDE.md, README gaps on Cloud, design docs).
- Deliver a high-quality new worked example + refreshed docs so the project continues to demonstrate detection-engineering craft.

### Measurable Success Criteria (all must pass for release)
1. `pytest` green on Linux + Windows (CI matrix) with no regressions.
2. All 11 existing examples + 1 new Cloud example validate cleanly (`ddr validate examples/`).
3. Schema drift check passes after regeneration (`spec/ddr-v0.8.schema.json`).
4. `ruff check && ruff format --check` clean.
5. `ddr new --target splunk` on a realistic servicesNS JSON produces correct `query_hash` (matches Enterprise path for identical SPL).
6. Live fetch path (`ddr new --target splunk --splunk-host ... --token ...`) succeeds in a test harness without embedding secrets.
7. `ddr refresh-hash` and `--strict` drift warnings work for Cloud artifacts (local JSON export).
8. All five QA findings items have either a fix or an explicit, documented deferral with rationale.
9. README contains a clear "Splunk Cloud" section with curl one-liner + live-fetch example.
10. New design doc `docs/design/v0.8-splunk-cloud.md` exists and is referenced from README + spec.
11. Root + spec CHANGELOG entries are complete and conventional.
12. `pyproject.toml` version = `0.8.0`; classifiers still "Alpha" or bumped to "Beta" only if author decides.

### Non-Goals (Explicitly Out of Scope for v0.8)
- New `target.kind: "splunk-cloud"` (or any new discriminated union member).
- Changes to SPL canonicalization algorithm or `export-splunk` output shape.
- Support for XML exports (JSON only for v0.8; XML can be a future additive).
- Token storage, OAuth flows, or any persistent credential management.
- Live fetch for any target other than Splunk.
- UI, web service, or database features.
- Breaking changes to v0.1–v0.7 records.

---

## 2. Proposed Changes / Feature Breakdown

### 2.1 Core Technical Approach (Locked)

**Extend the existing `splunk` target only.**  
`target.kind` remains `"splunk"`. `SplunkQueryRef`, `SplunkTarget`, and `SplunkTuning` are unchanged (or receive only additive optional fields if truly required).

Detection of artifact type is **automatic and content-driven** (no mandatory `--cloud` flag for the common case):
- Classic path: input ends with `.conf` **or** top-level structure is INI-style with `[Stanza]` sections → use existing `splunk_conf.py` parser.
- Cloud path: input is JSON with characteristic servicesNS envelope (`entry`, `content`, `search`, `acl`, `author`, etc.) → use new cloud parser.

This keeps CLI surface minimal and matches the "it just works" UX of other targets (e.g., `.ndjson` inference for Elastic).

### 2.2 New Internal Module: `src/ddr/_internal/splunk_cloud.py`

Responsibilities (parallel to `splunk_conf.py`):
- `parse_servicesns_export(path: Path) -> dict` — load JSON, unwrap common envelopes, return normalized dict with at minimum: `name`, `app` (or owner/app), `search` (raw SPL), plus any useful metadata (`disabled`, `is_scheduled`, etc.).
- `extract_search_from_servicesns(obj: dict) -> tuple[str, str, str | None]` — (name, search_string, app_or_none).
- Re-use the **exact same** `canonicalize_spl(query)` and `compute_query_hash(query)` from `splunk_conf` (import, do not copy). Hash identity guarantee is non-negotiable.
- Support the primary shape: full servicesNS REST response (single search object or the `entry[0].content` shape returned by `/servicesNS/.../saved/searches/<name>`).
- Graceful fallback / clear error for other shapes (minimal hand-crafted JSON with `name` + `search` + optional `app` is acceptable as a documented escape hatch).

Canonicalization identity proof: the same SPL string must produce the identical `sha256:...` whether it came from a `.conf` stanza or a servicesNS `search` field.

### 2.3 CLI Changes (`src/ddr/cli.py`)

**`ddr new --target splunk`**
- Existing behavior for `.conf` paths unchanged.
- When positional argument is a `.json` (or content sniff detects servicesNS shape), route to new `_cmd_new_splunk_from_cloud_export(...)`.
- New optional flags for **live fetch** (all optional, never required):
  - `--splunk-host <host:port>` (e.g. `mytenant.splunkcloud.com:8089`)
  - `--splunk-token <token>` (or read from `SPLUNK_TOKEN` / `SPLUNK_CLOUD_TOKEN` env var)
  - `--splunk-app <app>` (override; otherwise infer from ACL or default to "search")
  - `--splunk-owner <owner>` (default "nobody" or current user context)
  - `--splunk-insecure` (allow self-signed / skip TLS verify — emit loud warning)
- Live fetch path:
  - Builds `https://{host}/servicesNS/{owner}/{app}/saved/searches/{name}?output_mode=json`
  - Uses `Authorization: Bearer {token}` (or Splunk's session key form if needed)
  - Timeouts (reasonable default, e.g. 30s), clear error on 401/403/404
  - **Never** logs the token (even on error paths). Use `typer.echo(..., err=True)` only for non-sensitive parts.
  - On success, writes a local artifact copy (next to the DDR or in a conventional location) and sets `path_or_url` to that local copy (or the API URL + note). See path handling below.
- When `--splunk-host` is supplied without a positional path, the command requires `--name` (stanza/search name).

**`ddr refresh-hash`**
- Existing `--conf` flag continues to work for Enterprise.
- Add `--export <path>` (or reuse `--conf` with content detection) for Cloud JSON exports.
- For live Cloud records: if `path_or_url` is an `https://...servicesNS...` URL, `refresh-hash` without an override emits a clear NOTE + error telling the user to provide a local export (consistent with current remote-URL behavior for other targets).

**`ddr validate --strict`**
- Extend `_strict_splunk_drift_check` with a Cloud branch (parallel to existing Enterprise branch).
- If `path_or_url` ends in `.json` and contains servicesNS keys, use the cloud parser + `compute_query_hash`.
- Remote HTTPS URLs → same "NOTE: drift cannot be verified for remote path_or_url" behavior as today.

**Scaffold version emission**
- All `ddr new` paths (sigma, splunk Enterprise, splunk Cloud, elastic, kql-*) must emit `ddr_version: "0.8"` (or the current latest at release time). Remove all hardcoded older strings.

### 2.4 Path / URL Semantics for Cloud Records (Important UX Detail)

For Cloud records created via local export file:
- `path_or_url` = relative or absolute path to the **local JSON export artifact** (the stable snapshot the hash was computed from).
- This mirrors the Enterprise pattern (`path_or_url` points at the `savedsearches.conf` that supplied the hash).

For records created via live fetch:
- Two acceptable choices (pick one and document clearly):
  - Option A (preferred for drift friendliness): After successful fetch, write the JSON response to a local file next to the DDR (or in `cloud-exports/`) and set `path_or_url` to that local file. Also store the original API URL in a new optional field `source_url` or inside `extensions`.
  - Option B: Set `path_or_url` to the API URL (https form) and document that drift checks are skipped (same as current remote behavior).

Recommendation in this plan: **Option A** (write local artifact + set `path_or_url` to it). This gives users the same drift-check experience as Enterprise. The original fetch URL can be captured in a comment or a new optional `query_refs[].fetch_url` field (additive, optional).

### 2.5 QA Findings Fixes (All Five Addressed)

**SCHEMA-01 — `evidence.type` missing `"note"`**
- Add `note = "note"` to `EvidenceType` StrEnum in `models/record.py`.
- Update `spec/ddr-v0.8.md` (or the v0.8 section of spec/CHANGELOG) and the prose spec.
- No migration needed (additive enum value). Old records using `other` for notes remain valid.

**SCHEMA-02 — `expires_on` required for active `deprecate` records**
- Modify the cross-field validator in `DDRRecord.check_record_constraints` (or the `Lifecycle` validator):
  - `expires_on` is required for `active` **only when** `decision.kind != "deprecate"`.
- Update the model validator error message.
- Update `spec/ddr-v0.8.md` § on Lifecycle constraints.
- Add a back-compat note: existing v0.1–v0.7 deprecate records that used `draft` status as a workaround can now be promoted to `active` without `expires_on`.

**UX-01 — Absolute Windows paths baked into `path_or_url` on `ddr new`**
- In every `_cmd_new_*` scaffold path:
  - Default behavior: if the source file is under CWD, compute a **relative** path from CWD (or from the output DDR location if `--output` is given).
  - If the source is outside CWD or on a different drive, fall back to the original behavior but emit a one-line NOTE suggesting `--source-url` or manual edit.
  - New optional flag: `--source-url <url-or-relative>` — overrides the `path_or_url` value entirely (useful for GitHub permalinks).
- Update all call sites (sigma, splunk Enterprise, splunk Cloud, elastic, KQL).
- Document the new flag in `--help` and README.

**UX-02 — `filter_title` missing from some scaffolds**
- Audit confirms it is already present in the four main suppress scaffolds (sigma, splunk, elastic, kql).
- Add an explicit unit test that every suppress scaffold path emits a `filter_title` key under `decision.tuning`.
- If any edge path (e.g. `ddr new --decision deprecate`) ever leaks a tuning block, it is already guarded by the discriminated union.

**UX-03 — `--strict` false-positive on infrastructure IPs in prose**
- Current regex in `cli.py`:
  ```python
  _LOG_LINE_RE = re.compile(
      r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
      r"|(\w+=(?:\d{1,3}\.){3}\d{1,3}\b)"
      r"|(\w+=\w+\|\w+=\w+)"
  )
  ```
- Change the IP arm to require a **log-line context prefix**:
  ```python
  r"|(?:src_ip|dest_ip|ip|host|clientip|source_ip|destination_ip|id\.orig_h|id\.resp_h)\s*[:=]\s*(?:\d{1,3}\.){3}\d{1,3}\b"
  ```
- Keep the existing bare-IP false-positive test cases; add new negative tests for prose containing "10.10.5.20 and 10.10.5.21 are our Veeam backup servers".
- The heuristic remains deliberately conservative (warn-only).

### 2.6 Documentation Deliverables

- New design doc: `docs/design/v0.8-splunk-cloud.md` (this plan, plus rationale for content-driven detection, hash identity guarantee, live-fetch security model).
- README.md updates:
  - New "Splunk Cloud" subsection under Quickstart / Targets.
  - Recommended one-liner `curl` to produce a stable local export artifact.
  - Live-fetch example with env var.
  - Note about hash identity between Enterprise and Cloud for the same SPL.
- `spec/ddr-v0.8.md` (or v0.8 delta section) covering:
  - Automatic detection rules.
  - Supported servicesNS JSON shapes.
  - Live fetch behavior and security notes.
  - Updated Lifecycle constraint for deprecate.
  - New `evidence.type: "note"`.
- `examples/12-splunk-cloud-rest-export/` (new directory):
  - `cloud-export.json` (realistic redacted servicesNS response)
  - `ddr.yml`
  - `splunk-fragment.spl` (generated)
  - `README.md` explaining creation workflow + drift story.
- Update `examples/README.md` and root `examples/` table.
- `spec/CHANGELOG.md` + root `CHANGELOG.md` entries (full 0.8.0 section).
- Update in-repo `CLAUDE.md` (current state + v0.8 scope summary).

### 2.7 Schema & Versioning

- `ddr_version` pattern updated to `^0\.[12345678]$`.
- `spec/ddr-v0.8.schema.json` regenerated from models (even if the only model changes are the `EvidenceType` addition and validator relaxation).
- No removal or rename of any existing field. All v0.1–v0.7 records remain valid.
- `SplunkQueryRef` may receive one new optional field (`fetch_url` or similar) — if added it must be optional with default `None`.

---

## 3. Impact

| Area                  | Impact                                                                 |
|-----------------------|------------------------------------------------------------------------|
| Schema                | Additive only: new enum value + relaxed deprecate constraint. v0.1–v0.7 records untouched. |
| Models                | `EvidenceType` addition; minor validator tweak in `DDRRecord` or `Lifecycle`. |
| New code              | `src/ddr/_internal/splunk_cloud.py` (parser + extractor). CLI branches for Cloud + live fetch. |
| CLI surface           | New optional flags for live fetch (all gated behind `--target splunk`). No breaking flag changes. |
| Public API            | New exports from `splunk_cloud` module if author wants them public (parallel to `splunk_conf`). |
| Examples              | 1 new (12). Existing 11 unchanged. One existing Splunk example may be lightly refreshed. |
| Tests                 | ~25–35 new (parser unit tests, CLI integration for Cloud paths, live-fetch harness with mocks, hash-identity tests, QA-finding regression tests). |
| Runtime deps          | None. Uses `httpx` or stdlib `urllib` + `json` (prefer stdlib for v0.8 to keep dep count at zero for this feature). |
| Docs                  | New design doc, README section, example README, spec update, CLAUDE.md refresh. |
| CI / Release          | New CI step exercising Cloud parser on golden export. Schema drift now covers v0.8. |

---

## 4. Edge Cases & Error Handling (Exhaustive)

### 4.1 Automatic Detection
- File with `.conf` extension but servicesNS-looking JSON inside → treat as Cloud (content wins) + emit NOTE.
- File with `.json` extension but classic INI content → error with "expected servicesNS export or minimal Cloud JSON; got something that looks like a .conf".
- Ambiguous minimal JSON (has `search` and `name` but no servicesNS envelope) → accept it, document the shape, compute hash, set `app` from flag or default.

### 4.2 Live Fetch
- Token provided via flag **and** env var → flag wins, emit one-line NOTE.
- Token appears in any log line or error message → hard failure in development; in prod the code must use redaction helpers.
- 401/403 → clear message: "Authentication failed. Check token scope (need `search` or `admin` capability on the app)."
- 404 → "Search 'Excessive Failed Logins' not found in app 'DA-ESS-AccessProtection' on host X. Did you use the correct --splunk-owner?"
- Self-signed cert without `--splunk-insecure` → fail with "TLS verification failed. Use --splunk-insecure only for testing (loud warning emitted if used)."
- `--splunk-insecure` used → emit bright warning on stderr + write a note into the generated DDR's description or an extension.
- Network timeout / DNS failure → clean message with the URL attempted (token redacted).
- Response is XML instead of JSON → "This endpoint returned XML. v0.8 supports JSON only. Re-run with `output_mode=json` or convert manually."

### 4.3 Hash & Drift
- SPL extracted from Cloud export contains macros (`$macro$`) → hash proceeds (same as Enterprise). Author is responsible for macro expansion in the filter.
- Cloud search is disabled (`disabled=1` or `is_scheduled=0`) → warn exactly as the Enterprise path does today.
- servicesNS response contains `search` that is a here-doc or heavily escaped → the parser must unescape/normalize only enough to feed `canonicalize_spl` (no semantic interpretation).
- Multiple searches in one JSON (bulk export) → error "bulk exports not supported for `ddr new`; export a single search or use the minimal hand-crafted shape".

### 4.4 Path Portability (UX-01)
- Source file on different drive from output DDR → fall back to absolute + NOTE suggesting `--source-url https://github.com/...`.
- User passes `--source-url` with a GitHub blob URL → store exactly that string (no local resolution attempted).

### 4.5 Deprecate + expires_on
- `deprecate` + `status: active` + no `expires_on` → now valid.
- `deprecate` + `status: active` + `expires_on` present → still accepted (harmless).
- Old records that used `draft` for deprecate can be edited to `active` without adding `expires_on`.

### 4.6 Evidence `note` type
- New records can use `type: note` immediately.
- Old records using `other` for notes remain valid forever.

### 4.7 `--strict` regex tightening (UX-03)
- "Veeam servers at 10.10.5.20 and 10.10.5.21" → no warning.
- "src_ip=10.10.5.20" or "id.orig_h=10.10.5.20" → still warns (desired).
- Bare IPv4 in a timestamped log line → still warns.

---

## 5. Testing Strategy

### 5.1 Unit Tests (new file `tests/test_splunk_cloud.py`)
- Parser happy paths for the three most common servicesNS shapes observed in the wild.
- Extraction of `name`, `search`, `app` (from `acl.app` or `eai:acl.app` or top-level).
- Round-trip: Cloud export → `compute_query_hash` → same result as feeding the identical SPL string through the Enterprise path.
- Idempotency of canonicalize on Cloud-extracted SPL.
- Error cases: missing `search` key, empty search, malformed JSON, XML content, bulk array.
- Minimal hand-crafted shape acceptance.

### 5.2 CLI Integration Tests (`tests/test_cli.py`)
- `ddr new --target splunk cloud-export.json` → produces DDR with `query_hash`, correct `name`/`app`, `path_or_url` pointing at the export file (relative when possible).
- Same command with `--output elsewhere/ddr.yml` → `path_or_url` is relative to `elsewhere/`.
- Live fetch path exercised via `respx` / `responses` / `unittest.mock` (no real network in CI).
- Token redaction: assert token string never appears in captured output or exceptions.
- `--splunk-insecure` emits the expected loud warning.
- `ddr refresh-hash` on a Cloud DDR with local export updates hash correctly.
- `ddr validate --strict` on a stale Cloud export emits the drift warning with correct `query_refs[N]` label.
- All five QA-finding regression tests (new enum value, deprecate without expires_on, relative path in scaffold, filter_title presence, IP heuristic negative cases).

### 5.3 Golden Files & Examples
- Add `tests/fixtures/cloud/` with 2–3 realistic redacted servicesNS JSON exports (single search, different app contexts).
- New Example 12 checked into `examples/12-splunk-cloud-rest-export/` and exercised by the "validate all examples" CI job.
- Hash-identity test: take the SPL from Example 06, wrap it in a fake servicesNS JSON, run the Cloud path, assert identical hash.

### 5.4 Live-Fetch Safety (Critical)
- All live-fetch tests use an in-process mock server or `respx`.
- No real Splunk Cloud token is ever committed or present in CI secrets for this project.
- A manual "smoke" test script can be provided in `scripts/` (gitignored) for the author to run locally against a throwaway tenant.

### 5.5 Schema & Back-compat
- Add v0.7 back-compat fixture if not already present.
- After model changes: all existing fixtures (including the 11 examples) must still validate under the v0.8 models.
- Schema export + drift check must be green.

### 5.6 Documentation Tests (light)
- README code blocks that are commands should be manually verified during release.
- The curl one-liner in the Cloud section must produce a file that `ddr new` accepts.

---

## 6. Sigma Compatibility & Ecosystem Fit

- No impact on Sigma-targeted records or the sigma-to-spl export path.
- Strengthens the overall story: "DDR gives you the same governance experience whether your detection is Sigma, native Splunk Enterprise, Splunk Cloud, Elastic, Sentinel, or M365D."
- The hash-identity guarantee between Enterprise and Cloud is a powerful migration/portability narrative ("I can move this detection from on-prem to Cloud and the DDR still makes sense").
- Splunk-native records remain the explicit escape hatch (as documented since v0.3). Nothing in v0.8 changes that philosophy.

---

## 7. Final Plan Summary + Locked Implementation Order

v0.8 closes the most visible real-world gap for the Splunk detection community (Cloud) while simultaneously raising the overall polish bar on the flagship project. The approach (extend existing `splunk` target + automatic detection + live fetch + hash identity + five QA fixes + docs) is additive, low-risk, and fully back-compatible.

### Locked Step-by-Step Implementation Order (do not reorder without re-review)

1. **Models & validators (smallest blast radius first)**
   - Add `"note"` to `EvidenceType`.
   - Relax the `expires_on` requirement for `deprecate` + `active` in the `DDRRecord` (or `Lifecycle`) validator.
   - Update `__all__` and any related exports.
   - Add unit tests for the two schema changes.

2. **New module `src/ddr/_internal/splunk_cloud.py`**
   - Implement parser + extractor for primary servicesNS JSON shapes.
   - Re-export / import `canonicalize_spl` and `compute_query_hash` from `splunk_conf`.
   - Write comprehensive unit tests (parser + hash identity).

3. **CLI scaffolding & detection logic**
   - Refactor existing splunk `new` paths to share common scaffold builder where possible.
   - Implement content-based dispatch (`.conf` vs servicesNS JSON vs minimal Cloud JSON).
   - Implement `_cmd_new_splunk_from_cloud_export`.
   - Implement live-fetch helper (httpx or urllib, token handling from flag+env, redaction, timeouts, TLS warning).
   - Fix all `ddr_version` hardcodes to emit current latest ("0.8").
   - Implement `--source-url` override + relative-path logic for **all** `ddr new` target kinds.
   - Update `refresh-hash` and `_strict_splunk_drift_check` with Cloud branches.

4. **QA finding UX-03 (regex)**
   - Tighten `_LOG_LINE_RE` IP arm.
   - Add negative test cases for prose infrastructure IPs.

5. **Export path & any minor model tweaks**
   - Confirm `export-splunk` needs zero changes (it should not).
   - If `SplunkQueryRef` gains an optional `fetch_url`, add it here.

6. **Tests (parallelizable with 3–5)**
   - New `test_splunk_cloud.py`.
   - CLI integration tests for all new paths + regression tests for the five QA items.
   - Hash-identity cross tests.
   - Update existing splunk exporter tests if any behavior subtly shifts (unlikely).

7. **Golden artifacts & new example**
   - Create realistic redacted `cloud-export.json` fixtures.
   - Build `examples/12-splunk-cloud-rest-export/` (ddr.yml, export, fragment, README).
   - Update `examples/README.md`.

8. **Documentation**
   - Write `docs/design/v0.8-splunk-cloud.md`.
   - Update root `README.md` (Cloud quickstart, curl one-liner, live-fetch example, path semantics).
   - Update `spec/ddr-v0.8.md` (or delta section) + `spec/CHANGELOG.md`.
   - Refresh in-repo `CLAUDE.md`.
   - Update any other references (CONTRIBUTING if needed).

9. **Schema & release artifacts**
   - Run schema export → `spec/ddr-v0.8.schema.json`.
   - Update root `CHANGELOG.md` with full 0.8.0 section.
   - Bump `pyproject.toml` version to `0.8.0`.
   - Final pass: `ruff`, full pytest matrix, `ddr validate examples/`, schema drift check.

10. **Release**
    - Tag `v0.8.0`, GitHub release with the new design doc + example linked.
    - (Optional but recommended) Update PyPI classifiers if moving from Alpha to Beta.

### File Layout After v0.8 (new/changed only)

```
src/ddr/_internal/splunk_cloud.py          (new)
src/ddr/models/record.py                   (EvidenceType + validator tweak)
src/ddr/cli.py                             (major extensions + cleanup)
spec/ddr-v0.8.md                           (new or delta)
spec/ddr-v0.8.schema.json                  (new, regenerated)
spec/CHANGELOG.md                          (0.8 entry)
docs/design/v0.8-splunk-cloud.md           (new — this plan + rationale)
CHANGELOG.md                               (0.8.0 entry)
README.md                                  (Cloud section + polish)
CLAUDE.md                                  (refreshed)
pyproject.toml                             (version 0.8.0)
examples/12-splunk-cloud-rest-export/      (new directory + 4 files)
tests/test_splunk_cloud.py                 (new)
tests/test_cli.py                          (+ ~20 tests)
tests/fixtures/cloud/                      (2–3 golden servicesNS JSONs)
qa/QA-FINDINGS.md                          (add "Closed in v0.8" section)
```

### Post-Release Polish Ideas (for v0.9 or later, not in this plan)
- First-class XML support for servicesNS exports.
- `ddr splunk-fetch` subcommand (separate from `new`) that only does the HTTP part and writes a stable artifact.
- Better macro expansion hints or optional macro context file.
- Integration with common contentctl / detection-content repo layouts.

---

**This plan is now locked.** Any material deviation (new target kind, different primary artifact shape, removal of live fetch, deferral of more than one QA item, etc.) requires another explicit review pass with the author before implementation begins.

**Implementation may now start.** Begin with section 1 of the locked order above.
