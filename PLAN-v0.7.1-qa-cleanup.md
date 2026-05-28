# DDR v0.7.1 — QA Cleanup + Polish (Patch Release)

**Status:** Draft
**Date:** 2026-05-27
**Theme:** Close all QA findings from `qa/QA-FINDINGS.md`, eliminate hardcoded version strings, no schema/feature changes. Pure quality patch on top of v0.7.

**Schema version:** stays at `0.7`. No regex change. No new examples required.

---

## Scope

### In
- QA findings closure (5 items, mostly doc/test work since most fixes already shipped)
- UX-01: relative `path_or_url` + `--source-url` override across all scaffolds
- UX-03: `--strict` IP-heuristic tweak (with revised approach — see below)
- `LATEST_DDR_VERSION` constant in `cli.py` (single source of truth)
- `qa/QA-FINDINGS.md` "Closed in v0.7.1" section with commit links

### Out (deferred to v0.8 or later)
- Splunk Cloud parser
- Live fetch
- Any schema/model changes (additive or otherwise)
- New examples or design docs
- New target kinds

---

## Work Items

### 1. Closure-only (no code change needed — verified in 2nd-pass audit)

| ID | Status | Deliverable |
|---|---|---|
| SCHEMA-01 (`note` enum) | Already in `record.py:64` | Spec note + changelog entry + regression test |
| SCHEMA-02 (deprecate exempt) | Already in `record.py:469-474` | Spec note + changelog entry + regression test confirming `deprecate`+`active`+no `expires_on` validates |
| UX-02 (`filter_title` scaffold) | Already in all four suppress scaffolds | Single regression unit test asserting every suppress scaffold emits `filter_title` |

These shouldn't be "five items to fix" — they're three test-only tasks.

### 2. UX-01 — Relative paths + `--source-url`

- Default behavior in every `ddr new` scaffold (sigma, splunk Enterprise, elastic, sentinel, m365d):
  - If source file is under CWD (or under the `--output` dir's parent), compute relative path.
  - Otherwise fall back to absolute + one-line stderr NOTE suggesting `--source-url`.
- Add `--source-url <string>` flag — overrides `path_or_url` value entirely. **Metadata only; hash still comes from the positional source file.** State this in `--help`.
- Per-target regression tests (not just one shared test).

### 3. UX-03 — `--strict` IP heuristic (revised)

Original plan proposed an allowlist of field names. **Reject that** — it misses custom fields (`src=`, `c_ip=`, `remote_addr=`). Current `\w+=(?:\d{1,3}\.){3}\d{1,3}\b` already avoids bare-IP false positives in prose like "Veeam servers at 10.10.5.20".

**Revised approach:** keep the existing `\w+=ip` arm; the bug in the QA finding was that the test record had `src_ip=10.10.5.20` *inside the rationale prose*, not bare IPs. Re-read the QA evidence before changing the regex. If a real FP still exists, add `--no-strict-ip-lint` escape hatch instead of narrowing the pattern.

**Action:** verify the original FP scenario against the current regex first. If reproducible, add the escape-hatch flag. If not reproducible (regex was already tightened), mark UX-03 closed with a "verified non-reproducible" note.

### 4. Hardcoded `ddr_version` strings → constant

- Add `LATEST_DDR_VERSION = "0.7"` at top of `cli.py`.
- Replace literals at `cli.py:188, 259, 332, 426, 525`.
- Next bump (v0.8) becomes a one-line change.

### 5. Negative-fixture confirmation

`tests/fixtures/negative/missing_expires_on.yml` is `accept-risk` + `active` (not `deprecate`). Confirm test still rejects it post-SCHEMA-02 docs work. No fixture change.

---

## Tests

- 3 regression tests for the already-shipped fixes (SCHEMA-01/02, UX-02).
- 5–8 per-target tests for UX-01 (relative path in CWD case, absolute-path fallback case, `--source-url` override case — per target kind).
- 1 verification test for UX-03 (or escape-hatch test if added).
- `ruff check && ruff format --check` clean.
- `pytest` green on Linux + Windows.
- All 11 examples revalidate unchanged.

---

## Deliverables

```
src/ddr/cli.py                             (LATEST_DDR_VERSION + UX-01 + maybe UX-03)
tests/test_cli.py                          (UX-01 per-target + UX-03)
tests/test_models.py                       (3 closure regression tests)
spec/CHANGELOG.md                          (0.7.1 entry)
CHANGELOG.md                               (0.7.1 entry)
qa/QA-FINDINGS.md                          ("Closed in v0.7.1" section w/ commit refs)
pyproject.toml                             (version 0.7.1)
```

No schema regen. No new docs. No example changes. No `CLAUDE.md` refresh (save for v0.8).

---

## Order

1. `LATEST_DDR_VERSION` constant + literal replacement (mechanical, low risk).
2. UX-01 across all targets + per-target tests.
3. UX-03 reproduction check; act based on outcome.
4. Three closure regression tests.
5. CHANGELOG + QA-FINDINGS update.
6. Tag `v0.7.1`.

Total estimated blast radius: ~6 files, ~10 tests. One-day patch.
