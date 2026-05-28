# DDR v0.8 — Design Considerations / Plan Review

**Date:** 2026-05-27
**Reviewer:** Claude (Opus 4.7)
**Subject:** Review of `PLAN-v0.8-splunk-cloud.md`

---

## Biggest concern: scope

This is a lot for one minor: Cloud parser + **live HTTP fetch** + 5 QA fixes + relative-path refactor across **all** target scaffolds + new example + design doc + spec update + CLAUDE refresh + (sneaky) "refactor existing splunk new paths to share common scaffold builder." Any one of those slipping cascades into the others. Two obvious splits:

- **v0.8 = Cloud parser (file-only) + 5 QA fixes + docs.** Ship.
- **v0.9 = live fetch as its own `ddr splunk-fetch` subcommand.** Cleaner separation, no network code wedged into `ddr new`'s dispatch.

## Live fetch — strongest reason to cut from v0.8

- Brings network I/O, TLS, auth, redaction into a CLI that's been pure-local. New failure surface (DNS, certs, timeouts, 401/403/404, XML responses, proxies).
- You already concluded Option A is preferred (write local artifact, set `path_or_url` to it). At that point the marginal value over `curl … | ddr new --target splunk -` (or `ddr new --target splunk export.json`) is small. Docs + a one-liner curl gets 90% of the UX for 5% of the code.
- "Prefer stdlib urllib for zero deps" — urllib + bearer + TLS verify control + timeouts + redaction is genuinely worse than `httpx`. If you keep live-fetch, just add `httpx`. Don't martyr yourself for a dep count.
- Splunk Cloud auth: verify the actual scheme. Splunkd typically takes `Authorization: Bearer <token>` for auth tokens, but session-key flow is `Authorization: Splunk <key>`. Plan assumes Bearer — confirm against a real tenant before coding.

## Auto-detection by content — add an explicit override

`.conf` vs servicesNS JSON vs minimal JSON inference is clever but fragile, especially for the "minimal hand-crafted JSON" escape hatch. Add `--format conf|cloud-json` as an explicit override even though it's usually inferred. Saves a confused user 20 minutes when sniffing misfires.

## Hash identity — make the test brutal

The strongest selling point of v0.8. But SPL in `.conf` uses backslash line continuation (`\<newline>`); SPL in servicesNS JSON is one string with `\n` (or `\r\n`). The plan says "re-use the exact same canonicalize" — make sure canonicalize **already** normalizes continuations + line endings, or extend it. Specific test: take Example 06's SPL, build a fake servicesNS JSON, hash both → assert equal. Plan mentions this; promote it to a release blocker, not just a test.

## `--source-url` semantics need one more sentence

What's the contract? My read: positional path = where content is read from (drives hash); `--source-url` = metadata-only override for `path_or_url`. State that explicitly; otherwise users will assume `--source-url` triggers a fetch.

## UX-01 refactor scope

Applying relative-path logic to **every** `ddr new` target = touching sigma, splunk Enterprise, splunk Cloud, elastic, sentinel, m365d scaffolds. Add explicit regression tests per target, not just the new Cloud path. This is where v0.8 will silently break v0.7 behavior.

## SCHEMA-02 — one-line rationale missing

You relax the validator for `deprecate` + `active`. Worth noting in spec *why* you didn't add a `deprecated` status: it would force every consumer that pattern-matches on `LifecycleStatus` to handle a new variant. Relaxation is back-compat safe; new enum value isn't.

## Alpha → Beta

Don't. Beta = stronger back-compat burden. Stay Alpha through v0.8; promote at v1.0 when schema feels frozen. (Plan already says "only if author decides" — vote no.)

## Small stuff

- Step 5 in the locked order ("confirm export-splunk needs zero changes") isn't a step. Fold into 2/3.
- The "share common scaffold builder where possible" line in step 3 is the kind of cleanup that eats a day. Either budget for it as its own step or explicitly defer.
- Add to deliverables: update the `ddr_version` regex **test** (asserts rejection of `"0.8"` today). Easy to forget.
- `qa/QA-FINDINGS.md` "Closed in v0.8" section is good — also link each fix to its commit/PR for traceability.

## Net

Plan is thorough and the technical direction is right. The risk is breadth, not depth. Strongest single edit: **cut live-fetch from v0.8.** Second strongest: **explicit `--format` override.** Everything else is polish.

---

## Second Pass Review (2026-05-27) — Codebase-Audited Findings

Verified against current `src/`, `tests/`, `examples/`, and `qa/`. Finds fall into three buckets: already-shipped, real bugs, and design gaps.

### Already Fixed in Code (plan lists as work, but no code change needed)

1. **SCHEMA-01 (`note` enum value)** — `EvidenceType` already has `note = "note"` at `record.py:64`. Must have been added post-QA. Plan step 1 is a no-op for the model; only the spec/changelog delta is real work.

2. **SCHEMA-02 (`expires_on` exemption for deprecate)** — The cross-field validator at `record.py:469-474` already exempts `DeprecateDecision`:
   ```python
   and not isinstance(self.decision, DeprecateDecision)
   ```
   No model change needed. Only test/fixtures/spec delta remains.

3. **UX-02 (`filter_title` in scaffolds)** — All four suppress scaffolds already include `filter_title: "TODO: descriptive filter name"`. The only deliverable is the regression unit test. This should not be counted as "one of five findings to fix" — it's a test-only task.

### Real Bugs / Must-Fix Before Implementation

4. **`test_ddr_version_08_rejected` (test_models.py:995-997)** — This test explicitly asserts that `ddr_version: "0.8"` is **invalid**. When you extend the regex to `^0\.[12345678]$`, this test will flip from pass to fail. The plan doesn't mention converting it. **Add `test_ddr_version_08_accepted` and delete/rewrite the rejection test for `0.9`.** Step 1 of the locked order will break CI immediately without this.

5. **Hardcoded `ddr_version` strings** — `cli.py` has `"0.6"` at lines 188, 259, 426, 525 and `"0.7"` at line 332. Plan says "remove all hardcoded older strings" but proposes no `LATEST_DDR_VERSION` constant. **Define `LATEST_DDR_VERSION = "0.8"` once at module level** so the next bump is a one-line change, not a five-site hunt.

### Design Concerns Worth Reconsidering

6. **UX-03 regex tightening** — The current `\w+=(?:\d{1,3}\.){3}\d{1,3}\b` already avoids bare-IP false positives. The plan's proposed allowlist (`src_ip|dest_ip|ip|host|clientip|...`) is **more restrictive** and will miss custom sourcetype fields like `src=1.2.3.4`, `remote_addr=1.2.3.4`, or `c_ip=1.2.3.4`. The existing `\w+=` pattern is broader but less likely to produce false negatives. Keep `\w+=` or explicitly document the coverage tradeoff and provide an escape hatch (e.g., `--strict-no-ip-lint`).

7. **`--app` vs `--splunk-app`** — The existing CLI already has `--app` (cli.py:106-109) for the Splunk app context. The plan adds `--splunk-app` for the live-fetch path. Two overlapping flags will confuse users. **Reuse `--app` for both codepaths** or document the relationship explicitly in `--help`.

8. **`SplunkQueryRef.fetch_url`** — Listed as "may receive one new optional field." Decide before implementation starts. If added, it affects schema export, model tests, and the version regex (which must allow `0.8`). If deferred, say so explicitly and remove it from the step-5 deliverable.

9. **stdlib `urllib` vs `httpx` for live fetch** — The plan says "prefer stdlib" but implementing `--splunk-insecure` (skip TLS verify) with `urllib.request` requires custom `ssl.SSLContext` + `HTTPSHandler` wiring. `httpx` makes this trivial (`verify=False`). Given this is the only HTTP feature in the CLI, the one dependency is worth the saved complexity. If you keep live-fetch (see first-review recommendation to cut it), just add `httpx`.

10. **Positional arg naming** — `cmd_new` names its positional `sigma_rule` (cli.py:87-90). When this path doubles as a Splunk Cloud JSON input, the name is misleading. Rename to `source_path` or `input_path` with updated help text.

11. **Cloud `app` precedence** — When a servicesNS JSON provides `acl.app` (e.g., `"DA-ESS-AccessProtection"`) and the user also passes `--app`, which wins? The Enterprise path uses `--app` as override when path inference fails. **Recommend: CLI flag always wins, emit a NOTE on stderr when overriding an inferred/extracted value.**

### Minor / Nitpicks

12. **Example `ddr_version` values** — The plan says "11 existing examples + 1 new" must validate. Examples 01-05 use `"0.1"`, 06-08 use `"0.5"`, 09 uses `"0.6"`, 10-11 use `"0.7"`. All are within the current regex `^0\.[1234567]$`. After the regex update, they remain valid. Just confirm that **no existing fixture or example file should be bumped to `"0.8"`** — they represent records created in older spec versions and should stay as-is.

13. **Negative fixtures** — `tests/fixtures/negative/missing_expires_on.yml` is an `accept-risk` + `active` record without `expires_on`. After the SCHEMA-02 relaxation, this fixture will **stop being invalid** for `deprecate` + `active`, but it should remain invalid for `accept-risk` + `active`. Verify the test still catches the right failure mode — the fixture is specifically `kind: accept-risk`, so the validator won't exempt it. No change needed, but worth a confirming assertion.

14. **`qa/` directory records** — All 7 QA fixture files use `ddr_version: '0.1'` (YAML bare string, not quoted). After the regex change these still validate fine. No action, just awareness.
