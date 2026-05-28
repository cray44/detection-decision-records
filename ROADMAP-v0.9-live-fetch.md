# DDR v0.9 (Roadmap) — Splunk Live Query Fetch

**Status:** Roadmap only — not committed
**Date:** 2026-05-27
**Theme:** Add network I/O to the CLI as its own discrete subcommand (`ddr splunk-fetch`). Cleanly separated from `ddr new` so the local-only ingestion path stays simple.

**Prerequisite:** v0.8 shipped (Splunk Cloud file-based parser + hash identity guarantee).

---

## Why a separate subcommand (not flags on `ddr new`)

- `ddr new` stayed pure-local since v0.1. Wedging HTTP into its dispatch tree expands its failure surface (DNS, TLS, auth, timeouts, 401/403/404, XML responses, proxies).
- A dedicated `ddr splunk-fetch` keeps the network concern isolated. It writes a local artifact, then the user runs the normal `ddr new --target splunk <artifact>` path. Two simple commands compose better than one complex one.
- Marginal UX delta over `curl … > export.json && ddr new …` is small; the gain is in token handling, redaction, and a uniform retry/error story.

---

## Surface

```
ddr splunk-fetch \
  --host tenant.splunkcloud.com:8089 \
  --name "Excessive Failed Logins" \
  [--owner nobody] \
  [--app search] \
  [--token TOKEN | env SPLUNK_TOKEN] \
  [--insecure] \
  [--output cloud-exports/excessive-failed-logins.json]
```

On success: writes JSON to `--output` (default `./cloud-exports/<slugified-name>.json`) and prints the suggested next command:

```
ddr new --target splunk cloud-exports/excessive-failed-logins.json
```

---

## Open Design Questions (resolve during v0.9 planning)

1. **Auth scheme.** Splunk Cloud auth tokens — `Authorization: Bearer <token>` vs `Authorization: Splunk <session_key>`. Verify against a real tenant. Document which scheme is supported; reject the other with a clear error.

2. **HTTP client.** `httpx` (one dep, clean TLS verify control, sane timeouts) vs stdlib `urllib.request` (zero deps, but `--insecure` requires custom `ssl.SSLContext` + `HTTPSHandler` wiring). **Recommendation: add `httpx` as a runtime dep.** The complexity-vs-deps tradeoff inverts once `--insecure` exists.

3. **Token redaction.** All error paths, log lines, and exceptions must scrub the token. Add a redaction helper + assert no token leak in unit tests (search captured output for the token literal).

4. **`SplunkQueryRef.fetch_url` field.** Decide pre-implementation. If added:
   - Additive optional field (default `None`).
   - Stores the original API URL even when `path_or_url` points at the local artifact.
   - Requires schema regen + version bump regex update.
   - Recommended: yes, add it. Captures provenance.

5. **TLS-insecure UX.** Loud red-on-stderr warning + write a note into the generated DDR's description (or `extensions`). Document that it is for throwaway test tenants only.

6. **Bulk fetch.** Out of scope for v0.9 (single search per invocation). Re-evaluate in v1.x.

7. **XML responses.** Reject with clear message: "Run with `output_mode=json`." JSON-only stays the contract.

---

## Tests

- Mock HTTP server (`respx` or `unittest.mock`) — no real network in CI.
- Token redaction assertions (negative grep for token string in all captured output).
- 401/403/404/timeout/DNS-failure error paths produce clean messages without token.
- `--insecure` emits warning + still works against self-signed certs.
- Local artifact written to expected path; suggested next command printed.

---

## Non-Goals for v0.9

- New target kinds.
- Elastic / Sentinel / M365D live fetch (would each require their own subcommand, evaluated separately).
- Persistent credential storage, OAuth flows, keyring integration.
- Bulk multi-search export.
- XML support.

---

## Items Pulled Forward from Original v0.8 Plan (Belong Here)

- Live-fetch flags (`--splunk-host`, `--splunk-token`, `--splunk-app`, `--splunk-owner`, `--splunk-insecure`).
- `httpx` dependency decision.
- `SplunkQueryRef.fetch_url` field.
- Auth scheme verification (Bearer vs session key).
- `--app` vs `--splunk-app` collision (resolve by reusing `--app` from existing CLI).
- All HTTP error-path handling.
- Token redaction.

---

## Items NOT in v0.9 (Further Roadmap)

- XML servicesNS export support.
- Live fetch for non-Splunk targets.
- Detection-content-repo integration (contentctl, etc.).
- Macro expansion hints.
- UI / web service / database.
