# Security Policy

## Reporting a vulnerability

Email: chrisray@pm.me. Do not open public issues for vulnerabilities.

Expect an acknowledgment within 7 days. Public disclosure will be coordinated.

## Threat model (v0.1)

DDR records are **untrusted YAML/JSON files** consumed by the CLI. Assumptions:

- DDR files may come from untrusted sources (forked repos, pull requests, vendor records).
- The CLI must not execute code embedded in records.
- The CLI must not fetch URLs referenced in `evidence.ref` or `rule_ref.path_or_url` during validation.
- YAML loading uses safe loaders only — no `!!python/object`, no arbitrary tag construction.

## Out of scope

- Tampering with already-committed DDR files in your own git history (use git's own integrity controls).
- Compromise of the upstream Sigma rules DDR records reference (track those upstream).
- The Python interpreter, Pydantic, or other dependencies — report to those projects.

## Hardening (enforced)

- All YAML loading uses `ruamel.yaml` in safe mode — no arbitrary tag construction.
- No `eval`, `exec`, `subprocess`, or `pickle` anywhere in the codebase.
- No network calls during `validate`, `expire-check`, or `export-sigma-filter`.
- `evidence` schema disallows inline content fields, enforced by Pydantic strict mode.
- Negative-fixture corpus covers adversarial YAML inputs (deeply nested aliases, unexpected types).
