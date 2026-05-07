# DDR Upstream Proposal: Detection Decision Records as a Sigma Companion Format

**Status:** Draft — for review before posting to SigmaHQ GitHub Discussions  
**Repo:** https://github.com/cray44/detection-decision-records  
**Author:** Chris Ray (@cray44)

---

## The gap

Sigma rules answer *what* to detect. Sigma Filters answer *what* to suppress.

Neither answers:

- *Why* was this suppression added?
- *Who* approved it?
- *Until when* is it valid?
- *How do we know* when it's time to revisit?

Today those answers live in Jira tickets, Slack threads, macro comments, or nowhere. They rot. Engineers inherit tuned rules with no trace of why the filter exists, and silently maintain suppressions that may no longer be accurate.

DDR fills that gap.

---

## What DDR is

Detection Decision Records is a versioned YAML format for post-deployment decisions about Sigma rules: FP suppressions, accepted-risk acknowledgments, and rule deprecations.

A DDR record wraps a Sigma Filter's suppression logic in a governance envelope — rationale, reviewer, expiry, evidence references — and exports back to a valid Sigma Filter so existing tooling continues to work unmodified.

> Sigma Filters answer *what* to suppress.  
> DDR answers *who decided, why, until when, and how to know if it's still right.*

DDR is **not**:

- A competitor to `falsepositives:` — that field is authorship documentation. DDR is operational governance.
- A competitor to Sigma Filters — DDR *produces* Sigma Filters and adds the lifecycle wrapper.
- A competitor to ADS writeups — ADS captures detection intent at authorship time. DDR captures post-deployment decisions.
- A new rule format. DDR records reference Sigma rules by ID; they never embed or replace them.
- **A Sigma spec change.** DDR is an external governance layer. It requires no modifications to the Sigma rule format, Sigma Filter format, pySigma, or sigma-cli. Teams that don't use DDR are unaffected.

---

## A concrete example

A detection team is running [proc_creation_win_sysinternals_psexec_execution](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_sysinternals_psexec_execution.yml) in production. It fires ~40 times/day from SCCM patch management agents — a 100% FP class with a distinct parent process signature.

Without DDR, the fix is: add a filter, maybe comment it, hope future-you remembers why.

With DDR:

```yaml
ddr_version: "0.1"
id: 550e8400-e29b-41d4-a716-446655440001
title: "Suppress: PsExec execution from SCCM management endpoints"
description: >
  IT Operations runs PsExec via SCCM (ccmexec.exe parent) for patch deployment.
  ~40 alerts/day, 100% FP rate from the management VLAN.
target:
  kind: sigma
  rule_ref:
    rule_id: 4a6a3b37-1bef-4741-ae2d-c34cca8c8e77
    content_hash: sha256:9f75c9941f1036d9221ff44379beb32cf4ebc71e1319ec0ee62492992a83b829
    source: sigmahq
    path_or_url: "https://github.com/SigmaHQ/sigma/blob/main/rules/windows/..."
decision:
  kind: suppress
  rationale: >
    SCCM ccmexec.exe spawning PsExec is a documented IT Ops workflow. Parent-child
    chain is distinct from attacker use (PsExec from cmd.exe or powershell.exe).
  tuning:
    filter_title: "FP Filter: PsExec from SCCM management agents"
    logsource:
      category: process_creation
      product: windows
    selections:
      known_fp_sccm_agent:
        ParentImage|endswith:
          - \CCM\ccmexec.exe
          - \SMS\Bin\ccmsetup.exe
    condition: not known_fp_sccm_agent
lifecycle:
  status: active
  created_on: "2025-10-01T14:00:00Z"
  expires_on: "2027-01-01T00:00:00Z"
  review_cadence_days: 180
provenance:
  author: alice@corp.example.com
  approved_by: bob@corp.example.com
  ticket_refs:
    - SOC-4421
  evidence:
    - type: splunk_query
      ref: "savedsearch://FP_PsExec_SCCM_Sample"
      note: "30-day query confirming all ~40 daily alerts match the SCCM parent pattern."
```

Then:

```bash
ddr validate my_suppression.yml        # validates against JSON Schema
ddr export-sigma-filter my_suppression.yml   # emits a valid Sigma Filter YAML
ddr expire-check detections/ --days-ahead 30 # surfaces records due for review
```

The exported Sigma Filter is standard — no changes to pySigma, SIEM backends, or pipelines.

---

## What's been built

| Area | Status |
|---|---|
| JSON Schema (`spec/ddr-v0.1.schema.json`) | Done — generated from Pydantic v2 models |
| CLI (`ddr new`, `validate`, `expire-check`, `export-sigma-filter`) | Done |
| 7 worked examples against real SigmaHQ rules | Done |
| 157 unit + integration tests | Passing |
| Apache-2.0 license | Aligned with SigmaHQ |

Current schema version is v0.4; it extends v0.1 with Splunk-native target support (for teams running proprietary detections alongside Sigma). The Sigma-native path is the core of the spec; Splunk support is additive.

---

## What "upstream" means — options

I'm not proposing that DDR merge into the SigmaHQ repo. Three lighter-weight outcomes would be meaningful:

1. **Blessed companion format** — SigmaHQ acknowledges DDR as a compatible governance companion, similar to how `pySigma` and `sigma-cli` are separate ecosystem projects. A link from the Sigma docs is sufficient.

2. **Co-location of DDR schema in sigma-compatible-tooling** — The JSON Schema lives in an official or community-maintained registry so tooling authors can reference it.

3. **Feedback on spec design** — Before DDR hardens at v1.0, input from Sigma maintainers on the schema design (particularly the `tuning` IR and its relationship to Sigma Filter field semantics) would prevent incompatibilities.

4. **pySigma integration point** — DDR's `export-sigma-filter` currently produces standalone Sigma Filter YAML. A natural v1.0 extension would be a pySigma processing pipeline stage that reads DDR records and injects their filters at conversion time — keeping DDR as the source of truth without requiring manual filter management. This would require Thomas Patzke's input on the right integration surface.

Any of these would constitute a "clear upstream path." I am not asking for a code merge.

---

## Questions for the Sigma maintainers

1. Is there existing or planned first-party tooling for FP-tuning governance that DDR would duplicate or conflict with?
2. Does the `tuning` IR in DDR (which mirrors Sigma Filter's `selection`/`condition` structure) align with how you intend Sigma Filters to be used?
3. Would the SigmaHQ project be open to a reference in the Sigma Filters documentation pointing to DDR as a governance companion?
4. Is there a preferred channel for this kind of ecosystem proposal (Discussion, Issue, mailing list)?

---

## Links

- Repo: https://github.com/cray44/detection-decision-records
- Spec: `spec/ddr-v0.1.md` through `spec/ddr-v0.4.md`
- Worked examples: `examples/` (7 examples, each with Sigma rule + DDR record + exported filter)
- JSON Schema: `spec/ddr-v0.1.schema.json`
