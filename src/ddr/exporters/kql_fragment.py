"""Kusto | where not (...) fragment exporter for KQL-target DDR records.

Works for both kql-sentinel and kql-m365d targets. Output is a paste-in
exclusion clause — the engineer inserts it into the rule's KQL query.
"""

from __future__ import annotations

from pathlib import Path

from ddr.models.record import DDRRecord, KqlM365DTuning, KqlSentinelTuning, SuppressDecision

_KQL_TARGET_KINDS = frozenset({"kql-sentinel", "kql-m365d"})


def build_kql_fragment(record: DDRRecord) -> str:
    """Return a Kusto | where not (...) fragment string."""
    if record.target.kind not in _KQL_TARGET_KINDS:
        raise ValueError(
            f"export-kql requires target.kind kql-sentinel or kql-m365d, got '{record.target.kind}'"
        )
    if not isinstance(record.decision, SuppressDecision):
        raise ValueError(
            f"accept-risk and deprecate decisions have no KQL fragment to export "
            f"(decision.kind='{record.decision.kind}')"
        )

    tuning = record.decision.tuning
    if not isinstance(tuning, (KqlSentinelTuning, KqlM365DTuning)):
        raise ValueError(f"tuning.kind must be kql-sentinel or kql-m365d, got '{tuning.kind}'")

    expires = (
        record.lifecycle.expires_on.strftime("%Y-%m-%d")
        if record.lifecycle.expires_on
        else "no-expiry"
    )
    rationale = getattr(record.decision, "rationale", "")
    rationale_snippet = rationale[:120].rstrip() if rationale else ""

    lines = [
        f"// DDR: {record.title}",
        f"// Rationale: {rationale_snippet}",
        f"// Expires: {expires}",
        f"| where not ({tuning.kusto_filter})",
    ]
    return "\n".join(lines) + "\n"


def export_kql_fragment(
    record: DDRRecord,
    output: Path | None = None,
) -> str:
    """Build fragment and optionally write to file. Returns the fragment string."""
    fragment = build_kql_fragment(record)
    if output is not None:
        output.write_text(fragment, encoding="utf-8")
    return fragment
