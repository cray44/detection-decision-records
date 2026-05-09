"""Sigma Filter YAML exporter for DDR suppress decisions."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from ddr.models.record import DDRRecord, SuppressDecision


def _yaml() -> YAML:
    y = YAML()
    y.default_flow_style = False
    y.width = 4096
    return y


def build_sigma_filter(record: DDRRecord) -> dict[str, Any]:
    """Return a Sigma Filter dict from a suppress DDR record."""
    if not isinstance(record.decision, SuppressDecision):
        raise ValueError(
            f"export-sigma-filter requires decision.kind='suppress', got '{record.decision.kind}'"
        )

    dec = record.decision
    ls = dec.tuning.logsource

    logsource: dict[str, str] = {}
    if ls.category:
        logsource["category"] = ls.category
    if ls.product:
        logsource["product"] = ls.product
    if ls.service:
        logsource["service"] = ls.service

    # pySigma SigmaGlobalFilter expects condition and rules inside the filter block,
    # not at the top level of the document.
    filter_block: dict[str, Any] = dict(dec.tuning.selections)
    filter_block["condition"] = dec.tuning.condition
    filter_block["rules"] = [str(ref.rule_id) for ref in record.target.rule_refs]  # type: ignore[union-attr]

    return {
        "title": dec.tuning.filter_title or f"FP Filter: {record.title}",
        "name": f"filter_{record.id.hex[:8]}",
        "status": "experimental",
        "description": dec.tuning.filter_description or record.description,
        "logsource": logsource,
        "filter": filter_block,
    }


def export_to_yaml(record: DDRRecord, output: Path | None = None) -> str:
    """Serialize Sigma Filter to YAML string; write to output path if given."""
    sigma_filter = build_sigma_filter(record)
    y = _yaml()
    buf = io.StringIO()
    y.dump(sigma_filter, buf)
    result = buf.getvalue()

    if output is not None:
        output.write_text(result, encoding="utf-8")

    return result
