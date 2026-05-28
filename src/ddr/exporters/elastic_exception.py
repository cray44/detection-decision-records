"""Elastic Security exception list NDJSON exporter for DDR suppress decisions.

Produces one exception list item per DDR record, in Kibana 8.x NDJSON import
format (Security → Rules → Exception Lists → Import).

KQL parsing is best-effort:
  - Simple AND-chains of `field : "value"` or `field : wildcard*` conditions
    are emitted as structured entries[].
  - Anything more complex (OR, NOT, nested parens, functions) emits a MANUAL
    warning and an empty entries[] — the raw kql_filter is always preserved in
    the item description so the engineer can fill in entries manually.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from ddr.models.record import DDRRecord, ElasticTuning, SuppressDecision

# Simple single-field KQL patterns
_QUOTED_RE = re.compile(r'^([\w.]+)\s*:\s*"([^"]*)"$')
_WILDCARD_RE = re.compile(r"^([\w.]+)\s*:\s*([\w.*?/\-]+[*?][\w.*?/\-]*)$")
_UNQUOTED_RE = re.compile(r"^([\w.]+)\s*:\s*([\w./\-]+)$")

# AND-split: only split on "and" surrounded by whitespace (not inside quotes)
_AND_SPLIT_RE = re.compile(r"\s+and\s+", re.IGNORECASE)

# Detect complex KQL patterns that the simple parser cannot handle
_COMPLEX_RE = re.compile(r"[\(\)]|\bor\b|\bnot\b", re.IGNORECASE)


def _parse_simple_condition(cond: str) -> dict | None:
    """Parse a single field:value KQL condition into an Elastic exception entry.

    Returns None if the condition cannot be parsed as a simple match or wildcard.
    """
    cond = cond.strip()

    m = _QUOTED_RE.match(cond)
    if m:
        return {"field": m.group(1), "operator": "included", "type": "match", "value": m.group(2)}

    m = _WILDCARD_RE.match(cond)
    if m:
        return {
            "field": m.group(1),
            "operator": "included",
            "type": "wildcard",
            "value": m.group(2),
        }

    m = _UNQUOTED_RE.match(cond)
    if m:
        return {"field": m.group(1), "operator": "included", "type": "match", "value": m.group(2)}

    return None


def _parse_kql_filter(kql_filter: str) -> tuple[list[dict], bool]:
    """Return (entries, is_manual).

    is_manual=True means the KQL was too complex to parse; entries will be [].
    """
    kql = kql_filter.strip()

    # Detect patterns that require a full KQL parser
    if _COMPLEX_RE.search(kql):
        return [], True

    parts = _AND_SPLIT_RE.split(kql)
    entries: list[dict] = []
    for part in parts:
        entry = _parse_simple_condition(part)
        if entry is None:
            return [], True
        entries.append(entry)

    return entries, False


def build_elastic_exception(
    record: DDRRecord,
    list_id: str = "ddr-exceptions",
) -> dict:
    """Return an Elastic exception list item dict from a suppress DDR record."""
    if not isinstance(record.decision, SuppressDecision):
        raise ValueError(
            f"export-elastic-exception requires decision.kind='suppress', "
            f"got '{record.decision.kind}'"
        )
    if record.target.kind != "elastic":
        raise ValueError(
            f"export-elastic-exception requires target.kind='elastic', got '{record.target.kind}'"
        )

    tuning: ElasticTuning = record.decision.tuning  # type: ignore[assignment]
    entries, is_manual = _parse_kql_filter(tuning.kql_filter)

    name = tuning.filter_title or record.title
    description = (
        f"{tuning.filter_description or record.description}\n\n"
        f"DDR id: {record.id}\n"
        f"KQL filter: {tuning.kql_filter}"
    ).strip()

    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    item_id = f"ddr-{record.id.hex[:8]}"

    return {
        "id": str(uuid4()),
        "item_id": item_id,
        "list_id": list_id,
        "name": name,
        "description": description,
        "namespace_type": "single",
        "type": "simple",
        "entries": entries,
        "tags": ["ddr", f"ddr-id:{record.id}"],
        "os_types": [],
        "comments": [],
        "created_at": now,
        "created_by": "ddr",
        "updated_at": now,
        "updated_by": "ddr",
        "tie_breaker_id": str(uuid4()),
        "_is_manual": is_manual,
    }


def export_to_ndjson(
    record: DDRRecord,
    output: Path | None = None,
    list_id: str = "ddr-exceptions",
) -> tuple[str, bool]:
    """Return (ndjson_string, is_manual); write to output path if given.

    is_manual=True signals that the caller should print a MANUAL warning.
    """
    item = build_elastic_exception(record, list_id=list_id)
    is_manual = item.pop("_is_manual")

    ndjson = json.dumps(item, ensure_ascii=False)

    if output is not None:
        output.write_text(ndjson + "\n", encoding="utf-8")

    return ndjson, is_manual
