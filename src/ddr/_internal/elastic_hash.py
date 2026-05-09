"""Elastic rule JSON canonicalization + hash — algorithm v1.

Algorithm (spec §6, v0.6):
  1. Load NDJSON: first non-empty line that parses as a JSON object.
  2. Unwrap: if top-level has a "rule" key, use obj["rule"].
  3. Strip volatile fields that change on Kibana import/export without
     affecting rule logic (revision, version, created_at, etc.).
  4. Sort mapping keys recursively.
  5. Serialize to compact JSON (sort_keys=True, no extra whitespace).
  6. UTF-8 encode → SHA-256 → "sha256:" prefix.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

_VOLATILE_FIELDS = frozenset(
    {
        "created_at",
        "updated_at",
        "created_by",
        "updated_by",
        "revision",
        "version",
        "id",
        "immutable",
        "related_integrations",
        "required_fields",
        "setup",
    }
)


def _sort_keys(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _sort_keys(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [_sort_keys(item) for item in obj]
    return obj


def _load_rule_dict(ndjson_path: Path) -> dict:
    """Return the rule dict from an NDJSON file (first parseable rule object)."""
    text = ndjson_path.read_text(encoding="utf-8-sig")  # strips BOM if present
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        # Unwrap Kibana Rules API GET response format {"rule": {...}}
        if "rule" in obj and isinstance(obj["rule"], dict) and len(obj) <= 3:
            return obj["rule"]
        return obj
    raise ValueError(f"No parseable JSON object found in {ndjson_path}")


def compute_elastic_hash(ndjson_path: Path) -> str:
    """Return sha256: content hash for an Elastic detection rule NDJSON file."""
    rule = _load_rule_dict(ndjson_path)

    # Strip volatile fields before hashing
    stripped = {k: v for k, v in rule.items() if k not in _VOLATILE_FIELDS}

    canonical = _sort_keys(stripped)
    serialized = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"
