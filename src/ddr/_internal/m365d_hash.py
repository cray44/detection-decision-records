"""M365D Advanced Hunting custom detection JSON canonicalization + hash — algorithm v1.

Algorithm (spec §4, v0.7):
  1. Load JSON from path (local files only).
  2. If top-level is an array (bulk export), use first element; print note.
  3. Strip volatile Graph API / Defender fields:
     id, createdDateTime, lastModifiedDateTime, lastRunTime, nextRunTime,
     isEnabled, createdBy, lastModifiedBy.
  4. Sort mapping keys recursively.
  5. Serialize to compact JSON → UTF-8 → SHA-256 → "sha256:" prefix.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

_VOLATILE_FIELDS = frozenset(
    {
        "id",
        "createdDateTime",
        "lastModifiedDateTime",
        "lastRunTime",
        "nextRunTime",
        "isEnabled",
        "createdBy",
        "lastModifiedBy",
    }
)


def _sort_keys(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _sort_keys(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [_sort_keys(item) for item in obj]
    return obj


def _load_rule_dict(json_path: Path) -> dict:
    text = json_path.read_text(encoding="utf-8-sig")
    obj = json.loads(text)

    if isinstance(obj, list):
        print(
            f"NOTE: {json_path}: multi-item export — using first detection",
            file=sys.stderr,
        )
        if not obj:
            raise ValueError(f"Empty array in {json_path}")
        obj = obj[0]

    if not isinstance(obj, dict):
        raise ValueError(f"Expected JSON object, got {type(obj).__name__} in {json_path}")

    return obj


def compute_m365d_hash(json_path: Path) -> str:
    """Return sha256: content hash for an M365D custom detection JSON file."""
    rule = _load_rule_dict(json_path)
    stripped = {k: v for k, v in rule.items() if k not in _VOLATILE_FIELDS}
    canonical = _sort_keys(stripped)
    serialized = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"
