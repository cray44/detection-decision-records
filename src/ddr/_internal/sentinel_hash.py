"""Sentinel Analytics Rule JSON canonicalization + hash — algorithm v1.

Algorithm (spec §3, v0.7):
  1. Load JSON from path (local files only).
  2. If top-level has "properties" key (ARM envelope), extract obj["properties"].
     Also strip envelope-level keys: id, name, type, systemData.
  3. Strip volatile Sentinel/ARM fields from the rule body:
     etag, lastModifiedUtc, lastRunTime, nextRunTime,
     lastDeploymentStatusMessage, lastDeploymentStatus,
     alertRuleTemplateName, templateVersion.
  4. Sort mapping keys recursively.
  5. Serialize to compact JSON → UTF-8 → SHA-256 → "sha256:" prefix.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

_ENVELOPE_VOLATILE = frozenset({"id", "name", "type", "systemData"})

_BODY_VOLATILE = frozenset(
    {
        "etag",
        "lastModifiedUtc",
        "lastRunTime",
        "nextRunTime",
        "lastDeploymentStatusMessage",
        "lastDeploymentStatus",
        "alertRuleTemplateName",
        "templateVersion",
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

    if not isinstance(obj, dict):
        raise ValueError(f"Expected JSON object, got {type(obj).__name__} in {json_path}")

    # Unwrap ARM envelope
    if "properties" in obj and isinstance(obj["properties"], dict):
        rule = {k: v for k, v in obj["properties"].items()}
        # Strip envelope-level volatile keys that may bleed through
        for k in _ENVELOPE_VOLATILE:
            rule.pop(k, None)
        return rule

    # No envelope — strip any envelope-level keys from flat export
    return {k: v for k, v in obj.items() if k not in _ENVELOPE_VOLATILE}


def compute_sentinel_hash(json_path: Path) -> str:
    """Return sha256: content hash for a Sentinel Analytics Rule JSON file."""
    rule = _load_rule_dict(json_path)
    stripped = {k: v for k, v in rule.items() if k not in _BODY_VOLATILE}
    canonical = _sort_keys(stripped)
    serialized = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"
