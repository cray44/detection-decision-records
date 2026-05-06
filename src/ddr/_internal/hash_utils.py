"""Content hash computation: canonicalization algorithm v1.

Algorithm (spec §5):
  1. Load rule YAML with safe loader (strips comments).
  2. Sort mapping keys recursively.
  3. Dump to UTF-8 string with deterministic YAML style.
  4. Normalize line endings to LF.
  5. SHA-256 the result.
  6. Prefix hex digest with 'sha256:'.
"""

from __future__ import annotations

import hashlib
import io
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML


def _safe_loader() -> YAML:
    return YAML(typ="safe")


def _canonical_dumper() -> YAML:
    y = YAML()
    y.default_flow_style = False
    y.width = 4096
    y.best_sequence_indent = 2
    y.best_map_flow_style = False
    return y


def _sort_keys(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _sort_keys(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [_sort_keys(item) for item in obj]
    return obj


def compute_content_hash(rule_path: Path) -> str:
    """Return sha256: content hash for a Sigma rule file."""
    loader = _safe_loader()
    with open(rule_path, encoding="utf-8") as fh:
        data = loader.load(fh)

    if data is None:
        raise ValueError(f"Empty or null YAML: {rule_path}")

    canonical = _sort_keys(data)
    dumper = _canonical_dumper()
    buf = io.StringIO()
    dumper.dump(canonical, buf)
    text = buf.getvalue().replace("\r\n", "\n").replace("\r", "\n")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def verify_content_hash(rule_path: Path, recorded_hash: str) -> bool:
    """Return True if rule's current content hash matches recorded_hash."""
    return compute_content_hash(rule_path) == recorded_hash
