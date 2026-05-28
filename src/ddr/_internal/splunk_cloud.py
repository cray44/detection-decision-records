"""Splunk Cloud servicesNS REST JSON parser.

Parses the JSON artifact produced by:

    curl -H "Authorization: Bearer $TOKEN" \\
      "https://tenant.splunkcloud.com:8089/servicesNS/nobody/search/saved/searches/MySearch
       ?output_mode=json" \\
      > cloud-export.json

Supported shapes (in priority order):
  1. Full servicesNS envelope: top-level ``entry`` array with ``content.search``.
  2. Direct ``content`` object: ``{"content": {"search": "...", ...}, "acl": ...}``.
  3. Minimal hand-crafted: ``{"name": "...", "search": "...", "app": "..."}``.

Hash identity guarantee: the same SPL string produces the same ``sha256:`` hash
regardless of whether it came from a ``.conf`` stanza or a Cloud export.
``canonicalize_spl`` and ``compute_query_hash`` are imported from ``splunk_conf``
and never duplicated here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import NamedTuple

from ddr._internal.splunk_conf import canonicalize_spl, compute_query_hash  # noqa: F401 (re-export)


class CloudSearchInfo(NamedTuple):
    """Extracted fields from a servicesNS JSON export."""

    name: str
    search: str
    app: str | None


def parse_servicesns_export(path: Path) -> CloudSearchInfo:
    """Load and parse a servicesNS JSON export; return CloudSearchInfo.

    Raises ValueError on unrecognised shape or missing/empty ``search``.
    """
    try:
        text = path.read_text(encoding="utf-8-sig")
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Not valid JSON: {exc}") from exc

    if not isinstance(obj, dict):
        raise ValueError("Expected a JSON object at top level")

    name, search, app = _extract_fields(obj)

    search = _clean_search(search)
    if not search:
        raise ValueError("'search' field is present but empty after cleaning")

    return CloudSearchInfo(name=name, search=search, app=app)


def _extract_fields(obj: dict) -> tuple[str, str, str | None]:
    # Shape 1: servicesNS envelope with entry[]
    if "entry" in obj:
        entries = obj["entry"]
        if not isinstance(entries, list) or not entries:
            raise ValueError("'entry' array is missing or empty")
        if len(entries) > 1:
            import sys

            print(
                "NOTE: servicesNS export contains multiple entries; using first entry only",
                file=sys.stderr,
            )
        entry = entries[0]
        if not isinstance(entry, dict):
            raise ValueError("entry[0] is not a JSON object")
        return _extract_from_entry(entry)

    # Shape 2: direct content wrapper {content: {...}, acl: {...}}
    if "content" in obj and isinstance(obj["content"], dict):
        content = obj["content"]
        search = content.get("search") or content.get("eai:data", "")
        if not isinstance(search, str):
            search = ""
        name = obj.get("name") or content.get("title") or "TODO: search name"
        app = _extract_app(obj)
        return str(name), search, app

    # Shape 3: minimal hand-crafted {name, search, app}
    if "search" in obj:
        search = obj.get("search", "")
        if not isinstance(search, str):
            raise ValueError("'search' must be a string")
        name = obj.get("name") or "TODO: search name"
        app = obj.get("app") if isinstance(obj.get("app"), str) else None
        return str(name), search, app

    raise ValueError(
        "Unrecognised JSON shape — expected servicesNS envelope (entry[]), "
        "content wrapper, or minimal {name, search} object"
    )


def _extract_from_entry(entry: dict) -> tuple[str, str, str | None]:
    name = entry.get("name") or "TODO: search name"
    app = _extract_app(entry)

    content = entry.get("content", {})
    if not isinstance(content, dict):
        raise ValueError("entry[0].content is not a JSON object")

    search = content.get("search") or content.get("eai:data", "")
    if not isinstance(search, str):
        raise ValueError("entry[0].content.search is not a string")

    return str(name), search, app


def _extract_app(obj: dict) -> str | None:
    """Try acl.app, eai:acl.app, then top-level app field."""
    for acl_key in ("acl", "eai:acl"):
        acl = obj.get(acl_key)
        if isinstance(acl, dict):
            app = acl.get("app")
            if isinstance(app, str) and app:
                return app
    app = obj.get("app")
    if isinstance(app, str) and app:
        return app
    return None


def _clean_search(search: str) -> str:
    """Normalize a search string extracted from JSON.

    JSON embeds SPL as a single string — no backslash continuation.
    Feeds through canonicalize_spl for whitespace normalization so the
    result is identical to the .conf-parsed path.
    """
    return canonicalize_spl(search)


def is_servicesns_json(path: Path) -> bool:
    """Heuristic: return True if this file looks like a servicesNS JSON export.

    Used for content-driven dispatch in ``ddr new --target splunk``.
    Returns False on any read/parse error.
    """
    if path.suffix.lower() not in (".json",):
        return False
    try:
        text = path.read_text(encoding="utf-8-sig")
        obj = json.loads(text)
    except Exception:
        return False
    if not isinstance(obj, dict):
        return False
    # Full envelope
    if "entry" in obj and isinstance(obj.get("entry"), list):
        return True
    # Content wrapper
    if "content" in obj and isinstance(obj.get("content"), dict):
        return True
    # Minimal shape: must have "search" key to be unambiguous
    return "search" in obj
