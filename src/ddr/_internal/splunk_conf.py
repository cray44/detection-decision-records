"""Pure-Python savedsearches.conf parser and SPL canonicalizer.

SPL canonicalization algorithm v1 (spec/ddr-v0.4.md §6):
  1. UTF-8 decode, strip BOM
  2. CRLF -> LF
  3. Join backslash-continued physical lines
  4. Drop lines whose first non-whitespace char is '#'
  5. Collapse runs of whitespace to single space
  6. Trim outer whitespace
  7. SHA-256 -> hex -> 'sha256:' prefix
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

_APP_PATH_RE = re.compile(
    r"[/\\]etc[/\\]apps[/\\]([^/\\]+)[/\\](?:local|default)[/\\]savedsearches\.conf$",
    re.IGNORECASE,
)


def parse_savedsearches_conf(path: Path) -> dict[str, dict[str, str]]:
    """Parse savedsearches.conf; return {stanza_name: {key: value}}.

    Handles: BOM, CRLF, backslash-continuation, #-comments, multi-stanza.
    [default] stanza is skipped. Last-wins for duplicate keys.
    """
    text = path.read_bytes().decode("utf-8-sig")  # utf-8-sig strips BOM
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # First pass: join backslash-continued physical lines into logical lines.
    physical = text.split("\n")
    logical: list[str] = []
    for raw in physical:
        if logical and logical[-1].endswith("\\") and not raw.lstrip().startswith("#"):
                logical[-1] = logical[-1][:-1] + " " + raw
                continue
        logical.append(raw)

    result: dict[str, dict[str, str]] = {}
    current_stanza: str | None = None

    for line in logical:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            name = stripped[1:-1]
            if name.lower() == "default":
                current_stanza = None
            else:
                current_stanza = name
                result[current_stanza] = {}
            continue
        if current_stanza is not None and "=" in stripped:
            key, _, value = stripped.partition("=")
            result[current_stanza][key.strip()] = value.strip()

    return result


def extract_stanza(conf: dict[str, dict[str, str]], name: str) -> dict[str, str]:
    """Return the named stanza dict or raise KeyError listing available stanzas."""
    if name not in conf:
        available = ", ".join(repr(s) for s in sorted(conf.keys()))
        raise KeyError(f"Stanza {name!r} not found. Available: {available or '(none)'}")
    return conf[name]


def infer_app_from_path(path: Path) -> str | None:
    """Return Splunk app name from .../etc/apps/<app>/(local|default)/savedsearches.conf."""
    m = _APP_PATH_RE.search(path.as_posix())
    return m.group(1) if m else None


def canonicalize_spl(query: str) -> str:
    """Return canonicalized SPL string (algorithm v1, spec/ddr-v0.4.md §6).

    Steps: strip BOM -> CRLF->LF -> join backslash-continuations ->
    drop comment lines -> collapse whitespace -> trim.
    No keyword lowercasing.
    """
    query = query.lstrip("﻿")
    query = query.replace("\r\n", "\n").replace("\r", "\n")

    physical = query.split("\n")
    logical: list[str] = []
    for ln in physical:
        if logical and logical[-1].endswith("\\"):
            logical[-1] = logical[-1][:-1] + " " + ln
        else:
            logical.append(ln)

    non_comment = [ln for ln in logical if not ln.lstrip().startswith("#")]
    joined = " ".join(non_comment)
    return re.sub(r"\s+", " ", joined).strip()


def compute_query_hash(query: str) -> str:
    """Return sha256:<64 hex chars> of canonicalized SPL."""
    canonical = canonicalize_spl(query)
    if not canonical:
        raise ValueError("SPL query is empty after canonicalization")
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"
