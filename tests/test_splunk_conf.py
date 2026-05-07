"""Unit tests for ddr._internal.splunk_conf."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from ddr._internal.splunk_conf import (
    canonicalize_spl,
    compute_query_hash,
    extract_stanza,
    infer_app_from_path,
    parse_savedsearches_conf,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def write_conf(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "savedsearches.conf"
    p.write_text(content, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# parse_savedsearches_conf
# ---------------------------------------------------------------------------


def test_simple_stanza(tmp_path):
    p = write_conf(tmp_path, "[My Detection]\nsearch = index=main error\n")
    conf = parse_savedsearches_conf(p)
    assert "My Detection" in conf
    assert conf["My Detection"]["search"] == "index=main error"


def test_multi_stanza(tmp_path):
    p = write_conf(
        tmp_path,
        "[Alpha]\nsearch = index=a\n\n[Beta]\nsearch = index=b\n",
    )
    conf = parse_savedsearches_conf(p)
    assert set(conf.keys()) == {"Alpha", "Beta"}
    assert conf["Alpha"]["search"] == "index=a"
    assert conf["Beta"]["search"] == "index=b"


def test_continuation_lines(tmp_path):
    p = write_conf(
        tmp_path,
        "[Detect]\nsearch = index=auth action=failure \\\n  | stats count by src_ip\n",
    )
    conf = parse_savedsearches_conf(p)
    assert "src_ip" in conf["Detect"]["search"]
    assert "\\" not in conf["Detect"]["search"]


def test_comment_lines_skipped(tmp_path):
    p = write_conf(
        tmp_path,
        "# top comment\n[Detect]\n# inline comment\nsearch = index=main\n",
    )
    conf = parse_savedsearches_conf(p)
    assert "Detect" in conf
    assert conf["Detect"]["search"] == "index=main"


def test_bom_stripped(tmp_path):
    p = tmp_path / "bom.conf"
    p.write_bytes(b"\xef\xbb\xbf[BOMStanza]\nsearch = index=bom\n")
    conf = parse_savedsearches_conf(p)
    assert "BOMStanza" in conf


def test_crlf_normalized(tmp_path):
    p = tmp_path / "crlf.conf"
    p.write_bytes(b"[CRLF]\r\nsearch = index=crlf\r\n")
    conf = parse_savedsearches_conf(p)
    assert "CRLF" in conf
    assert conf["CRLF"]["search"] == "index=crlf"


def test_default_stanza_skipped(tmp_path):
    p = write_conf(
        tmp_path,
        "[default]\nauto_summarize = true\n\n[Real]\nsearch = index=real\n",
    )
    conf = parse_savedsearches_conf(p)
    assert "default" not in conf
    assert "Real" in conf


def test_missing_stanza_raises(tmp_path):
    p = write_conf(tmp_path, "[Alpha]\nsearch = index=a\n")
    conf = parse_savedsearches_conf(p)
    with pytest.raises(KeyError, match="not found"):
        extract_stanza(conf, "Missing")


def test_duplicate_key_last_wins(tmp_path):
    p = write_conf(
        tmp_path,
        "[Dup]\nsearch = first\nsearch = second\n",
    )
    conf = parse_savedsearches_conf(p)
    assert conf["Dup"]["search"] == "second"


def test_malformed_line_no_equals_ignored(tmp_path):
    p = write_conf(tmp_path, "[S]\nno_equals_here\nsearch = ok\n")
    conf = parse_savedsearches_conf(p)
    assert conf["S"]["search"] == "ok"
    assert "no_equals_here" not in conf["S"]


def test_empty_conf(tmp_path):
    p = write_conf(tmp_path, "# only comments\n")
    conf = parse_savedsearches_conf(p)
    assert conf == {}


# ---------------------------------------------------------------------------
# infer_app_from_path
# ---------------------------------------------------------------------------


def test_infer_app_local_path(tmp_path):
    p = tmp_path / "etc" / "apps" / "MyApp" / "local" / "savedsearches.conf"
    assert infer_app_from_path(p) == "MyApp"


def test_infer_app_default_dir(tmp_path):
    p = tmp_path / "etc" / "apps" / "SplunkES" / "default" / "savedsearches.conf"
    assert infer_app_from_path(p) == "SplunkES"


def test_infer_app_no_match(tmp_path):
    p = tmp_path / "some" / "other" / "path" / "savedsearches.conf"
    assert infer_app_from_path(p) is None


# ---------------------------------------------------------------------------
# canonicalize_spl
# ---------------------------------------------------------------------------


def test_canonicalize_collapses_whitespace():
    raw = "index=main   sourcetype=syslog   | stats count"
    assert canonicalize_spl(raw) == "index=main sourcetype=syslog | stats count"


def test_canonicalize_idempotent():
    raw = "index=main | stats count by host"
    c1 = canonicalize_spl(raw)
    c2 = canonicalize_spl(c1)
    assert c1 == c2


def test_canonicalize_strips_bom():
    raw = "﻿index=main"
    assert canonicalize_spl(raw) == "index=main"


def test_canonicalize_crlf():
    raw = "index=main\r\n| stats count"
    result = canonicalize_spl(raw)
    assert "\r" not in result


def test_canonicalize_joins_continuation():
    raw = "index=main \\\n  | stats count"
    result = canonicalize_spl(raw)
    assert "\\" not in result
    assert "stats count" in result


def test_canonicalize_drops_comment_lines():
    raw = "# this is a comment\nindex=main"
    result = canonicalize_spl(raw)
    assert "#" not in result
    assert "index=main" in result


def test_whitespace_only_difference_same_hash():
    a = "index=main  sourcetype=syslog  |  stats count"
    b = "index=main sourcetype=syslog | stats count"
    assert compute_query_hash(a) == compute_query_hash(b)


def test_semantic_difference_different_hash():
    a = "index=main | stats count by host"
    b = "index=main | stats count by src_ip"
    assert compute_query_hash(a) != compute_query_hash(b)


# ---------------------------------------------------------------------------
# compute_query_hash
# ---------------------------------------------------------------------------


_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def test_hash_format():
    h = compute_query_hash("index=main")
    assert _HASH_RE.match(h), f"Unexpected format: {h}"


def test_hash_empty_raises():
    with pytest.raises(ValueError, match="empty"):
        compute_query_hash("   ")


def test_hash_deterministic():
    q = "index=auth sourcetype=linux_secure | stats count by src_ip"
    assert compute_query_hash(q) == compute_query_hash(q)
