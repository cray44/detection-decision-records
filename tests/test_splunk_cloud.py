"""Tests for splunk_cloud.py — servicesNS JSON parser and hash identity guarantee."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ddr._internal.splunk_cloud import (
    CloudSearchInfo,
    is_servicesns_json,
    parse_servicesns_export,
)
from ddr._internal.splunk_conf import compute_query_hash

FIXTURES = Path(__file__).parent / "fixtures" / "cloud"


# ---------------------------------------------------------------------------
# Parser happy paths
# ---------------------------------------------------------------------------


def test_full_envelope_extraction(tmp_path):
    fixture = FIXTURES / "full_envelope.json"
    info = parse_servicesns_export(fixture)
    assert info.name == "Excessive Failed Logins From Single Source"
    assert info.app == "DA-ESS-AccessProtection"
    assert "index=auth" in info.search


def test_content_wrapper_extraction(tmp_path):
    fixture = FIXTURES / "content_wrapper.json"
    info = parse_servicesns_export(fixture)
    assert info.name == "Beaconing Detection via Statistical Analysis"
    assert info.app == "SA-ThreatIntelligence"
    assert "index=network" in info.search


def test_minimal_shape_extraction():
    fixture = FIXTURES / "minimal.json"
    info = parse_servicesns_export(fixture)
    assert info.name == "Brute Force Login Attempt"
    assert info.app == "search"
    assert "index=auth" in info.search


def test_returns_cloud_search_info_namedtuple():
    fixture = FIXTURES / "minimal.json"
    info = parse_servicesns_export(fixture)
    assert isinstance(info, CloudSearchInfo)
    assert hasattr(info, "name")
    assert hasattr(info, "search")
    assert hasattr(info, "app")


# ---------------------------------------------------------------------------
# Hash identity guarantee — core release blocker
# ---------------------------------------------------------------------------


def test_hash_identity_conf_vs_cloud_simple(tmp_path):
    """Same SPL via .conf and via Cloud JSON must produce identical query_hash."""
    spl = (
        "index=auth sourcetype=linux_secure action=failure"
        " | stats count by src_ip, user | where count > 50"
    )

    # .conf path: write a savedsearches.conf, parse it
    conf = tmp_path / "savedsearches.conf"
    conf.write_text(f"[My Search]\nsearch = {spl}\n", encoding="utf-8")
    from ddr._internal.splunk_conf import extract_stanza, parse_savedsearches_conf

    parsed = parse_savedsearches_conf(conf)
    conf_spl = extract_stanza(parsed, "My Search")["search"].strip()
    conf_hash = compute_query_hash(conf_spl)

    # Cloud path: same SPL in a servicesNS envelope
    cloud_json = tmp_path / "cloud-export.json"
    cloud_json.write_text(
        json.dumps(
            {
                "entry": [
                    {
                        "name": "My Search",
                        "acl": {"app": "search"},
                        "content": {"search": spl},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    info = parse_servicesns_export(cloud_json)
    cloud_hash = compute_query_hash(info.search)

    assert conf_hash == cloud_hash


def test_hash_identity_with_backslash_continuation(tmp_path):
    """SPL in .conf with backslash continuation must hash-equal the same SPL in JSON."""
    spl_conf = (
        "index=auth sourcetype=linux_secure action=failure \\\n"
        "  | stats count by src_ip, user \\\n"
        "  | where count > 50"
    )
    spl_json = (
        "index=auth sourcetype=linux_secure action=failure"
        "   | stats count by src_ip, user   | where count > 50"
    )

    conf = tmp_path / "s.conf"
    conf.write_text(f"[X]\nsearch = {spl_conf}\n", encoding="utf-8")
    from ddr._internal.splunk_conf import extract_stanza, parse_savedsearches_conf

    conf_spl = extract_stanza(parse_savedsearches_conf(conf), "X")["search"].strip()
    conf_hash = compute_query_hash(conf_spl)

    cloud_json = tmp_path / "cloud.json"
    cloud_json.write_text(
        json.dumps(
            {"entry": [{"name": "X", "acl": {"app": "s"}, "content": {"search": spl_json}}]}
        ),
        encoding="utf-8",
    )
    info = parse_servicesns_export(cloud_json)
    cloud_hash = compute_query_hash(info.search)

    assert conf_hash == cloud_hash


def test_hash_identity_crlf_in_cloud_json(tmp_path):
    """Cloud JSON with \\r\\n in SPL string hashes the same as LF-only."""
    spl_lf = "index=auth | stats count by src_ip | where count > 50"
    spl_crlf = "index=auth | stats count by src_ip | where count > 50".replace(
        " | ", " |\r\n  "
    )

    def _cloud_hash(spl: str) -> str:
        f = tmp_path / f"cloud_{hash(spl)}.json"
        f.write_text(
            json.dumps({"entry": [{"name": "T", "acl": {"app": "s"}, "content": {"search": spl}}]}),
            encoding="utf-8",
        )
        return compute_query_hash(parse_servicesns_export(f).search)

    assert _cloud_hash(spl_lf) == _cloud_hash(spl_crlf)


def test_hash_idempotent(tmp_path):
    """Parsing and hashing the same file twice yields the same result."""
    fixture = FIXTURES / "full_envelope.json"
    h1 = compute_query_hash(parse_servicesns_export(fixture).search)
    h2 = compute_query_hash(parse_servicesns_export(fixture).search)
    assert h1 == h2


def test_hash_identity_example06_spl(tmp_path):
    """Hash identity against Example 06's real SPL (the canonical regression test)."""
    example_spl = (
        "index=auth sourcetype=linux_secure action=failure "
        "| stats count by src_ip, user "
        "| where count > 50"
    )
    cloud_json = tmp_path / "cloud.json"
    cloud_json.write_text(
        json.dumps(
            {
                "entry": [
                    {
                        "name": "Excessive Failed Logins From Single Source",
                        "acl": {"app": "DA-ESS-AccessProtection"},
                        "content": {"search": example_spl},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    cloud_hash = compute_query_hash(parse_servicesns_export(cloud_json).search)

    # Also hash it directly for cross-check
    direct_hash = compute_query_hash(example_spl)
    assert cloud_hash == direct_hash
    assert cloud_hash.startswith("sha256:")
    assert len(cloud_hash) == 7 + 64  # "sha256:" + 64 hex chars


# ---------------------------------------------------------------------------
# is_servicesns_json heuristic
# ---------------------------------------------------------------------------


def test_is_servicesns_json_full_envelope():
    assert is_servicesns_json(FIXTURES / "full_envelope.json") is True


def test_is_servicesns_json_content_wrapper():
    assert is_servicesns_json(FIXTURES / "content_wrapper.json") is True


def test_is_servicesns_json_minimal():
    assert is_servicesns_json(FIXTURES / "minimal.json") is True


def test_is_servicesns_json_rejects_conf(tmp_path):
    conf = tmp_path / "s.conf"
    conf.write_text("[My Search]\nsearch = index=main\n", encoding="utf-8")
    assert is_servicesns_json(conf) is False


def test_is_servicesns_json_rejects_plain_json_no_search(tmp_path):
    f = tmp_path / "other.json"
    f.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
    assert is_servicesns_json(f) is False


def test_is_servicesns_json_returns_false_on_invalid_json(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("not json at all", encoding="utf-8")
    assert is_servicesns_json(f) is False


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------


def test_parse_missing_search_key_raises(tmp_path):
    f = tmp_path / "no_search.json"
    payload = {"entry": [{"name": "X", "acl": {"app": "s"}, "content": {"disabled": "0"}}]}
    f.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        parse_servicesns_export(f)


def test_parse_empty_search_raises(tmp_path):
    f = tmp_path / "empty_search.json"
    f.write_text(json.dumps({"name": "X", "search": ""}), encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        parse_servicesns_export(f)


def test_parse_malformed_json_raises(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(ValueError, match="Not valid JSON"):
        parse_servicesns_export(f)


def test_parse_unrecognised_shape_raises(tmp_path):
    f = tmp_path / "unknown.json"
    f.write_text(json.dumps({"completely": "different", "shape": True}), encoding="utf-8")
    with pytest.raises(ValueError, match="Unrecognised"):
        parse_servicesns_export(f)


def test_parse_empty_entry_array_raises(tmp_path):
    f = tmp_path / "empty_entry.json"
    f.write_text(json.dumps({"entry": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        parse_servicesns_export(f)


def test_parse_no_app_in_acl_returns_none(tmp_path):
    f = tmp_path / "no_app.json"
    f.write_text(json.dumps({"name": "X", "search": "index=main | head 10"}), encoding="utf-8")
    info = parse_servicesns_export(f)
    assert info.app is None
    assert info.name == "X"


def test_parse_multiple_entries_uses_first(tmp_path):
    f = tmp_path / "multi.json"
    f.write_text(
        json.dumps(
            {
                "entry": [
                    {"name": "First", "acl": {"app": "s"}, "content": {"search": "index=main"}},
                    {"name": "Second", "acl": {"app": "s"}, "content": {"search": "index=other"}},
                ]
            }
        ),
        encoding="utf-8",
    )
    info = parse_servicesns_export(f)
    assert info.name == "First"
    assert "index=main" in info.search
