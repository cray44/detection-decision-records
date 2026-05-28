"""Tests for Elastic rule JSON canonicalization hasher (v0.6)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ddr._internal.elastic_hash import compute_elastic_hash

_FIXTURES = Path(__file__).parent / "fixtures"


def _write_ndjson(path: Path, obj: dict) -> None:
    path.write_text(json.dumps(obj) + "\n", encoding="utf-8")


def _base_rule(**kwargs) -> dict:
    base = {
        "rule_id": "96b9fc2a-cbd5-4a3e-b7d7-3d9d6a6e8d5c",
        "name": "Test Rule",
        "type": "eql",
        "language": "eql",
        "query": 'process where process.name : "cmd.exe"',
        "risk_score": 47,
        "severity": "medium",
        "tags": ["Windows"],
        "enabled": True,
        "from": "now-360s",
        "to": "now",
        "interval": "5m",
        "max_signals": 100,
        "threat": [],
    }
    base.update(kwargs)
    return base


def test_compute_returns_sha256_prefix(tmp_path):
    f = tmp_path / "rule.ndjson"
    _write_ndjson(f, _base_rule())
    h = compute_elastic_hash(f)
    assert h.startswith("sha256:")
    assert len(h) == len("sha256:") + 64


def test_compute_is_deterministic(tmp_path):
    f = tmp_path / "rule.ndjson"
    _write_ndjson(f, _base_rule())
    assert compute_elastic_hash(f) == compute_elastic_hash(f)


def test_volatile_fields_do_not_affect_hash(tmp_path):
    """Changing revision/version/created_at must not change the hash."""
    f1 = tmp_path / "rule1.ndjson"
    f2 = tmp_path / "rule2.ndjson"
    _write_ndjson(f1, _base_rule(revision=1, version=1, created_at="2026-01-01T00:00:00Z"))
    _write_ndjson(f2, _base_rule(revision=5, version=5, created_at="2026-06-01T00:00:00Z"))
    assert compute_elastic_hash(f1) == compute_elastic_hash(f2)


def test_all_volatile_fields_stripped(tmp_path):
    volatile = {
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-06-01T00:00:00Z",
        "created_by": "elastic",
        "updated_by": "admin",
        "revision": 3,
        "version": 7,
        "id": "internal-kibana-uuid",
        "immutable": True,
        "related_integrations": [{"package": "endpoint"}],
        "required_fields": [{"name": "host.id", "type": "keyword"}],
        "setup": "Install endpoint agent.",
    }
    f1 = tmp_path / "base.ndjson"
    f2 = tmp_path / "with_volatile.ndjson"
    _write_ndjson(f1, _base_rule())
    _write_ndjson(f2, _base_rule(**volatile))
    assert compute_elastic_hash(f1) == compute_elastic_hash(f2)


def test_non_volatile_field_change_affects_hash(tmp_path):
    f1 = tmp_path / "rule_medium.ndjson"
    f2 = tmp_path / "rule_high.ndjson"
    _write_ndjson(f1, _base_rule(severity="medium"))
    _write_ndjson(f2, _base_rule(severity="high"))
    assert compute_elastic_hash(f1) != compute_elastic_hash(f2)


def test_query_change_affects_hash(tmp_path):
    f1 = tmp_path / "rule_v1.ndjson"
    f2 = tmp_path / "rule_v2.ndjson"
    _write_ndjson(f1, _base_rule(query='process where process.name : "cmd.exe"'))
    _write_ndjson(f2, _base_rule(query='process where process.name : "powershell.exe"'))
    assert compute_elastic_hash(f1) != compute_elastic_hash(f2)


def test_wrapped_rule_same_hash_as_unwrapped(tmp_path):
    """{\"rule\": {...}} wrapper is unwrapped before hashing."""
    rule = _base_rule()
    f_plain = tmp_path / "plain.ndjson"
    f_wrapped = tmp_path / "wrapped.ndjson"
    _write_ndjson(f_plain, rule)
    f_wrapped.write_text(json.dumps({"rule": rule}) + "\n", encoding="utf-8")
    assert compute_elastic_hash(f_plain) == compute_elastic_hash(f_wrapped)


def test_fixture_plain_hashes_successfully():
    h = compute_elastic_hash(_FIXTURES / "elastic_rule.ndjson")
    assert h.startswith("sha256:")


def test_fixture_wrapped_same_hash_as_plain():
    h_plain = compute_elastic_hash(_FIXTURES / "elastic_rule.ndjson")
    h_wrapped = compute_elastic_hash(_FIXTURES / "elastic_rule_wrapped.ndjson")
    assert h_plain == h_wrapped


def test_key_order_does_not_affect_hash(tmp_path):
    """Keys sorted before hashing — insertion order is irrelevant."""
    rule_a = {
        "b_field": 2,
        "a_field": 1,
        "rule_id": "x",
        "name": "r",
        "type": "eql",
        "language": "eql",
        "query": "q",
        "risk_score": 47,
        "severity": "medium",
        "tags": [],
        "enabled": True,
        "from": "now-360s",
        "to": "now",
        "interval": "5m",
        "max_signals": 100,
        "threat": [],
    }
    rule_b = dict(sorted(rule_a.items()))
    f1 = tmp_path / "r_a.ndjson"
    f2 = tmp_path / "r_b.ndjson"
    _write_ndjson(f1, rule_a)
    _write_ndjson(f2, rule_b)
    assert compute_elastic_hash(f1) == compute_elastic_hash(f2)


def test_empty_file_raises(tmp_path):
    empty = tmp_path / "empty.ndjson"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="No parseable JSON"):
        compute_elastic_hash(empty)


def test_non_json_file_raises(tmp_path):
    bad = tmp_path / "bad.ndjson"
    bad.write_text("this is not json\n", encoding="utf-8")
    with pytest.raises(ValueError, match="No parseable JSON"):
        compute_elastic_hash(bad)
