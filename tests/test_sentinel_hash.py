"""Tests for Sentinel Analytics Rule JSON canonicalization hasher (v0.7)."""

from __future__ import annotations

import json
from pathlib import Path

from ddr._internal.sentinel_hash import compute_sentinel_hash

_FIXTURES = Path(__file__).parent / "fixtures"


def _write_json(path: Path, obj: dict) -> None:
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")


def _base_properties(**kwargs) -> dict:
    base = {
        "displayName": "Test Sentinel Rule",
        "description": "A test rule.",
        "severity": "Medium",
        "enabled": True,
        "query": "SigninLogs\n| where ResultType == \"50057\"",
        "queryFrequency": "PT1H",
        "queryPeriod": "PT1H",
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
        "tactics": ["CredentialAccess"],
        "techniques": ["T1110"],
    }
    base.update(kwargs)
    return base


def _arm_envelope(**prop_kwargs) -> dict:
    return {
        "id": "/subscriptions/00000000/resourceGroups/rg/providers/sentinel/rule1",
        "name": "rule1",
        "type": "Microsoft.SecurityInsights/alertRules",
        "etag": "\"abc123\"",
        "systemData": {"createdAt": "2024-01-01T00:00:00Z"},
        "properties": _base_properties(**prop_kwargs),
    }


def test_compute_returns_sha256_prefix(tmp_path):
    f = tmp_path / "rule.json"
    _write_json(f, _arm_envelope())
    h = compute_sentinel_hash(f)
    assert h.startswith("sha256:")
    assert len(h) == len("sha256:") + 64


def test_compute_is_deterministic(tmp_path):
    f = tmp_path / "rule.json"
    _write_json(f, _arm_envelope())
    assert compute_sentinel_hash(f) == compute_sentinel_hash(f)


def test_volatile_etag_does_not_affect_hash(tmp_path):
    f1 = tmp_path / "r1.json"
    f2 = tmp_path / "r2.json"
    env1 = _arm_envelope()
    env2 = _arm_envelope()
    env1["etag"] = "\"etag-v1\""
    env2["etag"] = "\"etag-v999\""
    _write_json(f1, env1)
    _write_json(f2, env2)
    assert compute_sentinel_hash(f1) == compute_sentinel_hash(f2)


def test_volatile_timestamps_do_not_affect_hash(tmp_path):
    f1 = tmp_path / "r1.json"
    f2 = tmp_path / "r2.json"
    _write_json(f1, _arm_envelope(lastModifiedUtc="2026-01-01T00:00:00Z",
                                   lastRunTime="2026-05-01T00:00:00Z",
                                   nextRunTime="2026-05-01T01:00:00Z"))
    _write_json(f2, _arm_envelope(lastModifiedUtc="2026-06-01T00:00:00Z",
                                   lastRunTime="2026-06-01T00:00:00Z",
                                   nextRunTime="2026-06-01T01:00:00Z"))
    assert compute_sentinel_hash(f1) == compute_sentinel_hash(f2)


def test_all_volatile_fields_stripped(tmp_path):
    f1 = tmp_path / "clean.json"
    f2 = tmp_path / "volatile.json"
    _write_json(f1, _arm_envelope())
    _write_json(f2, _arm_envelope(
        lastModifiedUtc="2026-06-01T00:00:00Z",
        lastRunTime="2026-06-01T00:00:00Z",
        nextRunTime="2026-06-01T01:00:00Z",
        lastDeploymentStatus="Success",
        lastDeploymentStatusMessage="OK",
        alertRuleTemplateName="tmpl-uuid",
        templateVersion="1.0.1",
    ))
    assert compute_sentinel_hash(f1) == compute_sentinel_hash(f2)


def test_non_volatile_query_change_affects_hash(tmp_path):
    f1 = tmp_path / "r1.json"
    f2 = tmp_path / "r2.json"
    _write_json(f1, _arm_envelope(query="SigninLogs | where ResultType == \"50057\""))
    _write_json(f2, _arm_envelope(query="SigninLogs | where ResultType == \"50055\""))
    assert compute_sentinel_hash(f1) != compute_sentinel_hash(f2)


def test_severity_change_affects_hash(tmp_path):
    f1 = tmp_path / "med.json"
    f2 = tmp_path / "high.json"
    _write_json(f1, _arm_envelope(severity="Medium"))
    _write_json(f2, _arm_envelope(severity="High"))
    assert compute_sentinel_hash(f1) != compute_sentinel_hash(f2)


def test_arm_envelope_unwrapped(tmp_path):
    """ARM envelope stripped; hash equals flat properties-only object."""
    props = _base_properties()
    flat = tmp_path / "flat.json"
    arm = tmp_path / "arm.json"
    _write_json(flat, props)
    _write_json(arm, _arm_envelope())
    assert compute_sentinel_hash(flat) == compute_sentinel_hash(arm)


def test_flat_rule_without_envelope(tmp_path):
    f = tmp_path / "flat.json"
    _write_json(f, _base_properties())
    h = compute_sentinel_hash(f)
    assert h.startswith("sha256:")


def test_fixture_hashes_successfully():
    h = compute_sentinel_hash(_FIXTURES / "sentinel_rule.json")
    assert h.startswith("sha256:")


def test_fixture_is_deterministic():
    h1 = compute_sentinel_hash(_FIXTURES / "sentinel_rule.json")
    h2 = compute_sentinel_hash(_FIXTURES / "sentinel_rule.json")
    assert h1 == h2


def test_fixture_volatile_fields_do_not_affect_hash(tmp_path):
    """Mutating volatile fields in the fixture produces the same hash."""
    import json as _json
    orig = _json.loads((_FIXTURES / "sentinel_rule.json").read_text(encoding="utf-8"))
    orig_hash = compute_sentinel_hash(_FIXTURES / "sentinel_rule.json")

    mutated = {**orig}
    mutated["etag"] = "\"brand-new-etag\""
    mutated["properties"] = {
        **orig["properties"],
        "lastModifiedUtc": "2099-01-01T00:00:00Z",
        "lastRunTime": "2099-01-01T00:00:00Z",
        "nextRunTime": "2099-01-01T01:00:00Z",
    }
    f = tmp_path / "mutated.json"
    f.write_text(_json.dumps(mutated), encoding="utf-8")
    assert compute_sentinel_hash(f) == orig_hash
