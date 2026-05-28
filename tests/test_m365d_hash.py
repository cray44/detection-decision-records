"""Tests for M365D custom detection JSON canonicalization hasher (v0.7)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ddr._internal.m365d_hash import compute_m365d_hash

_FIXTURES = Path(__file__).parent / "fixtures"


def _write_json(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")


def _base_detection(**kwargs) -> dict:
    base = {
        "displayName": "LOLBin regsvr32 suspicious parent",
        "description": "Detects suspicious regsvr32.exe.",
        "queryCondition": 'DeviceProcessEvents\n| where FileName =~ "regsvr32.exe"',
        "queryFrequency": "PT1H",
        "queryPeriod": "P1D",
        "severity": "Medium",
        "detectionAction": {
            "alertTitle": "Suspicious regsvr32.exe",
            "category": "SuspiciousActivity",
        },
        "mitreTechniques": ["T1218.010"],
    }
    base.update(kwargs)
    return base


def test_compute_returns_sha256_prefix(tmp_path):
    f = tmp_path / "det.json"
    _write_json(f, _base_detection())
    h = compute_m365d_hash(f)
    assert h.startswith("sha256:")
    assert len(h) == len("sha256:") + 64


def test_compute_is_deterministic(tmp_path):
    f = tmp_path / "det.json"
    _write_json(f, _base_detection())
    assert compute_m365d_hash(f) == compute_m365d_hash(f)


def test_volatile_fields_do_not_affect_hash(tmp_path):
    f1 = tmp_path / "d1.json"
    f2 = tmp_path / "d2.json"
    _write_json(
        f1,
        _base_detection(
            id="det-001",
            createdDateTime="2025-01-01T00:00:00Z",
            lastModifiedDateTime="2026-01-01T00:00:00Z",
            lastRunTime="2026-05-13T08:00:00Z",
            nextRunTime="2026-05-13T09:00:00Z",
            isEnabled=True,
            createdBy="alice@corp.com",
            lastModifiedBy="bob@corp.com",
        ),
    )
    _write_json(
        f2,
        _base_detection(
            id="det-002-different",
            createdDateTime="2024-06-01T00:00:00Z",
            lastModifiedDateTime="2025-06-01T00:00:00Z",
            lastRunTime="2026-01-01T00:00:00Z",
            nextRunTime="2026-01-01T01:00:00Z",
            isEnabled=False,
            createdBy="carol@corp.com",
            lastModifiedBy="dave@corp.com",
        ),
    )
    assert compute_m365d_hash(f1) == compute_m365d_hash(f2)


def test_non_volatile_query_change_affects_hash(tmp_path):
    f1 = tmp_path / "d1.json"
    f2 = tmp_path / "d2.json"
    q1 = 'DeviceProcessEvents | where FileName =~ "regsvr32.exe"'
    q2 = 'DeviceProcessEvents | where FileName =~ "mshta.exe"'
    _write_json(f1, _base_detection(queryCondition=q1))
    _write_json(f2, _base_detection(queryCondition=q2))
    assert compute_m365d_hash(f1) != compute_m365d_hash(f2)


def test_severity_change_affects_hash(tmp_path):
    f1 = tmp_path / "med.json"
    f2 = tmp_path / "high.json"
    _write_json(f1, _base_detection(severity="Medium"))
    _write_json(f2, _base_detection(severity="High"))
    assert compute_m365d_hash(f1) != compute_m365d_hash(f2)


def test_array_input_uses_first_element(tmp_path, capsys):
    det = _base_detection()
    other = _base_detection(displayName="Other Detection")
    f_single = tmp_path / "single.json"
    f_array = tmp_path / "array.json"
    _write_json(f_single, det)
    _write_json(f_array, [det, other])
    h_single = compute_m365d_hash(f_single)
    h_array = compute_m365d_hash(f_array)
    assert h_single == h_array
    captured = capsys.readouterr()
    assert "multi-item export" in captured.err


def test_fixture_hashes_successfully():
    h = compute_m365d_hash(_FIXTURES / "m365d_detection.json")
    assert h.startswith("sha256:")


def test_fixture_is_deterministic():
    h1 = compute_m365d_hash(_FIXTURES / "m365d_detection.json")
    h2 = compute_m365d_hash(_FIXTURES / "m365d_detection.json")
    assert h1 == h2


def test_fixture_volatile_fields_stripped(tmp_path):
    """Mutating volatile fields produces same hash as fixture."""
    import json as _json

    orig = _json.loads((_FIXTURES / "m365d_detection.json").read_text(encoding="utf-8"))
    orig_hash = compute_m365d_hash(_FIXTURES / "m365d_detection.json")

    mutated = {
        **orig,
        "id": "totally-different-id",
        "createdDateTime": "2099-01-01T00:00:00Z",
        "lastModifiedDateTime": "2099-06-01T00:00:00Z",
        "lastRunTime": "2099-06-13T09:00:00Z",
        "nextRunTime": "2099-06-13T10:00:00Z",
        "isEnabled": False,
        "createdBy": "someone-else@corp.com",
        "lastModifiedBy": "another@corp.com",
    }
    f = tmp_path / "mutated.json"
    f.write_text(_json.dumps(mutated), encoding="utf-8")
    assert compute_m365d_hash(f) == orig_hash


def test_empty_array_raises(tmp_path):
    f = tmp_path / "empty_array.json"
    _write_json(f, [])
    with pytest.raises(ValueError):
        compute_m365d_hash(f)
