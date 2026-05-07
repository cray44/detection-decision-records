"""Tests for Sigma Filter exporter."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ddr.exporters.sigma_filter import build_sigma_filter, export_to_yaml
from ddr.models.record import DDRRecord

_VALID_HASH = "sha256:" + "a" * 64
_NOW = datetime(2025, 1, 15, 9, 0, 0, tzinfo=UTC)
_FUTURE = datetime(2026, 1, 15, 9, 0, 0, tzinfo=UTC)


def _suppress_record_data(**overrides) -> dict:
    base = {
        "ddr_version": "0.1",
        "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "title": "Suppress PsExec from SCCM",
        "description": "IT Ops FP suppression.",
        "target": {
            "kind": "sigma",
            "rule_ref": {
                "rule_id": "d7a95147-145f-4678-b555-b7a3c9b16830",
                "content_hash": _VALID_HASH,
                "source": "sigmahq",
                "path_or_url": "https://example.com/rule.yml",
            },
        },
        "decision": {
            "kind": "suppress",
            "rationale": "Known FP.",
            "tuning": {
                "logsource": {"category": "process_creation", "product": "windows"},
                "selections": {
                    "known_fp_sccm": {"ParentImage|endswith": ["\\ccmexec.exe"]}
                },
                "condition": "not known_fp_sccm",
            },
        },
        "lifecycle": {
            "status": "active",
            "created_on": _NOW.isoformat(),
            "activated_on": _NOW.isoformat(),
            "expires_on": _FUTURE.isoformat(),
        },
        "provenance": {"author": "alice@example.com"},
    }
    base.update(overrides)
    return base


def test_build_sigma_filter_structure():
    record = DDRRecord.model_validate(_suppress_record_data())
    sigma_filter = build_sigma_filter(record)

    assert sigma_filter["status"] == "experimental"
    assert sigma_filter["logsource"]["category"] == "process_creation"
    assert sigma_filter["logsource"]["product"] == "windows"
    # condition and rules live inside filter block (pySigma SigmaGlobalFilter requirement)
    assert "known_fp_sccm" in sigma_filter["filter"]
    assert sigma_filter["filter"]["condition"] == "not known_fp_sccm"
    assert "d7a95147-145f-4678-b555-b7a3c9b16830" in sigma_filter["filter"]["rules"]
    assert "rules" not in sigma_filter
    assert "condition" not in sigma_filter


def test_build_sigma_filter_title_fallback():
    record = DDRRecord.model_validate(_suppress_record_data())
    sigma_filter = build_sigma_filter(record)
    assert "Suppress PsExec" in sigma_filter["title"]


def test_build_sigma_filter_custom_title():
    data = _suppress_record_data()
    data["decision"]["tuning"]["filter_title"] = "Custom Filter Title"
    record = DDRRecord.model_validate(data)
    sigma_filter = build_sigma_filter(record)
    assert sigma_filter["title"] == "Custom Filter Title"


def test_build_sigma_filter_name_uses_ddr_id():
    record = DDRRecord.model_validate(_suppress_record_data())
    sigma_filter = build_sigma_filter(record)
    assert sigma_filter["name"].startswith("filter_")
    assert len(sigma_filter["name"]) == len("filter_") + 8


def test_export_non_suppress_raises():
    data = _suppress_record_data()
    data["decision"] = {"kind": "accept-risk", "rationale": "Accepted."}
    record = DDRRecord.model_validate(data)
    with pytest.raises(ValueError, match="suppress"):
        build_sigma_filter(record)


def test_export_to_yaml_returns_string():
    record = DDRRecord.model_validate(_suppress_record_data())
    yaml_str = export_to_yaml(record)
    assert isinstance(yaml_str, str)
    assert "title:" in yaml_str
    assert "rules:" in yaml_str
    assert "filter:" in yaml_str
    assert "condition:" in yaml_str


def test_export_to_yaml_writes_file(tmp_path):
    record = DDRRecord.model_validate(_suppress_record_data())
    out = tmp_path / "sigma_filter.yml"
    result = export_to_yaml(record, output=out)
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert content == result


def test_export_logsource_service_only():
    data = _suppress_record_data()
    data["decision"]["tuning"]["logsource"] = {"service": "syslog"}
    record = DDRRecord.model_validate(data)
    sigma_filter = build_sigma_filter(record)
    assert sigma_filter["logsource"] == {"service": "syslog"}
    assert "category" not in sigma_filter["logsource"]


def test_export_sigma_filter_parses_with_pysigma():
    """Round-trip: exported filter must parse cleanly via pySigma SigmaFilter."""
    from sigma.filters import SigmaFilter

    record = DDRRecord.model_validate(_suppress_record_data())
    sigma_filter = build_sigma_filter(record)
    parsed = SigmaFilter.from_dict(sigma_filter)
    assert parsed is not None
