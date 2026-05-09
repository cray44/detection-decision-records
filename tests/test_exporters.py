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
                "selections": {"known_fp_sccm": {"ParentImage|endswith": ["\\ccmexec.exe"]}},
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


# ---------------------------------------------------------------------------
# Elastic exception exporter (v0.6)
# ---------------------------------------------------------------------------

import json as _json  # noqa: E402

from ddr.exporters.elastic_exception import build_elastic_exception, export_to_ndjson  # noqa: E402


def _elastic_suppress_data(**overrides) -> dict:
    base = {
        "ddr_version": "0.6",
        "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "title": "Suppress: AV scanner noise",
        "description": "Nessus scanner FP.",
        "target": {
            "kind": "elastic",
            "query_refs": [
                {
                    "rule_id": "96b9fc2a-cbd5-4a3e-b7d7-3d9d6a6e8d5c",
                    "name": "Windows Defender AV Threats",
                    "index_pattern": "logs-endpoint.events.process-*",
                    "source": "internal",
                }
            ],
        },
        "decision": {
            "kind": "suppress",
            "rationale": "Scanner FP.",
            "tuning": {
                "kind": "elastic",
                "filter_title": "Suppress Nessus AV",
                "kql_filter": 'source.ip : "10.0.100.0/24"',
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


def test_elastic_exception_structure():
    record = DDRRecord.model_validate(_elastic_suppress_data())
    item = build_elastic_exception(record)
    item.pop("_is_manual")
    assert item["namespace_type"] == "single"
    assert item["type"] == "simple"
    assert "entries" in item
    assert "tags" in item
    assert "ddr" in item["tags"]


def test_elastic_exception_simple_match_entry():
    record = DDRRecord.model_validate(_elastic_suppress_data())
    item = build_elastic_exception(record)
    item.pop("_is_manual")
    assert len(item["entries"]) == 1
    entry = item["entries"][0]
    assert entry["field"] == "source.ip"
    assert entry["type"] == "match"
    assert entry["value"] == "10.0.100.0/24"


def test_elastic_exception_and_chain():
    data = _elastic_suppress_data()
    data["decision"]["tuning"]["kql_filter"] = (
        'source.ip : "10.0.100.0/24" and agent.name : "nessus"'
    )
    record = DDRRecord.model_validate(data)
    item = build_elastic_exception(record)
    is_manual = item.pop("_is_manual")
    assert not is_manual
    assert len(item["entries"]) == 2


def test_elastic_exception_wildcard_entry():
    data = _elastic_suppress_data()
    data["decision"]["tuning"]["kql_filter"] = 'agent.name : nessus*'
    record = DDRRecord.model_validate(data)
    item = build_elastic_exception(record)
    item.pop("_is_manual")
    assert len(item["entries"]) == 1
    assert item["entries"][0]["type"] == "wildcard"
    assert item["entries"][0]["value"] == "nessus*"


def test_elastic_exception_complex_kql_is_manual():
    data = _elastic_suppress_data()
    data["decision"]["tuning"]["kql_filter"] = 'source.ip : "10.0.0.1" or agent.name : "nessus"'
    record = DDRRecord.model_validate(data)
    item = build_elastic_exception(record)
    is_manual = item.pop("_is_manual")
    assert is_manual
    assert item["entries"] == []


def test_elastic_exception_nested_parens_is_manual():
    data = _elastic_suppress_data()
    data["decision"]["tuning"]["kql_filter"] = '(source.ip : "10.0.0.1" and host.name : "foo")'
    record = DDRRecord.model_validate(data)
    item = build_elastic_exception(record)
    is_manual = item.pop("_is_manual")
    assert is_manual


def test_elastic_exception_kql_preserved_in_description():
    """Raw KQL always appears in the item description for human review."""
    record = DDRRecord.model_validate(_elastic_suppress_data())
    item = build_elastic_exception(record)
    item.pop("_is_manual")
    assert 'source.ip : "10.0.100.0/24"' in item["description"]


def test_elastic_exception_filter_title_used_as_name():
    record = DDRRecord.model_validate(_elastic_suppress_data())
    item = build_elastic_exception(record)
    item.pop("_is_manual")
    assert item["name"] == "Suppress Nessus AV"


def test_elastic_exception_list_id_respected():
    record = DDRRecord.model_validate(_elastic_suppress_data())
    item = build_elastic_exception(record, list_id="my-custom-list")
    item.pop("_is_manual")
    assert item["list_id"] == "my-custom-list"


def test_elastic_exception_non_suppress_raises():
    data = _elastic_suppress_data()
    data["decision"] = {"kind": "accept-risk", "rationale": "Accepted."}
    record = DDRRecord.model_validate(data)
    with pytest.raises(ValueError, match="suppress"):
        build_elastic_exception(record)


def test_elastic_exception_non_elastic_target_raises():
    record = DDRRecord.model_validate(_suppress_record_data())
    with pytest.raises(ValueError, match="elastic"):
        build_elastic_exception(record)


def test_export_to_ndjson_returns_string():
    record = DDRRecord.model_validate(_elastic_suppress_data())
    ndjson, _ = export_to_ndjson(record)
    obj = _json.loads(ndjson)
    assert obj["type"] == "simple"


def test_export_to_ndjson_writes_file(tmp_path):
    record = DDRRecord.model_validate(_elastic_suppress_data())
    out = tmp_path / "exception.ndjson"
    ndjson, _ = export_to_ndjson(record, output=out)
    assert out.exists()
    content = out.read_text(encoding="utf-8").strip()
    assert _json.loads(content) == _json.loads(ndjson)
