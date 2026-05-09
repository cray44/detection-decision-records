"""Unit tests for DDR Pydantic models."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from ddr.models.record import (
    AcceptRiskDecision,
    DDRRecord,
    DeprecateDecision,
    Evidence,
    EvidenceType,
    Lifecycle,
    LifecycleStatus,
    LogSource,
    RuleRef,
    SigmaTarget,
    SigmaTuning,
    SplunkQueryRef,
    SplunkTarget,
    SplunkTuning,
    SuppressDecision,
    Tuning,
)

_VALID_HASH = "sha256:" + "a" * 64
_RULE_ID = UUID("d7a95147-145f-4678-b555-b7a3c9b16830")
_DDR_ID = UUID("f47ac10b-58cc-4372-a567-0e02b2c3d479")
_NOW = datetime(2025, 1, 15, 9, 0, 0, tzinfo=UTC)
_FUTURE = datetime(2026, 1, 15, 9, 0, 0, tzinfo=UTC)
_PAST = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)


def _rule_ref(**kwargs) -> dict:
    return {
        "rule_id": str(_RULE_ID),
        "content_hash": _VALID_HASH,
        "source": "sigmahq",
        "path_or_url": "https://example.com/rule.yml",
        **kwargs,
    }


def _suppress_record(**overrides) -> dict:
    base = {
        "ddr_version": "0.1",
        "id": str(_DDR_ID),
        "title": "Test suppress",
        "description": "A test DDR record.",
        "target": {"kind": "sigma", "rule_ref": _rule_ref()},
        "decision": {
            "kind": "suppress",
            "rationale": "Known FP from SCCM.",
            "tuning": {
                "logsource": {"category": "process_creation", "product": "windows"},
                "selections": {"known_fp": {"ParentImage|endswith": ["\\ccmexec.exe"]}},
                "condition": "not known_fp",
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


# --- RuleRef ---


def test_rule_ref_valid_hash():
    rr = RuleRef.model_validate(_rule_ref())
    assert rr.content_hash == _VALID_HASH


def test_rule_ref_invalid_hash_format():
    with pytest.raises(ValidationError, match="content_hash"):
        RuleRef.model_validate(_rule_ref(content_hash="not-a-hash"))


def test_rule_ref_invalid_hash_short():
    with pytest.raises(ValidationError, match="content_hash"):
        RuleRef.model_validate(_rule_ref(content_hash="sha256:abc123"))


def test_rule_ref_optional_commit():
    rr = RuleRef.model_validate(_rule_ref(commit="abc123def"))
    assert rr.commit == "abc123def"


def test_rule_ref_extra_field_rejected():
    with pytest.raises(ValidationError):
        RuleRef.model_validate(_rule_ref(unknown_field="bad"))


# --- LogSource ---


def test_logsource_requires_at_least_one():
    with pytest.raises(ValidationError, match="at least one"):
        LogSource.model_validate({})


def test_logsource_category_only():
    ls = LogSource.model_validate({"category": "process_creation"})
    assert ls.category == "process_creation"


# --- Lifecycle ---


def test_lifecycle_active_requires_expires_on():
    data = _suppress_record()
    del data["lifecycle"]["expires_on"]
    with pytest.raises(ValidationError, match="expires_on"):
        DDRRecord.model_validate(data)


def test_lifecycle_active_deprecate_no_expires_on_allowed():
    """deprecate + status:active is valid without expires_on (permanent tombstone)."""
    data = _suppress_record()
    del data["lifecycle"]["expires_on"]
    data["lifecycle"]["activated_on"] = _NOW.isoformat()
    data["decision"] = {"kind": "deprecate", "rationale": "Replaced by v2."}
    record = DDRRecord.model_validate(data)
    assert record.lifecycle.expires_on is None


def test_lifecycle_retired_requires_retired_on():
    with pytest.raises(ValidationError, match="retired_on"):
        Lifecycle.model_validate({"status": "retired", "created_on": _NOW.isoformat()})


def test_lifecycle_superseded_by_requires_retired():
    with pytest.raises(ValidationError, match="superseded_by"):
        Lifecycle.model_validate(
            {
                "status": "active",
                "created_on": _NOW.isoformat(),
                "expires_on": _FUTURE.isoformat(),
                "superseded_by": str(uuid4()),
            }
        )


def test_lifecycle_retirement_reason_requires_retired():
    with pytest.raises(ValidationError, match="retirement_reason"):
        Lifecycle.model_validate(
            {
                "status": "active",
                "created_on": _NOW.isoformat(),
                "expires_on": _FUTURE.isoformat(),
                "retirement_reason": "replaced",
            }
        )


def test_lifecycle_draft_minimal():
    lc = Lifecycle.model_validate({"status": "draft", "created_on": _NOW.isoformat()})
    assert lc.status == LifecycleStatus.draft


def test_lifecycle_review_cadence_must_be_positive():
    with pytest.raises(ValidationError):
        Lifecycle.model_validate(
            {
                "status": "active",
                "created_on": _NOW.isoformat(),
                "expires_on": _FUTURE.isoformat(),
                "review_cadence_days": 0,
            }
        )


# --- Tuning ---


def test_tuning_empty_selections_rejected():
    with pytest.raises(ValidationError, match="at least one"):
        Tuning.model_validate(
            {
                "logsource": {"product": "windows"},
                "selections": {},
                "condition": "not x",
            }
        )


# --- DDRRecord ---


def test_ddr_record_suppress_roundtrip():
    record = DDRRecord.model_validate(_suppress_record())
    assert record.id == _DDR_ID
    assert isinstance(record.decision, SuppressDecision)
    assert record.decision.kind == "suppress"


def test_ddr_record_accept_risk():
    data = _suppress_record()
    data["decision"] = {"kind": "accept-risk", "rationale": "Accepted."}
    record = DDRRecord.model_validate(data)
    assert isinstance(record.decision, AcceptRiskDecision)


def test_ddr_record_deprecate():
    data = _suppress_record()
    data["lifecycle"] = {
        "status": "retired",
        "created_on": _NOW.isoformat(),
        "activated_on": _NOW.isoformat(),
        "retired_on": _NOW.isoformat(),
        "retirement_reason": "replaced",
    }
    data["decision"] = {
        "kind": "deprecate",
        "rationale": "Replaced by new rule.",
        "replacement_rule_id": str(uuid4()),
    }
    record = DDRRecord.model_validate(data)
    assert isinstance(record.decision, DeprecateDecision)
    assert record.decision.replacement_rule_id is not None


def test_ddr_record_extra_top_level_field_rejected():
    data = _suppress_record()
    data["unknown_field"] = "bad"
    with pytest.raises(ValidationError):
        DDRRecord.model_validate(data)


def test_ddr_record_extensions_require_x_prefix():
    data = _suppress_record()
    data["extensions"] = {"bad-key": "value"}
    with pytest.raises(ValidationError, match="x-"):
        DDRRecord.model_validate(data)


def test_ddr_record_extensions_x_prefix_accepted():
    data = _suppress_record()
    data["extensions"] = {"x-vendor-field": "custom"}
    record = DDRRecord.model_validate(data)
    assert record.extensions["x-vendor-field"] == "custom"


def test_ddr_version_float_coerced():
    data = _suppress_record(ddr_version=0.1)
    record = DDRRecord.model_validate(data)
    assert record.ddr_version == "0.1"


def test_ddr_version_wrong_value():
    with pytest.raises(ValidationError):
        DDRRecord.model_validate(_suppress_record(ddr_version="0.9"))


def test_ddr_record_scope_optional():
    record = DDRRecord.model_validate(_suppress_record())
    assert record.scope.environments == []


def test_ddr_record_scope_with_envs():
    data = _suppress_record()
    data["scope"] = {"environments": ["prod", "staging"]}
    record = DDRRecord.model_validate(data)
    assert record.scope.environments == ["prod", "staging"]


def test_evidence_requires_note():
    with pytest.raises(ValidationError):
        Evidence.model_validate({"type": "ticket", "ref": "JIRA-123"})


def test_evidence_valid():
    ev = Evidence.model_validate(
        {"type": "ticket", "ref": "JIRA-123", "note": "Ticket tracking this FP."}
    )
    assert ev.type == EvidenceType.ticket


# --- v0.3: SplunkQueryRef ---


def _splunk_query_ref(**kwargs) -> dict:
    return {"name": "My Detection", "app": "search", **kwargs}


def test_splunk_query_ref_valid():
    ref = SplunkQueryRef.model_validate(_splunk_query_ref())
    assert ref.name == "My Detection"
    assert ref.app == "search"
    assert ref.query_hash is None
    assert ref.path_or_url is None


def test_splunk_query_ref_with_optional_fields():
    ref = SplunkQueryRef.model_validate(
        _splunk_query_ref(
            query_hash="sha256:" + "b" * 64,
            path_or_url="/opt/splunk/etc/apps/search/local/savedsearches.conf",
        )
    )
    assert ref.query_hash == "sha256:" + "b" * 64


def test_splunk_query_ref_invalid_hash():
    with pytest.raises(ValidationError, match="query_hash"):
        SplunkQueryRef.model_validate(_splunk_query_ref(query_hash="not-a-hash"))


def test_splunk_query_ref_extra_field_rejected():
    with pytest.raises(ValidationError):
        SplunkQueryRef.model_validate(_splunk_query_ref(unknown="bad"))


# --- v0.3: SplunkTarget ---


def test_splunk_target_valid():
    t = SplunkTarget.model_validate({"kind": "splunk", "query_refs": [_splunk_query_ref()]})
    assert t.kind == "splunk"
    assert t.query_refs[0].name == "My Detection"


def test_splunk_target_back_compat_singular():
    """v0.3 YAML with query_ref (singular) still loads via the coercion shim."""
    t = SplunkTarget.model_validate({"kind": "splunk", "query_ref": _splunk_query_ref()})
    assert t.query_refs[0].name == "My Detection"


def test_splunk_target_extra_field_rejected():
    with pytest.raises(ValidationError):
        SplunkTarget.model_validate(
            {"kind": "splunk", "query_refs": [_splunk_query_ref()], "bad": "field"}
        )


# --- v0.3: SplunkTuning ---


def test_splunk_tuning_valid():
    t = SplunkTuning.model_validate({"kind": "splunk", "splunk_filter": "src_ip=10.0.0.1"})
    assert t.splunk_filter == "src_ip=10.0.0.1"


def test_splunk_tuning_blank_filter_rejected():
    with pytest.raises(ValidationError, match="splunk_filter"):
        SplunkTuning.model_validate({"kind": "splunk", "splunk_filter": "   "})


def test_splunk_tuning_empty_filter_rejected():
    with pytest.raises(ValidationError, match="splunk_filter"):
        SplunkTuning.model_validate({"kind": "splunk", "splunk_filter": ""})


def test_splunk_tuning_extra_field_rejected():
    with pytest.raises(ValidationError):
        SplunkTuning.model_validate({"kind": "splunk", "splunk_filter": "host=foo", "bad": "field"})


# --- v0.3: Tuning alias ---


def test_tuning_alias_is_sigma_tuning():
    assert Tuning is SigmaTuning


# --- v0.3: DDRRecord with Splunk target ---


def _splunk_suppress_record(**overrides) -> dict:
    base = {
        "ddr_version": "0.3",
        "id": str(_DDR_ID),
        "title": "Suppress: noisy Splunk detection",
        "description": "FP from authorized scanner.",
        "target": {
            "kind": "splunk",
            "query_refs": [{"name": "My Detection", "app": "search"}],
        },
        "decision": {
            "kind": "suppress",
            "rationale": "Scanner FP.",
            "tuning": {
                "kind": "splunk",
                "splunk_filter": "src_ip=10.0.0.0/8",
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


def test_ddr_record_splunk_target_suppress():
    record = DDRRecord.model_validate(_splunk_suppress_record())
    assert isinstance(record.target, SplunkTarget)
    assert record.target.kind == "splunk"
    assert len(record.target.query_refs) == 1
    assert isinstance(record.decision.tuning, SplunkTuning)  # type: ignore[union-attr]


def test_ddr_record_splunk_target_accept_risk():
    data = _splunk_suppress_record()
    data["decision"] = {"kind": "accept-risk", "rationale": "Accepted."}
    record = DDRRecord.model_validate(data)
    assert isinstance(record.target, SplunkTarget)


def test_ddr_record_splunk_target_deprecate():
    data = _splunk_suppress_record()
    data["lifecycle"] = {
        "status": "retired",
        "created_on": _NOW.isoformat(),
        "retired_on": _NOW.isoformat(),
        "retirement_reason": "replaced",
    }
    data["decision"] = {"kind": "deprecate", "rationale": "Retired."}
    record = DDRRecord.model_validate(data)
    assert isinstance(record.target, SplunkTarget)


def test_ddr_record_cross_field_validator_kind_mismatch():
    data = _splunk_suppress_record()
    # Splunk target + Sigma tuning → should fail
    data["decision"]["tuning"] = {
        "kind": "sigma",
        "logsource": {"category": "process_creation"},
        "selections": {"fp": {"host": "foo"}},
        "condition": "not fp",
    }
    with pytest.raises(ValidationError, match=r"tuning\.kind"):
        DDRRecord.model_validate(data)


def test_ddr_record_cross_field_validator_sigma_target_splunk_tuning():
    data = _suppress_record()
    data["decision"]["tuning"] = {
        "kind": "splunk",
        "splunk_filter": "host=foo",
    }
    with pytest.raises(ValidationError, match=r"tuning\.kind"):
        DDRRecord.model_validate(data)


def test_ddr_record_v01_back_compat_no_tuning_kind():
    """v0.1 tuning without kind field defaults to sigma."""
    record = DDRRecord.model_validate(_suppress_record())
    assert isinstance(record.decision.tuning, SigmaTuning)  # type: ignore[union-attr]
    assert record.decision.tuning.kind == "sigma"


def test_ddr_record_v02_back_compat():
    record = DDRRecord.model_validate(_suppress_record(ddr_version="0.2"))
    assert record.ddr_version == "0.2"
    assert isinstance(record.target, SigmaTarget)


def test_ddr_version_02_accepted():
    record = DDRRecord.model_validate(_suppress_record(ddr_version="0.2"))
    assert record.ddr_version == "0.2"


def test_ddr_version_03_accepted():
    record = DDRRecord.model_validate(_splunk_suppress_record(ddr_version="0.3"))
    assert record.ddr_version == "0.3"


def test_mixed_sigma_splunk_directory_validates(valid_fixtures_dir):
    """Both Sigma-targeted and Splunk-targeted fixtures parse cleanly."""
    sigma_record = DDRRecord.model_validate(
        __import__("ruamel.yaml", fromlist=["YAML"])
        .YAML(typ="safe")
        .load((valid_fixtures_dir / "suppress_basic.yml").read_text())
    )
    splunk_record = DDRRecord.model_validate(
        __import__("ruamel.yaml", fromlist=["YAML"])
        .YAML(typ="safe")
        .load((valid_fixtures_dir / "splunk_native_suppress.yml").read_text())
    )
    assert sigma_record.target.kind == "sigma"
    assert splunk_record.target.kind == "splunk"


# --- v0.5: multi-rule targeting ---


def _multi_ref_rule(n: int) -> dict:
    h = hex(n)[2:].zfill(64)
    return {
        "rule_id": f"a{n:07d}-0000-0000-0000-000000000000",
        "content_hash": f"sha256:{h}",
        "source": "sigmahq",
        "path_or_url": f"https://example.com/rule{n}.yml",
    }


def test_sigma_target_multi_ref():
    t = SigmaTarget.model_validate(
        {"kind": "sigma", "rule_refs": [_multi_ref_rule(1), _multi_ref_rule(2), _multi_ref_rule(3)]}
    )
    assert len(t.rule_refs) == 3


def test_sigma_target_single_ref_list():
    t = SigmaTarget.model_validate({"kind": "sigma", "rule_refs": [_multi_ref_rule(1)]})
    assert len(t.rule_refs) == 1


def test_sigma_target_back_compat_singular_rule_ref():
    """v0.1-v0.4 YAML with rule_ref (singular) still loads."""
    t = SigmaTarget.model_validate({"kind": "sigma", "rule_ref": _rule_ref()})
    assert len(t.rule_refs) == 1
    assert t.rule_refs[0].content_hash == _VALID_HASH


def test_sigma_target_rule_refs_both_present_rule_refs_wins():
    """When both rule_ref and rule_refs present, rule_refs takes precedence."""
    t = SigmaTarget.model_validate(
        {"kind": "sigma", "rule_ref": _rule_ref(), "rule_refs": [_multi_ref_rule(1)]}
    )
    assert len(t.rule_refs) == 1
    assert "a0000001" in str(t.rule_refs[0].rule_id)


def test_sigma_target_empty_rule_refs_rejected():
    with pytest.raises(ValidationError):
        SigmaTarget.model_validate({"kind": "sigma", "rule_refs": []})


def test_splunk_target_multi_ref():
    t = SplunkTarget.model_validate(
        {
            "kind": "splunk",
            "query_refs": [
                {"name": "Detection A", "app": "search"},
                {"name": "Detection B", "app": "search"},
            ],
        }
    )
    assert len(t.query_refs) == 2


def test_splunk_target_empty_query_refs_rejected():
    with pytest.raises(ValidationError):
        SplunkTarget.model_validate({"kind": "splunk", "query_refs": []})


def test_ddr_record_multi_ref_fixture(valid_fixtures_dir):
    """multi_ref_sigma.yml fixture (3 rule_refs) validates cleanly."""
    raw = (
        __import__("ruamel.yaml", fromlist=["YAML"])
        .YAML(typ="safe")
        .load((valid_fixtures_dir / "multi_ref_sigma.yml").read_text())
    )
    record = DDRRecord.model_validate(raw)
    assert len(record.target.rule_refs) == 3  # type: ignore[union-attr]


def test_ddr_record_v04_back_compat_fixture(valid_fixtures_dir):
    """v0.4_backcompat_rule_ref.yml (singular rule_ref) validates under v0.5 schema."""
    raw = (
        __import__("ruamel.yaml", fromlist=["YAML"])
        .YAML(typ="safe")
        .load((valid_fixtures_dir / "v0.4_backcompat_rule_ref.yml").read_text())
    )
    record = DDRRecord.model_validate(raw)
    assert len(record.target.rule_refs) == 1  # type: ignore[union-attr]


def test_ddr_version_05_accepted():
    data = _suppress_record(ddr_version="0.5")
    record = DDRRecord.model_validate(data)
    assert record.ddr_version == "0.5"
