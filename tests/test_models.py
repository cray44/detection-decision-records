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
    ElasticQueryRef,
    ElasticTarget,
    ElasticTuning,
    Evidence,
    EvidenceType,
    KqlM365DQueryRef,
    KqlM365DTarget,
    KqlM365DTuning,
    KqlSentinelQueryRef,
    KqlSentinelTarget,
    KqlSentinelTuning,
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


def test_evidence_type_note_accepted():
    """EvidenceType accepts the new 'note' value (SCHEMA-01 closure)."""
    ev = Evidence.model_validate({"type": "note", "ref": "INT-42", "note": "Internal reference."})
    assert ev.type == EvidenceType.note


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


# --- v0.6: ElasticQueryRef ---


def _elastic_query_ref(**kwargs) -> dict:
    return {
        "rule_id": "96b9fc2a-cbd5-4a3e-b7d7-3d9d6a6e8d5c",
        "name": "Windows Defender AV Threats",
        "index_pattern": "logs-endpoint.events.process-*",
        "source": "internal",
        **kwargs,
    }


def test_elastic_query_ref_valid():
    ref = ElasticQueryRef.model_validate(_elastic_query_ref())
    assert ref.rule_id == "96b9fc2a-cbd5-4a3e-b7d7-3d9d6a6e8d5c"
    assert ref.index_pattern == "logs-endpoint.events.process-*"
    assert ref.content_hash is None
    assert ref.path_or_url is None


def test_elastic_query_ref_with_hash():
    ref = ElasticQueryRef.model_validate(_elastic_query_ref(content_hash="sha256:" + "c" * 64))
    assert ref.content_hash == "sha256:" + "c" * 64


def test_elastic_query_ref_invalid_hash():
    with pytest.raises(ValidationError, match="content_hash"):
        ElasticQueryRef.model_validate(_elastic_query_ref(content_hash="not-a-hash"))


def test_elastic_query_ref_extra_field_rejected():
    with pytest.raises(ValidationError):
        ElasticQueryRef.model_validate(_elastic_query_ref(unknown="bad"))


def test_elastic_query_ref_rule_id_accepts_no_hyphens():
    """Elastic rule IDs without hyphens are accepted (str field, not UUID)."""
    no_hyphen = "96b9fc2acbd54a3eb7d73d9d6a6e8d5c"
    ref = ElasticQueryRef.model_validate(_elastic_query_ref(rule_id=no_hyphen))
    assert ref.rule_id == no_hyphen


# --- v0.6: ElasticTarget ---


def test_elastic_target_single_ref():
    t = ElasticTarget.model_validate(
        {"kind": "elastic", "query_refs": [_elastic_query_ref()]}
    )
    assert t.kind == "elastic"
    assert len(t.query_refs) == 1


def test_elastic_target_multi_ref():
    t = ElasticTarget.model_validate(
        {
            "kind": "elastic",
            "query_refs": [
                _elastic_query_ref(rule_id="rule-1", name="Rule 1"),
                _elastic_query_ref(rule_id="rule-2", name="Rule 2"),
                _elastic_query_ref(rule_id="rule-3", name="Rule 3"),
            ],
        }
    )
    assert len(t.query_refs) == 3


def test_elastic_target_empty_query_refs_rejected():
    with pytest.raises(ValidationError):
        ElasticTarget.model_validate({"kind": "elastic", "query_refs": []})


def test_elastic_target_extra_field_rejected():
    with pytest.raises(ValidationError):
        ElasticTarget.model_validate(
            {"kind": "elastic", "query_refs": [_elastic_query_ref()], "bad": "field"}
        )


# --- v0.6: ElasticTuning ---


def test_elastic_tuning_valid():
    t = ElasticTuning.model_validate(
        {"kind": "elastic", "kql_filter": 'source.ip : "10.0.100.0/24"'}
    )
    assert t.kql_filter == 'source.ip : "10.0.100.0/24"'


def test_elastic_tuning_blank_filter_rejected():
    with pytest.raises(ValidationError, match="kql_filter"):
        ElasticTuning.model_validate({"kind": "elastic", "kql_filter": "   "})


def test_elastic_tuning_empty_filter_rejected():
    with pytest.raises(ValidationError, match="kql_filter"):
        ElasticTuning.model_validate({"kind": "elastic", "kql_filter": ""})


def test_elastic_tuning_optional_title():
    t = ElasticTuning.model_validate(
        {
            "kind": "elastic",
            "kql_filter": 'agent.name : "nessus*"',
            "filter_title": "Suppress Nessus",
            "filter_description": "Scanner FP suppression.",
        }
    )
    assert t.filter_title == "Suppress Nessus"


def test_elastic_tuning_extra_field_rejected():
    with pytest.raises(ValidationError):
        ElasticTuning.model_validate(
            {"kind": "elastic", "kql_filter": "host=foo", "bad": "field"}
        )


# --- v0.6: DDRRecord with Elastic target ---


def _elastic_suppress_record(**overrides) -> dict:
    base = {
        "ddr_version": "0.6",
        "id": str(_DDR_ID),
        "title": "Suppress: Elastic AV scanner noise",
        "description": "Nessus scanner FP.",
        "target": {
            "kind": "elastic",
            "query_refs": [_elastic_query_ref()],
        },
        "decision": {
            "kind": "suppress",
            "rationale": "Scanner FP confirmed.",
            "tuning": {
                "kind": "elastic",
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


def test_ddr_record_elastic_target_suppress():
    record = DDRRecord.model_validate(_elastic_suppress_record())
    assert isinstance(record.target, ElasticTarget)
    assert record.target.kind == "elastic"
    assert len(record.target.query_refs) == 1
    assert isinstance(record.decision.tuning, ElasticTuning)  # type: ignore[union-attr]


def test_ddr_record_elastic_target_accept_risk():
    data = _elastic_suppress_record()
    data["decision"] = {"kind": "accept-risk", "rationale": "Accepted."}
    record = DDRRecord.model_validate(data)
    assert isinstance(record.target, ElasticTarget)


def test_ddr_record_elastic_target_deprecate():
    data = _elastic_suppress_record()
    data["lifecycle"] = {
        "status": "retired",
        "created_on": _NOW.isoformat(),
        "retired_on": _NOW.isoformat(),
        "retirement_reason": "replaced",
    }
    data["decision"] = {"kind": "deprecate", "rationale": "Retired."}
    record = DDRRecord.model_validate(data)
    assert isinstance(record.target, ElasticTarget)


def test_ddr_record_elastic_cross_field_mismatch_splunk_tuning():
    data = _elastic_suppress_record()
    data["decision"]["tuning"] = {"kind": "splunk", "splunk_filter": "host=foo"}
    with pytest.raises(ValidationError, match=r"tuning\.kind"):
        DDRRecord.model_validate(data)


def test_ddr_record_elastic_cross_field_mismatch_sigma_tuning():
    data = _elastic_suppress_record()
    data["decision"]["tuning"] = {
        "kind": "sigma",
        "logsource": {"product": "windows"},
        "selections": {"fp": {"host": "foo"}},
        "condition": "not fp",
    }
    with pytest.raises(ValidationError, match=r"tuning\.kind"):
        DDRRecord.model_validate(data)


def test_ddr_version_06_accepted():
    data = _elastic_suppress_record(ddr_version="0.6")
    record = DDRRecord.model_validate(data)
    assert record.ddr_version == "0.6"


def test_ddr_record_elastic_fixture(valid_fixtures_dir):
    """elastic_suppress.yml fixture validates cleanly."""
    raw = (
        __import__("ruamel.yaml", fromlist=["YAML"])
        .YAML(typ="safe")
        .load((valid_fixtures_dir / "elastic_suppress.yml").read_text())
    )
    record = DDRRecord.model_validate(raw)
    assert record.target.kind == "elastic"
    assert len(record.target.query_refs) == 2  # type: ignore[union-attr]


# --- KQL Sentinel models ---


def _kql_sentinel_ref(**kwargs) -> dict:
    return {"rule_id": "sentinel-rule-001", "name": "Test Sentinel Rule", "source": "internal",
            **kwargs}


def _kql_sentinel_suppress_record(**overrides) -> dict:
    base = {
        "ddr_version": "0.7",
        "id": str(_DDR_ID),
        "title": "Suppress: Sentinel test",
        "description": "KQL sentinel test record.",
        "target": {
            "kind": "kql-sentinel",
            "query_refs": [_kql_sentinel_ref()],
        },
        "decision": {
            "kind": "suppress",
            "rationale": "Authorized activity.",
            "tuning": {
                "kind": "kql-sentinel",
                "kusto_filter": 'IPAddress has_any ("10.50.0.0/16")',
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


def test_kql_sentinel_target_valid():
    t = KqlSentinelTarget.model_validate({"query_refs": [_kql_sentinel_ref()]})
    assert t.kind == "kql-sentinel"
    assert len(t.query_refs) == 1


def test_kql_sentinel_target_empty_refs_rejected():
    with pytest.raises(ValidationError):
        KqlSentinelTarget.model_validate({"query_refs": []})


def test_kql_sentinel_query_ref_optional_workspace():
    ref = KqlSentinelQueryRef.model_validate(_kql_sentinel_ref(workspace="my-workspace"))
    assert ref.workspace == "my-workspace"


def test_kql_sentinel_query_ref_optional_content_hash():
    ref = KqlSentinelQueryRef.model_validate(_kql_sentinel_ref(content_hash=_VALID_HASH))
    assert ref.content_hash == _VALID_HASH


def test_kql_sentinel_query_ref_bad_hash_rejected():
    with pytest.raises(ValidationError, match="content_hash"):
        KqlSentinelQueryRef.model_validate(_kql_sentinel_ref(content_hash="not-a-hash"))


def test_kql_sentinel_tuning_valid():
    t = KqlSentinelTuning.model_validate(
        {"kind": "kql-sentinel", "kusto_filter": 'IPAddress =~ "10.0.0.1"'}
    )
    assert t.kusto_filter == 'IPAddress =~ "10.0.0.1"'


def test_kql_sentinel_tuning_blank_filter_rejected():
    with pytest.raises(ValidationError, match="kusto_filter"):
        KqlSentinelTuning.model_validate({"kind": "kql-sentinel", "kusto_filter": "   "})


def test_kql_sentinel_suppress_record_valid():
    record = DDRRecord.model_validate(_kql_sentinel_suppress_record())
    assert record.target.kind == "kql-sentinel"
    assert record.decision.kind == "suppress"


def test_kql_sentinel_kind_mismatch_rejected():
    data = _kql_sentinel_suppress_record()
    data["decision"]["tuning"]["kind"] = "kql-m365d"
    with pytest.raises(ValidationError, match=r"tuning\.kind"):
        DDRRecord.model_validate(data)


# --- KQL M365D models ---


def _kql_m365d_ref(**kwargs) -> dict:
    return {"rule_id": "m365d-detection-001", "name": "Test M365D Detection", "source": "internal",
            **kwargs}


def _kql_m365d_suppress_record(**overrides) -> dict:
    base = {
        "ddr_version": "0.7",
        "id": str(_DDR_ID),
        "title": "Suppress: M365D test",
        "description": "KQL m365d test record.",
        "target": {
            "kind": "kql-m365d",
            "query_refs": [_kql_m365d_ref()],
        },
        "decision": {
            "kind": "suppress",
            "rationale": "Authorized admin activity.",
            "tuning": {
                "kind": "kql-m365d",
                "kusto_filter": 'InitiatingProcessAccountName has_any ("svc-patching")',
            },
        },
        "lifecycle": {
            "status": "active",
            "created_on": _NOW.isoformat(),
            "activated_on": _NOW.isoformat(),
            "expires_on": _FUTURE.isoformat(),
        },
        "provenance": {"author": "bob@example.com"},
    }
    base.update(overrides)
    return base


def test_kql_m365d_target_valid():
    t = KqlM365DTarget.model_validate({"query_refs": [_kql_m365d_ref()]})
    assert t.kind == "kql-m365d"
    assert len(t.query_refs) == 1


def test_kql_m365d_target_empty_refs_rejected():
    with pytest.raises(ValidationError):
        KqlM365DTarget.model_validate({"query_refs": []})


def test_kql_m365d_query_ref_optional_table():
    ref = KqlM365DQueryRef.model_validate(_kql_m365d_ref(table="DeviceProcessEvents"))
    assert ref.table == "DeviceProcessEvents"


def test_kql_m365d_query_ref_bad_hash_rejected():
    with pytest.raises(ValidationError, match="content_hash"):
        KqlM365DQueryRef.model_validate(_kql_m365d_ref(content_hash="bad"))


def test_kql_m365d_tuning_valid():
    t = KqlM365DTuning.model_validate(
        {"kind": "kql-m365d", "kusto_filter": 'AccountName has "svc-deploy"'}
    )
    assert t.kusto_filter == 'AccountName has "svc-deploy"'


def test_kql_m365d_tuning_blank_filter_rejected():
    with pytest.raises(ValidationError, match="kusto_filter"):
        KqlM365DTuning.model_validate({"kind": "kql-m365d", "kusto_filter": ""})


def test_kql_m365d_suppress_record_valid():
    record = DDRRecord.model_validate(_kql_m365d_suppress_record())
    assert record.target.kind == "kql-m365d"
    assert record.decision.kind == "suppress"


def test_kql_m365d_kind_mismatch_rejected():
    data = _kql_m365d_suppress_record()
    data["decision"]["tuning"]["kind"] = "kql-sentinel"
    with pytest.raises(ValidationError, match=r"tuning\.kind"):
        DDRRecord.model_validate(data)


def test_ddr_version_07_accepted():
    record = DDRRecord.model_validate(_kql_sentinel_suppress_record(ddr_version="0.7"))
    assert record.ddr_version == "0.7"


def test_ddr_version_08_accepted():
    record = DDRRecord.model_validate(_kql_sentinel_suppress_record(ddr_version="0.8"))
    assert record.ddr_version == "0.8"


def test_ddr_version_09_rejected():
    with pytest.raises(ValidationError):
        DDRRecord.model_validate(_kql_sentinel_suppress_record(ddr_version="0.9"))


def test_kql_sentinel_fixture(valid_fixtures_dir):
    raw = (
        __import__("ruamel.yaml", fromlist=["YAML"])
        .YAML(typ="safe")
        .load((valid_fixtures_dir / "kql_sentinel_suppress.yml").read_text())
    )
    record = DDRRecord.model_validate(raw)
    assert record.target.kind == "kql-sentinel"
    assert len(record.target.query_refs) == 1  # type: ignore[union-attr]


def test_kql_m365d_fixture(valid_fixtures_dir):
    raw = (
        __import__("ruamel.yaml", fromlist=["YAML"])
        .YAML(typ="safe")
        .load((valid_fixtures_dir / "kql_m365d_suppress.yml").read_text())
    )
    record = DDRRecord.model_validate(raw)
    assert record.target.kind == "kql-m365d"
    assert len(record.target.query_refs) == 1  # type: ignore[union-attr]


def test_v01_fixture_still_valid_under_v07(valid_fixtures_dir):
    raw = (
        __import__("ruamel.yaml", fromlist=["YAML"])
        .YAML(typ="safe")
        .load((valid_fixtures_dir / "suppress_basic.yml").read_text())
    )
    record = DDRRecord.model_validate(raw)
    assert record.ddr_version == "0.1"
