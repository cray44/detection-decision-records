"""Unit tests for DDR Pydantic models."""

from __future__ import annotations

from datetime import datetime, timezone
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
    Provenance,
    RetirementReason,
    RuleRef,
    RuleSource,
    Scope,
    SigmaTarget,
    SuppressDecision,
    Tuning,
)

_VALID_HASH = "sha256:" + "a" * 64
_RULE_ID = UUID("d7a95147-145f-4678-b555-b7a3c9b16830")
_DDR_ID = UUID("f47ac10b-58cc-4372-a567-0e02b2c3d479")
_NOW = datetime(2025, 1, 15, 9, 0, 0, tzinfo=timezone.utc)
_FUTURE = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)
_PAST = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


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
    with pytest.raises(ValidationError, match="expires_on"):
        Lifecycle.model_validate(
            {"status": "active", "created_on": _NOW.isoformat(), "activated_on": _NOW.isoformat()}
        )


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
        DDRRecord.model_validate(_suppress_record(ddr_version="0.2"))


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
    ev = Evidence.model_validate({"type": "ticket", "ref": "JIRA-123", "note": "Ticket tracking this FP."})
    assert ev.type == EvidenceType.ticket
