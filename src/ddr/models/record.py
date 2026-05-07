"""DDRRecord — Pydantic v2 models (source of truth for JSON Schema).

Design locked in docs/design/v0.1-design.md and docs/design/v0.3-splunk-native-target.md.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

__all__ = [
    "DDRRecord",
    "SigmaTarget",
    "SplunkTarget",
    "SplunkQueryRef",
    "Target",
    "RuleRef",
    "RuleSource",
    "SuppressDecision",
    "AcceptRiskDecision",
    "DeprecateDecision",
    "Decision",
    "SigmaTuning",
    "SplunkTuning",
    "Tuning",
    "LogSource",
    "Lifecycle",
    "LifecycleStatus",
    "RetirementReason",
    "Provenance",
    "Evidence",
    "EvidenceType",
    "Scope",
]


class RuleSource(str, Enum):
    sigmahq = "sigmahq"
    internal = "internal"
    vendor = "vendor"


class EvidenceType(str, Enum):
    splunk_query = "splunk_query"
    log_sample_uri = "log_sample_uri"
    ticket = "ticket"
    runbook = "runbook"
    dashboard = "dashboard"
    pcap = "pcap"
    other = "other"


class LifecycleStatus(str, Enum):
    draft = "draft"
    active = "active"
    retired = "retired"


class RetirementReason(str, Enum):
    rule_deprecated = "rule-deprecated"
    fp_source_removed = "fp-source-removed"
    replaced = "replaced"
    other = "other"


_CONTENT_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_X_KEY_RE = re.compile(r"^x-[a-z]")


class RuleRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: UUID
    content_hash: str = Field(..., description="sha256:<64 lowercase hex chars>")
    source: RuleSource
    path_or_url: str
    commit: str | None = None

    @field_validator("content_hash")
    @classmethod
    def validate_hash_format(cls, v: str) -> str:
        if not _CONTENT_HASH_RE.match(v):
            raise ValueError("content_hash must be 'sha256:<64 lowercase hex chars>'")
        return v


class SigmaTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["sigma"] = "sigma"
    rule_ref: RuleRef


class SplunkQueryRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="savedsearches stanza name")
    app: str = Field(..., description="Splunk app context (e.g. 'search')")
    query_hash: str | None = Field(default=None, description="sha256 of normalized SPL (optional in v0.3)")
    path_or_url: str | None = Field(default=None, description="Link to source or savedsearches.conf path")

    @field_validator("query_hash")
    @classmethod
    def validate_query_hash(cls, v: str | None) -> str | None:
        if v is not None and not _CONTENT_HASH_RE.match(v):
            raise ValueError("query_hash must be 'sha256:<64 lowercase hex chars>'")
        return v


class SplunkTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["splunk"] = "splunk"
    query_ref: SplunkQueryRef


Target = Annotated[SigmaTarget | SplunkTarget, Field(discriminator="kind")]


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: EvidenceType
    ref: str
    note: str = Field(..., description="One sentence explaining what this evidence shows")


class Provenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    author: str
    reviewers: list[str] = Field(default_factory=list)
    approved_by: str | None = None
    ticket_refs: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)


class Lifecycle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: LifecycleStatus
    created_on: datetime
    activated_on: datetime | None = None
    retired_on: datetime | None = None
    expires_on: datetime | None = None
    review_cadence_days: int | None = Field(default=None, gt=0)
    last_reviewed_on: datetime | None = None
    superseded_by: UUID | None = None
    retirement_reason: RetirementReason | None = None

    @model_validator(mode="after")
    def check_constraints(self) -> "Lifecycle":
        if self.status == LifecycleStatus.active and self.expires_on is None:
            raise ValueError("expires_on is required when status is 'active'")
        if self.status == LifecycleStatus.retired and self.retired_on is None:
            raise ValueError("retired_on is required when status is 'retired'")
        if self.superseded_by is not None and self.status != LifecycleStatus.retired:
            raise ValueError("superseded_by is only valid when status is 'retired'")
        if self.retirement_reason is not None and self.status != LifecycleStatus.retired:
            raise ValueError("retirement_reason is only valid when status is 'retired'")
        return self


class LogSource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: str | None = None
    product: str | None = None
    service: str | None = None

    @model_validator(mode="after")
    def at_least_one(self) -> "LogSource":
        if not any([self.category, self.product, self.service]):
            raise ValueError("logsource must specify at least one of category, product, or service")
        return self


class SigmaTuning(BaseModel):
    """Sigma-Filter-expressible IR. All fields are losslessly exportable to a Sigma Filter."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["sigma"] = "sigma"
    filter_title: str | None = None
    filter_description: str | None = None
    logsource: LogSource
    selections: dict[str, Any] = Field(..., description="Named selection blocks mirroring Sigma filter: blocks")
    condition: str = Field(..., description="Sigma filter condition string")

    @field_validator("selections")
    @classmethod
    def not_empty(cls, v: dict) -> dict:
        if not v:
            raise ValueError("tuning.selections must contain at least one named selection block")
        return v


# Back-compat alias: v0.1/v0.2 code that imports Tuning still works
Tuning = SigmaTuning


class SplunkTuning(BaseModel):
    """Native SPL FP filter — no Sigma selections required."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["splunk"] = "splunk"
    filter_title: str | None = None
    filter_description: str | None = None
    splunk_filter: str = Field(..., description="Raw SPL filter clause (FP condition written directly)")

    @field_validator("splunk_filter")
    @classmethod
    def not_blank(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("splunk_filter must not be empty or whitespace")
        return v


TuningUnion = Annotated[SigmaTuning | SplunkTuning, Field(discriminator="kind")]


class SuppressDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["suppress"] = "suppress"
    rationale: str
    tuning: TuningUnion

    @field_validator("tuning", mode="before")
    @classmethod
    def default_tuning_kind(cls, v: Any) -> Any:
        # v0.1/v0.2 records have no kind field in tuning — default to sigma
        if isinstance(v, dict) and "kind" not in v:
            return {"kind": "sigma", **v}
        return v


class AcceptRiskDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["accept-risk"] = "accept-risk"
    rationale: str


class DeprecateDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["deprecate"] = "deprecate"
    rationale: str
    replacement_rule_id: UUID | None = None


Decision = Annotated[
    SuppressDecision | AcceptRiskDecision | DeprecateDecision,
    Field(discriminator="kind"),
]


class Scope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    environments: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)


class DDRRecord(BaseModel):
    """Top-level Detection Decision Record. Pydantic model is source of truth for JSON Schema."""

    model_config = ConfigDict(extra="forbid")

    ddr_version: Annotated[str, Field(pattern=r"^0\.[123]$")]
    id: UUID
    target: Target
    title: str
    description: str
    decision: Decision
    lifecycle: Lifecycle
    provenance: Provenance
    scope: Scope = Field(default_factory=Scope)
    extensions: dict[str, Any] = Field(default_factory=dict)

    @field_validator("ddr_version", mode="before")
    @classmethod
    def normalize_version(cls, v: Any) -> str:
        return str(v)

    @field_validator("extensions")
    @classmethod
    def extensions_x_prefix(cls, v: dict) -> dict:
        for key in v:
            if not _X_KEY_RE.match(key):
                raise ValueError(f"extension key '{key}' must start with 'x-' (got '{key}')")
        return v

    @model_validator(mode="after")
    def target_tuning_kind_match(self) -> "DDRRecord":
        if isinstance(self.decision, SuppressDecision):
            if self.target.kind != self.decision.tuning.kind:
                raise ValueError(
                    f"tuning.kind '{self.decision.tuning.kind}' must match target.kind '{self.target.kind}'"
                )
        return self
