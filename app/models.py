from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class LogSinkApproval(BaseModel):
    sink_type: Literal["cloudwatch", "loki", "file"]
    connection_params: dict[str, Any] = Field(default_factory=dict)


class ApprovalCreate(BaseModel):
    kind: Literal["policy_change"]
    action: Literal["log_sink"]
    payload: LogSinkApproval


class ApprovalRead(BaseModel):
    id: int
    kind: str
    service: str | None
    action: str | None
    payload: dict[str, Any]
    incident_id: int | None
    trace_id: str | None
    status: str
    pr_number: int | None
    pr_url: str | None
    base_commit_sha: str | None
    requested_by: str
    requested_at: datetime
    expires_at: datetime
    decided_by: str | None
    decided_at: datetime | None
    decision_note: str | None
    waiting_seconds: int


class ApprovalList(BaseModel):
    status: str
    approvals: list[ApprovalRead]


class ApprovalDecision(BaseModel):
    decision: Literal["approved", "rejected"]
    decided_by: str = Field(min_length=1, max_length=120)
    decision_note: str = Field(min_length=1, max_length=1000)
    base_commit_sha: str | None = Field(default=None, max_length=80)


class SecretRotationAuditCreate(BaseModel):
    sha256: str = Field(min_length=64, max_length=64)
    actor: str = Field(min_length=1, max_length=120)
    secret_ref: str = Field(default="default/platform-secrets", min_length=1, max_length=200)
    key: str = Field(min_length=1, max_length=120)
    storage: Literal["kubernetes-secret"] = "kubernetes-secret"
    purpose: str = Field(min_length=1, max_length=240)

    @field_validator("sha256")
    @classmethod
    def sha256_must_be_hex(cls, value: str) -> str:
        lowered = value.lower()
        if len(lowered) != 64 or any(char not in "0123456789abcdef" for char in lowered):
            raise ValueError("sha256 must be 64 lowercase hex characters")
        return lowered


class AuditLogRead(BaseModel):
    id: int
    at: datetime
    actor: str
    verb: str
    object: str
    after: dict[str, Any] | None


class TimelineItem(BaseModel):
    at: datetime
    step: str
    detail: Any


class IncidentDetail(BaseModel):
    id: int
    service: str
    started_at: datetime
    timeline: list[TimelineItem]
    timeline_stale: bool
    agent_log_url: str | None = None


class Counters(BaseModel):
    alerts: int
    l0_absorbed: int = 0
    l0_absorbed_is_estimate: bool = True
    ai_diagnosed: int
    auto_remediated: int
    notify_only: int
    verified: int
    verify_failed: int
    skipped_cooldown: int


class NeedYou(BaseModel):
    id: int | None
    kind: str
    service: str | None
    action: str | None
    waiting_seconds: int | None
    href: str | None


class Overview(BaseModel):
    counters_computed_at: datetime
    counters: Counters
    needs_you: list[NeedYou]
    recent: list[dict[str, Any]]


class ScorecardServiceResult(BaseModel):
    service: str
    checks: dict[str, Any]
    passed: int
    total: int


class ScorecardTotals(BaseModel):
    passed: int
    total: int
    percent: int | None


class ScorecardLatest(BaseModel):
    scorecard_id: str
    name: str
    evaluated_at: datetime | None
    services: list[ScorecardServiceResult]
    totals: ScorecardTotals
