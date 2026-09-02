from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


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
