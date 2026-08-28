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
