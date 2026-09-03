import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.main import (
    approval_list_data,
    approval_execution_plan_data,
    audit_log_list_data,
    build_approval_execution_plan,
    decide_approval_data,
    link_approval_pr_data,
    record_secret_rotation_audit_data,
    require_decision_token,
)
from app.models import ApprovalDecision, ApprovalPrLink, SecretRotationAuditCreate


class FakeCursor:
    def __init__(self, row=None, rows=None):
        self.row = row
        self.rows = rows or []

    async def fetchone(self):
        return self.row

    async def fetchall(self):
        return self.rows


class FakeConnection:
    def __init__(self, cursors):
        self.cursors = list(cursors)
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    def transaction(self):
        return self

    async def execute(self, query, params=()):
        self.calls.append((query, params))
        return self.cursors.pop(0)


class FakePool:
    def __init__(self, connection):
        self._connection = connection

    def connection(self):
        return self._connection


def test_approval_list_returns_pending_read_model() -> None:
    requested_at = datetime(2026, 9, 3, 2, 0, tzinfo=timezone.utc)
    expires_at = requested_at + timedelta(hours=24)
    row = {
        "id": 1,
        "kind": "policy_change",
        "service": None,
        "action": "log_sink",
        "payload": {"sink_type": "cloudwatch"},
        "incident_id": None,
        "trace_id": "trace-1",
        "status": "pending",
        "pr_number": None,
        "pr_url": None,
        "base_commit_sha": None,
        "requested_by": "lab-ui",
        "requested_at": requested_at,
        "expires_at": expires_at,
        "decided_by": None,
        "decided_at": None,
        "decision_note": None,
        "waiting_seconds": 42,
    }
    connection = FakeConnection([FakeCursor(rows=[row])])

    result = asyncio.run(approval_list_data("pending", FakePool(connection), limit=25))

    assert result == {"status": "pending", "approvals": [row]}
    assert connection.calls[0][1] == ("pending", "pending", "pending", 25)


def test_approval_list_rejects_unsupported_status() -> None:
    with pytest.raises(HTTPException) as raised:
        asyncio.run(approval_list_data("deleted", FakePool(FakeConnection([FakeCursor()]))))

    assert raised.value.status_code == 400


def test_decide_approval_updates_status_and_writes_audit_log() -> None:
    requested_at = datetime(2026, 9, 3, 2, 0, tzinfo=timezone.utc)
    expires_at = requested_at + timedelta(hours=24)
    before = {
        "id": 1,
        "kind": "policy_change",
        "service": None,
        "action": "log_sink",
        "payload": {"sink_type": "cloudwatch"},
        "incident_id": None,
        "trace_id": "trace-1",
        "status": "pending",
        "pr_number": None,
        "pr_url": None,
        "base_commit_sha": None,
        "requested_by": "lab-ui",
        "requested_at": requested_at,
        "expires_at": expires_at,
        "decided_by": None,
        "decided_at": None,
        "decision_note": None,
        "waiting_seconds": 42,
    }
    after = {
        **before,
        "status": "approved",
        "base_commit_sha": "abc123",
        "decided_by": "operator",
        "decided_at": requested_at + timedelta(minutes=10),
        "decision_note": "reviewed",
        "waiting_seconds": 43,
    }
    connection = FakeConnection(
        [
            FakeCursor(row=before),
            FakeCursor(row=after),
            FakeCursor(),
        ]
    )

    result = asyncio.run(
        decide_approval_data(
            1,
            ApprovalDecision(decision="approved", decided_by="operator", decision_note="reviewed", base_commit_sha="abc123"),
            FakePool(connection),
        )
    )

    assert result["status"] == "approved"
    assert result["decided_by"] == "operator"
    assert connection.calls[0][1] == (1,)
    assert connection.calls[1][1] == ("approved", "operator", "reviewed", "abc123", 1)
    assert connection.calls[2][1][0:3] == ("operator", "approval.approve", "1")


def test_decide_approval_rejects_terminal_state() -> None:
    requested_at = datetime(2026, 9, 3, 2, 0, tzinfo=timezone.utc)
    connection = FakeConnection(
        [
            FakeCursor(
                row={
                    "id": 1,
                    "status": "approved",
                    "expires_at": requested_at + timedelta(hours=24),
                }
            )
        ]
    )

    with pytest.raises(HTTPException) as raised:
        asyncio.run(
            decide_approval_data(
                1,
                ApprovalDecision(decision="rejected", decided_by="operator", decision_note="no"),
                FakePool(connection),
            )
        )

    assert raised.value.status_code == 409


def test_link_approval_pr_updates_row_and_writes_audit_log() -> None:
    requested_at = datetime(2026, 9, 3, 2, 0, tzinfo=timezone.utc)
    expires_at = requested_at + timedelta(hours=24)
    before = {
        "id": 3,
        "kind": "policy_change",
        "service": None,
        "action": "log_sink",
        "payload": {"sink_type": "file"},
        "incident_id": None,
        "trace_id": "trace-3",
        "status": "approved",
        "pr_number": None,
        "pr_url": None,
        "base_commit_sha": None,
        "requested_by": "lab-ui",
        "requested_at": requested_at,
        "expires_at": expires_at,
        "decided_by": "operator",
        "decided_at": requested_at + timedelta(minutes=10),
        "decision_note": "reviewed",
        "waiting_seconds": 43,
    }
    after = {**before, "pr_number": 42, "pr_url": "https://github.com/A4225344A/platform-gitops/pull/42"}
    connection = FakeConnection([FakeCursor(row=before), FakeCursor(row=after), FakeCursor()])

    result = asyncio.run(
        link_approval_pr_data(
            3,
            ApprovalPrLink(pr_number=42, pr_url="https://github.com/A4225344A/platform-gitops/pull/42", linked_by="operator"),
            FakePool(connection),
        )
    )

    assert result["pr_number"] == 42
    assert result["pr_url"] == "https://github.com/A4225344A/platform-gitops/pull/42"
    assert connection.calls[0][1] == (3,)
    assert connection.calls[1][1] == (42, "https://github.com/A4225344A/platform-gitops/pull/42", 3)
    assert connection.calls[2][1][0:3] == ("operator", "approval.link_pr", "3")


def test_link_approval_pr_rejects_when_not_yet_approved() -> None:
    requested_at = datetime(2026, 9, 3, 2, 0, tzinfo=timezone.utc)
    connection = FakeConnection(
        [
            FakeCursor(
                row={
                    "id": 3,
                    "status": "pending",
                    "expires_at": requested_at + timedelta(hours=24),
                }
            )
        ]
    )

    with pytest.raises(HTTPException) as raised:
        asyncio.run(
            link_approval_pr_data(
                3,
                ApprovalPrLink(pr_number=42, pr_url="https://github.com/A4225344A/platform-gitops/pull/42", linked_by="operator"),
                FakePool(connection),
            )
        )

    assert raised.value.status_code == 409


def test_link_approval_pr_returns_404_when_missing() -> None:
    connection = FakeConnection([FakeCursor(row=None)])

    with pytest.raises(HTTPException) as raised:
        asyncio.run(
            link_approval_pr_data(
                99,
                ApprovalPrLink(pr_number=1, pr_url="https://github.com/A4225344A/platform-gitops/pull/1", linked_by="operator"),
                FakePool(connection),
            )
        )

    assert raised.value.status_code == 404


def test_link_approval_pr_rejects_url_outside_gitops_repo() -> None:
    with pytest.raises(ValidationError):
        ApprovalPrLink(pr_number=1, pr_url="https://github.com/someone-else/other-repo/pull/1", linked_by="operator")


def test_approval_execution_plan_is_read_only_and_bounded() -> None:
    row = {
        "id": 7,
        "kind": "policy_change",
        "service": None,
        "action": "log_sink",
        "payload": {
            "sink_type": "cloudwatch",
            "connection_params": {"region": "ap-northeast-1", "log_group": "/w3/ai-agent"},
        },
        "status": "pending",
    }

    plan = build_approval_execution_plan(row)

    assert plan["approval_id"] == 7
    assert plan["requires_human_decision"] is True
    assert plan["mutation_enabled"] is False
    assert plan["retry_limit"] == 2
    assert "rollback" in plan["rollback"].lower()
    assert [step["order"] for step in plan["steps"]] == [1, 2, 3, 4]


def test_approval_execution_plan_fetches_approval_row() -> None:
    row = {
        "id": 8,
        "kind": "policy_change",
        "service": None,
        "action": "log_sink",
        "payload": {"sink_type": "file", "connection_params": {"path": "/var/log/otel/ai-agent.log"}},
        "status": "approved",
    }
    connection = FakeConnection([FakeCursor(row=row)])

    plan = asyncio.run(approval_execution_plan_data(8, FakePool(connection)))

    assert plan["approval_id"] == 8
    assert plan["status"] == "approved"
    assert plan["mutation_enabled"] is False
    assert connection.calls[0][1] == (8,)


def test_approval_execution_plan_returns_404_when_missing() -> None:
    connection = FakeConnection([FakeCursor(row=None)])

    with pytest.raises(HTTPException) as raised:
        asyncio.run(approval_execution_plan_data(99, FakePool(connection)))

    assert raised.value.status_code == 404


def test_decision_token_requires_dedicated_secret(monkeypatch) -> None:
    monkeypatch.delenv("ENGOPS_DECISION_TOKEN", raising=False)
    with pytest.raises(HTTPException) as missing:
        require_decision_token("Bearer token")
    assert missing.value.status_code == 503

    monkeypatch.setenv("ENGOPS_DECISION_TOKEN", "decision-secret")
    with pytest.raises(HTTPException) as wrong:
        require_decision_token("Bearer wrong")
    assert wrong.value.status_code == 401

    require_decision_token("Bearer decision-secret")


def test_secret_rotation_audit_records_only_sha256_metadata() -> None:
    at = datetime(2026, 9, 3, 3, 0, tzinfo=timezone.utc)
    sha = "A" * 64
    row = {
        "id": 10,
        "at": at,
        "actor": "operator",
        "verb": "secret.rotate",
        "object": "default/platform-secrets/engops-decision-token",
        "after": {
            "sha256": sha.lower(),
            "secret_ref": "default/platform-secrets",
            "key": "engops-decision-token",
            "storage": "kubernetes-secret",
            "purpose": "engops approval decision endpoint",
        },
    }
    connection = FakeConnection([FakeCursor(row=row)])

    result = asyncio.run(
        record_secret_rotation_audit_data(
            SecretRotationAuditCreate(
                sha256=sha,
                actor="operator",
                key="engops-decision-token",
                purpose="engops approval decision endpoint",
            ),
            FakePool(connection),
        )
    )

    assert result == row
    assert connection.calls[0][1][0:3] == (
        "operator",
        "secret.rotate",
        "default/platform-secrets/engops-decision-token",
    )
    after = connection.calls[0][1][3].obj
    assert after == row["after"]
    assert "token" not in after


def test_secret_rotation_audit_rejects_non_hash_input() -> None:
    with pytest.raises(ValidationError):
        SecretRotationAuditCreate(
            sha256="not-a-token-or-hash",
            actor="operator",
            key="engops-decision-token",
            purpose="engops approval decision endpoint",
        )


def test_audit_log_list_returns_recent_rows_with_optional_verb_filter() -> None:
    at = datetime(2026, 9, 3, 4, 0, tzinfo=timezone.utc)
    row = {
        "id": 12,
        "at": at,
        "actor": "operator",
        "verb": "secret.rotate",
        "object": "default/platform-secrets/engops-decision-token",
        "before": None,
        "after": {"sha256": "a" * 64},
        "trace_id": None,
    }
    connection = FakeConnection([FakeCursor(rows=[row])])

    result = asyncio.run(audit_log_list_data(FakePool(connection), limit=10, verb="secret.rotate"))

    assert result == {"audit_log": [row]}
    assert connection.calls[0][1] == ("secret.rotate", "secret.rotate", 10)
