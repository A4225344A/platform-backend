import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.main import (
    approval_list_data,
    audit_log_list_data,
    decide_approval_data,
    record_secret_rotation_audit_data,
    require_decision_token,
)
from app.models import ApprovalDecision, SecretRotationAuditCreate


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
