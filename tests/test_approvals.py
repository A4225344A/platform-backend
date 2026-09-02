import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from app.main import approval_list_data


class FakeCursor:
    def __init__(self, rows=None):
        self.rows = rows or []

    async def fetchall(self):
        return self.rows


class FakeConnection:
    def __init__(self, cursor):
        self.cursor = cursor
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    async def execute(self, query, params=()):
        self.calls.append((query, params))
        return self.cursor


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
    connection = FakeConnection(FakeCursor(rows=[row]))

    result = asyncio.run(approval_list_data("pending", FakePool(connection), limit=25))

    assert result == {"status": "pending", "approvals": [row]}
    assert connection.calls[0][1] == ("pending", "pending", "pending", 25)


def test_approval_list_rejects_unsupported_status() -> None:
    with pytest.raises(HTTPException) as raised:
        asyncio.run(approval_list_data("deleted", FakePool(FakeConnection(FakeCursor()))))

    assert raised.value.status_code == 400
