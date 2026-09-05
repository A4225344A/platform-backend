import asyncio
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from app.main import incident_detail_data


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

    async def execute(self, query, params=()):
        self.calls.append((query, params))
        return self.cursors.pop(0)


class FakePool:
    def __init__(self, connection):
        self._connection = connection

    def connection(self):
        return self._connection


def test_incident_detail_data_includes_owner_from_service_catalog_join() -> None:
    started_at = datetime(2026, 8, 28, 0, 0, tzinfo=timezone.utc)
    connection = FakeConnection(
        [
            FakeCursor(
                row={
                    "id": 922,
                    "service": "auth-api",
                    "started_at": started_at,
                    "latest_at": started_at,
                    "status": "closed",
                    "log_query_url_template": None,
                    "owner_team": "identity-team",
                    "owner_email": "identity-oncall@example.com",
                    "escalation_email": "identity-escalate@example.com",
                }
            ),
            FakeCursor(rows=[]),
        ]
    )

    result = asyncio.run(incident_detail_data(922, FakePool(connection)))

    assert result["owner_team"] == "identity-team"
    assert result["owner_email"] == "identity-oncall@example.com"
    assert result["escalation_email"] == "identity-escalate@example.com"


def test_incident_detail_data_owner_is_none_when_service_not_in_catalog() -> None:
    started_at = datetime(2026, 8, 28, 0, 0, tzinfo=timezone.utc)
    connection = FakeConnection(
        [
            FakeCursor(
                row={
                    "id": 41,
                    "service": "billing-api",
                    "started_at": started_at,
                    "latest_at": started_at,
                    "status": "closed",
                    "log_query_url_template": None,
                    "owner_team": None,
                    "owner_email": None,
                    "escalation_email": None,
                }
            ),
            FakeCursor(rows=[]),
        ]
    )

    result = asyncio.run(incident_detail_data(41, FakePool(connection)))

    assert result["owner_team"] is None
    assert result["owner_email"] is None
    assert result["escalation_email"] is None


def test_incident_detail_data_raises_404_when_incident_missing() -> None:
    connection = FakeConnection([FakeCursor(row=None)])

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(incident_detail_data(9999, FakePool(connection)))

    assert excinfo.value.status_code == 404
