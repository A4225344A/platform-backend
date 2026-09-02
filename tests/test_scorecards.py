import asyncio
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from app.main import latest_scorecard_data


class FakeCursor:
    def __init__(self, *, row=None, rows=None):
        self.row = row
        self.rows = rows or []

    async def fetchone(self):
        return self.row

    async def fetchall(self):
        return self.rows


class FakeConnection:
    def __init__(self, cursors):
        self.cursors = list(cursors)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    async def execute(self, _query, _params=()):
        return self.cursors.pop(0)


class FakePool:
    def __init__(self, cursors):
        self._connection = FakeConnection(cursors)

    def connection(self):
        return self._connection


def test_latest_scorecard_returns_latest_batch_totals() -> None:
    evaluated_at = datetime(2026, 9, 3, 2, 0, tzinfo=timezone.utc)
    result = asyncio.run(
        latest_scorecard_data(
            "selfheal-readiness",
            FakePool(
                [
                    FakeCursor(row={"id": "selfheal-readiness", "name": "Self-heal readiness"}),
                    FakeCursor(
                        rows=[
                            {
                                "service": "inventory-api",
                                "evaluated_at": evaluated_at,
                                "checks": {"catalog_entry": True, "metrics_scraped": None},
                                "passed": 1,
                                "total": 2,
                            },
                            {
                                "service": "orders-api",
                                "evaluated_at": evaluated_at,
                                "checks": {"catalog_entry": True, "metrics_scraped": True},
                                "passed": 2,
                                "total": 2,
                            },
                        ]
                    ),
                ]
            ),
        )
    )

    assert result == {
        "scorecard_id": "selfheal-readiness",
        "name": "Self-heal readiness",
        "evaluated_at": evaluated_at,
        "services": [
            {
                "service": "inventory-api",
                "checks": {"catalog_entry": True, "metrics_scraped": None},
                "passed": 1,
                "total": 2,
            },
            {
                "service": "orders-api",
                "checks": {"catalog_entry": True, "metrics_scraped": True},
                "passed": 2,
                "total": 2,
            },
        ],
        "totals": {"passed": 3, "total": 4, "percent": 75},
    }


def test_latest_scorecard_returns_empty_state_before_first_evaluation() -> None:
    result = asyncio.run(
        latest_scorecard_data(
            "selfheal-readiness",
            FakePool(
                [
                    FakeCursor(row={"id": "selfheal-readiness", "name": "Self-heal readiness"}),
                    FakeCursor(rows=[]),
                ]
            ),
        )
    )

    assert result["evaluated_at"] is None
    assert result["services"] == []
    assert result["totals"] == {"passed": 0, "total": 0, "percent": None}


def test_latest_scorecard_404s_for_unknown_scorecard() -> None:
    with pytest.raises(HTTPException) as raised:
        asyncio.run(
            latest_scorecard_data(
                "missing",
                FakePool([FakeCursor(row=None)]),
            )
        )

    assert raised.value.status_code == 404
