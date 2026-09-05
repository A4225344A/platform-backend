import asyncio
from datetime import datetime, timezone

from app.main import accuracy_data, overview_data, search_data


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


def test_search_data_returns_empty_for_short_query_without_touching_db() -> None:
    connection = FakeConnection([])  # no cursors queued: any execute() would raise IndexError
    result = asyncio.run(search_data("a", FakePool(connection)))

    assert result == {"query": "a", "services": [], "incidents": []}
    assert connection.calls == []


def test_search_data_matches_services_and_incidents() -> None:
    started_at = datetime(2026, 9, 3, 2, 0, tzinfo=timezone.utc)
    connection = FakeConnection(
        [
            FakeCursor(
                rows=[
                    {
                        "service": "orders-api",
                        "display_name": "Orders API",
                        "owner_team": "platform-core",
                        "owner_email": "core@example.com",
                    }
                ]
            ),
            FakeCursor(
                rows=[
                    {
                        "id": 41,
                        "service": "orders-api",
                        "alertname": "PodCrashLooping",
                        "status": "closed",
                        "started_at": started_at,
                    }
                ]
            ),
        ]
    )

    result = asyncio.run(search_data("orders", FakePool(connection)))

    assert result["query"] == "orders"
    assert result["services"][0]["service"] == "orders-api"
    assert result["incidents"][0]["id"] == 41
    # ILIKE pattern actually carries the search term, not the raw literal query.
    services_query, services_params = connection.calls[0]
    assert "ILIKE" in services_query
    assert services_params == ("%orders%", "%orders%", "%orders%", "%orders%", 8)


def test_overview_data_defaults_window_to_24_hours(monkeypatch) -> None:
    monkeypatch.delenv("PROM_URL", raising=False)
    connection = FakeConnection(
        [
            FakeCursor(
                row={
                    "alerts": 0,
                    "ai_diagnosed": 0,
                    "auto_remediated": 0,
                    "notify_only": 0,
                    "verified": 0,
                    "verify_failed": 0,
                    "skipped_cooldown": 0,
                }
            ),
            FakeCursor(rows=[]),
            FakeCursor(rows=[]),
            FakeCursor(rows=[]),
            FakeCursor(rows=[]),
        ]
    )

    result = asyncio.run(overview_data(FakePool(connection)))

    assert result["window_hours"] == 24
    counters_params = connection.calls[0][1]
    assert counters_params == (24, 24)


def test_overview_data_respects_custom_window_hours(monkeypatch) -> None:
    monkeypatch.delenv("PROM_URL", raising=False)
    connection = FakeConnection(
        [
            FakeCursor(
                row={
                    "alerts": 0,
                    "ai_diagnosed": 0,
                    "auto_remediated": 0,
                    "notify_only": 0,
                    "verified": 0,
                    "verify_failed": 0,
                    "skipped_cooldown": 0,
                }
            ),
            FakeCursor(rows=[]),
            FakeCursor(rows=[]),
            FakeCursor(rows=[]),
            FakeCursor(rows=[]),
        ]
    )

    result = asyncio.run(overview_data(FakePool(connection), window_hours=6))

    assert result["window_hours"] == 6
    counters_params = connection.calls[0][1]
    assert counters_params == (6, 6)
    catalog_gaps_params = connection.calls[3][1]
    assert catalog_gaps_params == (6,)


def test_overview_data_needs_you_carries_owner_from_service_catalog_join(monkeypatch) -> None:
    monkeypatch.delenv("PROM_URL", raising=False)
    connection = FakeConnection(
        [
            FakeCursor(
                row={
                    "alerts": 0,
                    "ai_diagnosed": 0,
                    "auto_remediated": 0,
                    "notify_only": 0,
                    "verified": 0,
                    "verify_failed": 0,
                    "skipped_cooldown": 0,
                }
            ),
            FakeCursor(
                rows=[
                    {
                        "id": 41,
                        "kind": "remediation",
                        "service": "payments-api",
                        "action": "rollback",
                        "waiting_seconds": 720,
                        "href": "/incidents/922",
                        "owner_team": "payments-core",
                        "owner_email": "payments-oncall@example.com",
                    }
                ]
            ),
            FakeCursor(
                rows=[
                    {
                        "id": 922,
                        "service": "auth-api",
                        "status": "running",
                        "alertname": "PodCrashLooping",
                        "waiting_seconds": 420,
                        "owner_team": "identity-team",
                        "owner_email": "identity-oncall@example.com",
                    }
                ]
            ),
            FakeCursor(rows=[]),
            FakeCursor(rows=[]),
        ]
    )

    result = asyncio.run(overview_data(FakePool(connection)))

    needs_by_kind = {need.kind: need for need in result["needs_you"]}
    assert needs_by_kind["remediation"].owner_team == "payments-core"
    assert needs_by_kind["remediation"].owner_email == "payments-oncall@example.com"
    assert needs_by_kind["timeline_stale"].owner_team == "identity-team"
    assert needs_by_kind["timeline_stale"].owner_email == "identity-oncall@example.com"


def test_accuracy_data_computes_remediation_rate() -> None:
    connection = FakeConnection(
        [
            FakeCursor(
                rows=[
                    {"outcome": "verified", "n": 3},
                    {"outcome": "failed", "n": 1},
                    {"outcome": "notify_only", "n": 5},
                ]
            ),
        ]
    )

    result = asyncio.run(accuracy_data("orders-api", FakePool(connection)))

    assert result == {
        "service": "orders-api",
        "verified": 3,
        "failed": 1,
        "notify_only": 5,
        "remediation_rate": 0.75,
    }
    assert connection.calls[0][1] == ("orders-api",)


def test_accuracy_data_returns_none_rate_without_remediation_attempts() -> None:
    connection = FakeConnection([FakeCursor(rows=[{"outcome": "notify_only", "n": 2}])])

    result = asyncio.run(accuracy_data("payments-api", FakePool(connection)))

    assert result["remediation_rate"] is None
    assert result["verified"] == 0
    assert result["failed"] == 0
