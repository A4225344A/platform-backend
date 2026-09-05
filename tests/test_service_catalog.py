import asyncio

from app.main import service_catalog_data


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


def test_service_catalog_data_substitutes_log_url_template_and_drops_template() -> None:
    connection = FakeConnection(
        [
            FakeCursor(
                rows=[
                    {
                        "service": "orders-api",
                        "display_name": "Orders API",
                        "owner_team": "platform-core",
                        "owner_email": "core@example.com",
                        "escalation_email": "core-escalate@example.com",
                        "tier": 1,
                        "auto_remediate": True,
                        "runbook_url": "https://runbooks.example.com/orders-api",
                        "last_deploy_at": None,
                        "log_query_url_template": "https://logs.example.com/search?service=%s",
                        "depends_on": ["payments-api"],
                    }
                ]
            )
        ]
    )

    result = asyncio.run(service_catalog_data(FakePool(connection)))

    entry = result["services"][0]
    assert entry["log_url"] == "https://logs.example.com/search?service=orders-api"
    assert "log_query_url_template" not in entry
    assert entry["owner_team"] == "platform-core"


def test_service_catalog_data_handles_missing_log_url_template() -> None:
    connection = FakeConnection(
        [
            FakeCursor(
                rows=[
                    {
                        "service": "payments-api",
                        "display_name": None,
                        "owner_team": None,
                        "owner_email": None,
                        "escalation_email": None,
                        "tier": None,
                        "auto_remediate": None,
                        "runbook_url": None,
                        "last_deploy_at": None,
                        "log_query_url_template": None,
                        "depends_on": None,
                    }
                ]
            )
        ]
    )

    result = asyncio.run(service_catalog_data(FakePool(connection)))

    assert result["services"][0]["log_url"] is None


def test_service_catalog_data_returns_empty_list_when_catalog_is_empty() -> None:
    connection = FakeConnection([FakeCursor(rows=[])])

    result = asyncio.run(service_catalog_data(FakePool(connection)))

    assert result == {"services": []}
