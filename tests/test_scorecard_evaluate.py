import asyncio
from unittest.mock import patch

import httpx

from app.main import prometheus_scrape_status


class FakeResponse:
    def __init__(self, status_code: int, body: dict):
        self.status_code = status_code
        self._body = body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self._body


class FakeAsyncClient:
    next_response = FakeResponse(200, {"data": {"result": []}})

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    async def get(self, url, params=None):
        return FakeAsyncClient.next_response


def test_prometheus_scrape_status_returns_none_when_not_configured(monkeypatch) -> None:
    monkeypatch.delenv("PROM_URL", raising=False)

    result = asyncio.run(prometheus_scrape_status(["orders-api"]))

    assert result == {"orders-api": None}


def test_prometheus_scrape_status_returns_empty_dict_for_no_services(monkeypatch) -> None:
    monkeypatch.setenv("PROM_URL", "http://prometheus:9090")

    result = asyncio.run(prometheus_scrape_status([]))

    assert result == {}


def test_prometheus_scrape_status_marks_up_targets_true(monkeypatch) -> None:
    monkeypatch.setenv("PROM_URL", "http://prometheus:9090")
    FakeAsyncClient.next_response = FakeResponse(
        200,
        {
            "data": {
                "result": [
                    {"metric": {"service": "orders-api"}, "value": [0, "1"]},
                    {"metric": {"service": "payments-api"}, "value": [0, "0"]},
                ]
            }
        },
    )

    with patch("app.main.httpx.AsyncClient", FakeAsyncClient):
        result = asyncio.run(
            prometheus_scrape_status(["orders-api", "payments-api", "users-api"])
        )

    assert result == {"orders-api": True, "payments-api": False, "users-api": None}


def test_prometheus_scrape_status_prefers_up_when_service_has_multiple_targets(monkeypatch) -> None:
    monkeypatch.setenv("PROM_URL", "http://prometheus:9090")
    FakeAsyncClient.next_response = FakeResponse(
        200,
        {
            "data": {
                "result": [
                    {"metric": {"service": "orders-api"}, "value": [0, "0"]},
                    {"metric": {"service": "orders-api"}, "value": [0, "1"]},
                ]
            }
        },
    )

    with patch("app.main.httpx.AsyncClient", FakeAsyncClient):
        result = asyncio.run(prometheus_scrape_status(["orders-api"]))

    assert result == {"orders-api": True}


def test_prometheus_scrape_status_falls_back_to_none_on_http_error(monkeypatch) -> None:
    monkeypatch.setenv("PROM_URL", "http://prometheus:9090")
    FakeAsyncClient.next_response = FakeResponse(500, {})

    with patch("app.main.httpx.AsyncClient", FakeAsyncClient):
        result = asyncio.run(prometheus_scrape_status(["orders-api"]))

    assert result == {"orders-api": None}
