import asyncio
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.main import ask_incident_data


class FakeResponse:
    def __init__(self, status_code: int, body: dict):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


class FakeAsyncClient:
    next_response = FakeResponse(200, {"answer": "ok", "model": "judge", "cost_usd": None})
    last_call: tuple | None = None

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    async def get(self, url, params=None, headers=None):
        FakeAsyncClient.last_call = (url, params, headers)
        return FakeAsyncClient.next_response


def test_ask_incident_data_requires_ask_token(monkeypatch) -> None:
    monkeypatch.delenv("ASK_TOKEN", raising=False)

    with pytest.raises(HTTPException) as raised:
        asyncio.run(ask_incident_data(1, "why did it restart?"))

    assert raised.value.status_code == 503


def test_ask_incident_data_forwards_question_with_bearer_token(monkeypatch) -> None:
    monkeypatch.setenv("ASK_TOKEN", "secret-token")
    FakeAsyncClient.next_response = FakeResponse(
        200, {"answer": "crash loop detected, restarted", "model": "judge", "cost_usd": 0.0001}
    )

    with patch("app.main.httpx.AsyncClient", FakeAsyncClient):
        result = asyncio.run(ask_incident_data(7, "why did it restart?"))

    assert result == {"answer": "crash loop detected, restarted", "model": "judge", "cost_usd": 0.0001}
    url, params, headers = FakeAsyncClient.last_call
    assert url.endswith("/incidents/7/ask")
    assert params == {"question": "why did it restart?"}
    assert headers["Authorization"] == "Bearer secret-token"


def test_ask_incident_data_maps_404_to_incident_not_found(monkeypatch) -> None:
    monkeypatch.setenv("ASK_TOKEN", "secret-token")
    FakeAsyncClient.next_response = FakeResponse(404, {})

    with patch("app.main.httpx.AsyncClient", FakeAsyncClient):
        with pytest.raises(HTTPException) as raised:
            asyncio.run(ask_incident_data(999, "why?"))

    assert raised.value.status_code == 404


def test_ask_incident_data_maps_other_errors_to_502(monkeypatch) -> None:
    monkeypatch.setenv("ASK_TOKEN", "secret-token")
    FakeAsyncClient.next_response = FakeResponse(500, {})

    with patch("app.main.httpx.AsyncClient", FakeAsyncClient):
        with pytest.raises(HTTPException) as raised:
            asyncio.run(ask_incident_data(1, "why?"))

    assert raised.value.status_code == 502
