from app.main import api_boundary_authorized


def test_api_boundary_allows_when_not_configured(monkeypatch) -> None:
    monkeypatch.delenv("ENGOPS_API_ORIGIN_VERIFY_TOKEN", raising=False)
    assert api_boundary_authorized(None, None) is True


def test_api_boundary_accepts_cloudfront_origin_header(monkeypatch) -> None:
    monkeypatch.setenv("ENGOPS_API_ORIGIN_VERIFY_TOKEN", "origin-secret")
    monkeypatch.setenv("ENGOPS_API_TOKEN", "machine-secret")
    assert api_boundary_authorized("origin-secret", None) is True


def test_api_boundary_accepts_machine_token_for_internal_jobs(monkeypatch) -> None:
    monkeypatch.setenv("ENGOPS_API_ORIGIN_VERIFY_TOKEN", "origin-secret")
    monkeypatch.setenv("ENGOPS_API_TOKEN", "machine-secret")
    assert api_boundary_authorized(None, "Bearer machine-secret") is True


def test_api_boundary_rejects_direct_origin_without_trust(monkeypatch) -> None:
    monkeypatch.setenv("ENGOPS_API_ORIGIN_VERIFY_TOKEN", "origin-secret")
    monkeypatch.setenv("ENGOPS_API_TOKEN", "machine-secret")
    assert api_boundary_authorized(None, None) is False
    assert api_boundary_authorized("wrong", "Bearer wrong") is False
