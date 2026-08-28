import pytest

from app.errors import AppError
from app.validation import validate_action


def test_log_sink_accepts_supported_sink() -> None:
    validate_action("policy_change", "log_sink", {"sink_type": "loki"})


@pytest.mark.parametrize("kind, action", [("remediation", "rollback"), ("policy_change", "rollback")])
def test_rejects_unsupported_workflow(kind: str, action: str) -> None:
    with pytest.raises(AppError):
        validate_action(kind, action, {"sink_type": "loki"})


def test_rejects_unknown_sink() -> None:
    with pytest.raises(AppError, match="不支援的日誌目的地"):
        validate_action("policy_change", "log_sink", {"sink_type": "unknown"})
