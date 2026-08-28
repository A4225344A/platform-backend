import pytest
from pydantic import ValidationError

from app.models import ApprovalCreate


def test_approval_payload_is_strongly_typed() -> None:
    approval = ApprovalCreate(
        kind="policy_change",
        action="log_sink",
        payload={"sink_type": "cloudwatch", "connection_params": {"region": "local"}},
    )
    assert approval.payload.sink_type == "cloudwatch"


def test_approval_rejects_invalid_action() -> None:
    with pytest.raises(ValidationError):
        ApprovalCreate(
            kind="policy_change",
            action="rollback",
            payload={"sink_type": "file"},
        )
