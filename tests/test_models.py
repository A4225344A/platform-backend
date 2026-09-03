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


def test_approval_requested_by_defaults_to_lab_ui_but_can_be_overridden() -> None:
    default_approval = ApprovalCreate(
        kind="policy_change",
        action="log_sink",
        payload={"sink_type": "file"},
    )
    assert default_approval.requested_by == "lab-ui"

    named_approval = ApprovalCreate(
        kind="policy_change",
        action="log_sink",
        payload={"sink_type": "file"},
        requested_by="operator",
    )
    assert named_approval.requested_by == "operator"
