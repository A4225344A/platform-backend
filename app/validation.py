from typing import Any

from .errors import AppError

ALLOWED_LOG_SINKS = {"cloudwatch", "loki", "file"}


def validate_action(kind: str, action: str | None, payload: dict[str, Any] | None = None) -> None:
    if kind != "policy_change":
        raise AppError(f"不支援的提議種類: {kind}")
    if action != "log_sink":
        raise AppError(f"不支援的 policy_change action: {action}")
    sink = (payload or {}).get("sink_type")
    if sink not in ALLOWED_LOG_SINKS:
        raise AppError(
            f"不支援的日誌目的地: {sink}。目前只支援 {', '.join(sorted(ALLOWED_LOG_SINKS))}。"
        )
