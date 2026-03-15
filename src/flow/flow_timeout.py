
"""Pure timeout and finalization utility functions for flow lifecycle decisions."""

from __future__ import annotations

from pathlib import Path

import yaml

from src.storage.models import FlowRecord

_CONFIG_PATH = Path(__file__).resolve().parents[2] / "configs" / "default.yaml"
_CONFIG = yaml.safe_load(_CONFIG_PATH.read_text(encoding="utf-8")) or {}
_FLOW_TIMEOUT_SECONDS: float = float(_CONFIG.get("network", {}).get("flow_timeout_seconds", 60))


def is_timed_out(flow: FlowRecord, current_time: float) -> bool:
    """Return True when a flow exceeded the configured inactivity timeout."""
    last_activity = flow.end_time if flow.end_time is not None else flow.start_time
    return (current_time - last_activity) > _FLOW_TIMEOUT_SECONDS


def is_tcp_closed(tcp_flags_counts: dict[str, int]) -> bool:
    """Return True when FIN or RST counters indicate TCP teardown."""
    return int(tcp_flags_counts.get("FIN", 0)) > 0 or int(tcp_flags_counts.get("RST", 0)) > 0


def compute_duration_ms(start_time: float, end_time: float) -> float:
    """Compute flow duration in milliseconds, clamped to 0.0 for negative intervals."""
    if end_time < start_time:
        return 0.0
    return (end_time - start_time) * 1000.0


def should_finalize(flow: FlowRecord, current_time: float) -> tuple[bool, str]:
    """Return finalization decision and reason using TCP-close and timeout checks."""
    if is_tcp_closed(flow.tcp_flags):
        return True, "TCP_CLOSED"
    if is_timed_out(flow, current_time):
        return True, "TIMEOUT"
    return False, ""
