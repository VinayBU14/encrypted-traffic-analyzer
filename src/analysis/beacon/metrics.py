"""Beacon detection metric computations from flow timing and payload data."""

from __future__ import annotations

import math
import logging
from datetime import datetime, timezone

import numpy as np

from src.storage.models import FlowRecord

logger = logging.getLogger(__name__)


def compute_regularity_score(flow_start_times: list[float]) -> float:
    """Compute how evenly spaced flows are between 0.0 (random) and 1.0 (perfectly periodic).

    Strategy: compute inter-flow intervals, then score based on
    coefficient of variation (std/mean). Lower CoV = more regular = higher score.
    """
    if len(flow_start_times) < 2:
        return 0.0

    sorted_times = sorted(flow_start_times)
    intervals = [
        sorted_times[i + 1] - sorted_times[i]
        for i in range(len(sorted_times) - 1)
    ]

    if not intervals:
        return 0.0

    arr = np.array(intervals, dtype=float)
    mean_interval = float(np.mean(arr))

    if mean_interval <= 0.0:
        return 0.0

    std_interval = float(np.std(arr))
    cov = std_interval / mean_interval  # coefficient of variation

    # cov=0 means perfectly regular → score=1.0
    # cov>=1 means highly irregular → score=0.0
    # Linear mapping clamped to [0, 1]
    score = max(0.0, 1.0 - cov)
    logger.debug(
        "Regularity: intervals=%d mean=%.2fs std=%.2fs cov=%.3f score=%.3f",
        len(intervals), mean_interval, std_interval, cov, score,
    )
    return round(score, 4)


def compute_jitter_score(flow_start_times: list[float], jitter_cov_clean: float = 0.1, jitter_cov_max: float = 1.0) -> float:
    """Score jitter tightness — low jitter = high score = more beacon-like.

    Uses the same CoV but with configurable thresholds from config.
    cov <= jitter_cov_clean → score = 1.0 (very tight, suspicious)
    cov >= jitter_cov_max   → score = 0.0 (too random to be a beacon)
    """
    if len(flow_start_times) < 2:
        return 0.0

    sorted_times = sorted(flow_start_times)
    intervals = [
        sorted_times[i + 1] - sorted_times[i]
        for i in range(len(sorted_times) - 1)
    ]

    arr = np.array(intervals, dtype=float)
    mean_interval = float(np.mean(arr))

    if mean_interval <= 0.0:
        return 0.0

    cov = float(np.std(arr)) / mean_interval

    if cov <= jitter_cov_clean:
        score = 1.0
    elif cov >= jitter_cov_max:
        score = 0.0
    else:
        # Linear interpolation between thresholds
        score = 1.0 - (cov - jitter_cov_clean) / (jitter_cov_max - jitter_cov_clean)

    logger.debug("Jitter: cov=%.3f score=%.3f", cov, score)
    return round(max(0.0, min(1.0, score)), 4)


def compute_payload_consistency_score(flows: list[FlowRecord]) -> float:
    """Score how consistent payload sizes are across flows (0=variable, 1=identical).

    Beacons typically send the same small heartbeat payload each time.
    We use CoV of bytes_total across flows.
    """
    if len(flows) < 2:
        return 0.0

    byte_totals = [float(f.bytes_total) for f in flows if f.bytes_total > 0]
    if len(byte_totals) < 2:
        return 0.0

    arr = np.array(byte_totals, dtype=float)
    mean_bytes = float(np.mean(arr))

    if mean_bytes <= 0.0:
        return 0.0

    cov = float(np.std(arr)) / mean_bytes

    # Low CoV = consistent payloads = beacon-like
    score = max(0.0, 1.0 - cov)
    logger.debug("Payload consistency: mean=%.0f cov=%.3f score=%.3f", mean_bytes, cov, score)
    return round(score, 4)


def compute_time_independence_score(
    flow_start_times: list[float],
    anomalous_hour_start: int = 0,
    anomalous_hour_end: int = 6,
) -> float:
    """Score how time-independent the beaconing is (fires even at odd hours).

    A real beacon fires regardless of business hours — including 0am–6am.
    Returns fraction of flows that occur in the anomalous window.
    Higher fraction = more time-independent = more suspicious.
    """
    if not flow_start_times:
        return 0.0

    anomalous_count = 0
    for ts in flow_start_times:
        try:
            hour = datetime.fromtimestamp(ts, tz=timezone.utc).hour
            if anomalous_hour_start <= hour < anomalous_hour_end:
                anomalous_count += 1
        except Exception:
            continue

    score = anomalous_count / len(flow_start_times)
    logger.debug(
        "Time independence: %d/%d flows in hours %d-%d → score=%.3f",
        anomalous_count, len(flow_start_times),
        anomalous_hour_start, anomalous_hour_end, score,
    )
    return round(score, 4)
