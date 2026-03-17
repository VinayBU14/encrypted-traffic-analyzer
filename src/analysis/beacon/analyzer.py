"""Beacon detection analyzer — detects periodic C2 communication patterns."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from src.analysis.beacon.metrics import (
    compute_jitter_score,
    compute_payload_consistency_score,
    compute_regularity_score,
    compute_time_independence_score,
)
from src.storage.models import FlowRecord

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_CONFIG_PATH = _PROJECT_ROOT / "configs" / "default.yaml"
_CONFIG = yaml.safe_load(_CONFIG_PATH.read_text(encoding="utf-8")) or {}
_BEACON_CFG = _CONFIG.get("beacon", {})
_WEIGHTS = _BEACON_CFG.get("weights", {})
_THRESHOLDS = _BEACON_CFG.get("thresholds", {})

MIN_FLOWS: int = int(_BEACON_CFG.get("min_flows_required", 5))
ANOMALOUS_HOUR_START: int = int(_BEACON_CFG.get("anomalous_hour_start", 0))
ANOMALOUS_HOUR_END: int = int(_BEACON_CFG.get("anomalous_hour_end", 6))

W_REGULARITY: float = float(_WEIGHTS.get("regularity", 0.40))
W_JITTER: float = float(_WEIGHTS.get("jitter", 0.25))
W_PAYLOAD: float = float(_WEIGHTS.get("payload", 0.20))
W_TIME: float = float(_WEIGHTS.get("time_independence", 0.15))

JITTER_COV_CLEAN: float = float(_THRESHOLDS.get("jitter_cov_clean", 0.1))
JITTER_COV_MAX: float = float(_THRESHOLDS.get("jitter_cov_max", 1.0))


class BeaconAnalyzer:
    """Detect beaconing behavior from repeated flows between the same src/dst pair."""

    def __init__(self) -> None:
        """Initialize beacon analyzer with config-driven weights and thresholds."""
        logger.info(
            "BeaconAnalyzer initialized — min_flows=%d weights: reg=%.2f jitter=%.2f payload=%.2f time=%.2f",
            MIN_FLOWS, W_REGULARITY, W_JITTER, W_PAYLOAD, W_TIME,
        )

    def score(self, flows: list[FlowRecord]) -> dict[str, object]:
        """Score a list of flows between the same src/dst pair for beacon behavior.

        Args:
            flows: All FlowRecords for a single src_ip -> dst_ip pair,
                   ordered by start_time ascending.

        Returns a dict with:
            beacon_score (float): 0.0 to 1.0
            regularity_score (float): individual metric
            jitter_score (float): individual metric
            payload_score (float): individual metric
            time_score (float): individual metric
            flow_count (int): number of flows analyzed
            finding (str | None): human-readable finding if suspicious
            mean_interval_seconds (float): average gap between flows
        """
        if not flows or len(flows) < MIN_FLOWS:
            return {
                "beacon_score": 0.0,
                "regularity_score": 0.0,
                "jitter_score": 0.0,
                "payload_score": 0.0,
                "time_score": 0.0,
                "flow_count": len(flows) if flows else 0,
                "finding": None,
                "mean_interval_seconds": 0.0,
            }

        start_times = [float(f.start_time) for f in flows]

        regularity = compute_regularity_score(start_times)
        jitter = compute_jitter_score(start_times, JITTER_COV_CLEAN, JITTER_COV_MAX)
        payload = compute_payload_consistency_score(flows)
        time_ind = compute_time_independence_score(
            start_times, ANOMALOUS_HOUR_START, ANOMALOUS_HOUR_END
        )

        beacon_score = (
            W_REGULARITY * regularity
            + W_JITTER * jitter
            + W_PAYLOAD * payload
            + W_TIME * time_ind
        )
        beacon_score = round(min(1.0, max(0.0, beacon_score)), 4)

        # Mean interval between flows
        sorted_times = sorted(start_times)
        intervals = [
            sorted_times[i + 1] - sorted_times[i]
            for i in range(len(sorted_times) - 1)
        ]
        mean_interval = sum(intervals) / len(intervals) if intervals else 0.0

        # Build finding string if score is notable
        finding = None
        if beacon_score >= 0.60:
            src = flows[0].src_ip
            dst = flows[0].dst_ip
            finding = (
                f"Possible beacon: {src} → {dst} "
                f"({len(flows)} flows, interval ~{mean_interval:.0f}s, score={beacon_score:.2f})"
            )
            logger.warning("Beacon detected: %s", finding)
        elif beacon_score >= 0.35:
            finding = (
                f"Suspicious periodicity: {len(flows)} flows at ~{mean_interval:.0f}s intervals"
            )

        logger.debug(
            "Beacon score=%.3f reg=%.3f jitter=%.3f payload=%.3f time=%.3f flows=%d",
            beacon_score, regularity, jitter, payload, time_ind, len(flows),
        )

        return {
            "beacon_score": beacon_score,
            "regularity_score": regularity,
            "jitter_score": jitter,
            "payload_score": payload,
            "time_score": time_ind,
            "flow_count": len(flows),
            "finding": finding,
            "mean_interval_seconds": round(mean_interval, 2),
        }

    def score_from_db(self, src_ip: str, dst_ip: str, conn: object) -> dict[str, object]:
        """Convenience method to score directly from the database by src/dst pair."""
        from src.storage.repositories.flow_repository import get_flows_by_src_dst
        flows = get_flows_by_src_dst(conn, src_ip, dst_ip)
        return self.score(flows)
