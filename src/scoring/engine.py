"""Composite scoring engine — combines all module scores into a final risk score."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from src.scoring.severity import get_severity, get_recommended_action

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_CONFIG_PATH = _PROJECT_ROOT / "configs" / "default.yaml"
_CONFIG = yaml.safe_load(_CONFIG_PATH.read_text(encoding="utf-8")) or {}
_WEIGHTS = _CONFIG.get("scoring", {}).get("weights", {})

W_JA3: float = float(_WEIGHTS.get("ja3", 0.35))
W_BEACON: float = float(_WEIGHTS.get("beacon", 0.25))
W_CERT: float = float(_WEIGHTS.get("cert", 0.20))
W_GRAPH: float = float(_WEIGHTS.get("graph", 0.20))


class ScoringEngine:
    """Combine individual module scores into a weighted composite risk score."""

    def __init__(self) -> None:
        """Initialize scoring engine with config-driven weights."""
        logger.info(
            "ScoringEngine initialized — weights: ja3=%.2f beacon=%.2f cert=%.2f graph=%.2f",
            W_JA3, W_BEACON, W_CERT, W_GRAPH,
        )

    def compute(
        self,
        ja3_score: float = 0.0,
        cert_score: float = 0.0,
        beacon_score: float = 0.0,
        graph_score: float = 0.0,
        anomaly_score: float = 0.0,
    ) -> dict[str, Any]:
        """Compute weighted composite score and map to severity tier.

        Formula:
            composite = 0.35*ja3 + 0.25*beacon + 0.20*cert + 0.20*graph

        Anomaly uplift rule (from architecture.md):
            IF anomaly_score > 0.7 AND composite < 0.5:
                composite = max(composite, anomaly_score * 0.6)

        Returns:
            composite_score (float): final 0.0–1.0 risk score
            severity (str): CLEAN / LOW / MEDIUM / HIGH / CRITICAL
            recommended_action (str): human readable action
            pre_uplift_score (float): score before anomaly uplift
            uplift_applied (bool): whether uplift changed the score
        """
        ja3 = max(0.0, min(1.0, float(ja3_score)))
        cert = max(0.0, min(1.0, float(cert_score)))
        beacon = max(0.0, min(1.0, float(beacon_score)))
        graph = max(0.0, min(1.0, float(graph_score)))
        anomaly = max(0.0, min(1.0, float(anomaly_score)))

        # Weighted composite
        composite = (
            W_JA3 * ja3
            + W_BEACON * beacon
            + W_CERT * cert
            + W_GRAPH * graph
        )
        composite = round(min(1.0, max(0.0, composite)), 4)
        pre_uplift = composite

        # Anomaly uplift
        uplift_applied = False
        if anomaly > 0.70 and composite < 0.50:
            uplifted = max(composite, anomaly * 0.60)
            uplifted = round(min(1.0, uplifted), 4)
            if uplifted != composite:
                logger.debug(
                    "Anomaly uplift applied: %.4f → %.4f (anomaly=%.4f)",
                    composite, uplifted, anomaly,
                )
                composite = uplifted
                uplift_applied = True

        severity = get_severity(composite)
        action = get_recommended_action(severity)

        logger.debug(
            "Score: ja3=%.2f cert=%.2f beacon=%.2f graph=%.2f anomaly=%.2f → composite=%.4f severity=%s",
            ja3, cert, beacon, graph, anomaly, composite, severity,
        )

        return {
            "composite_score": composite,
            "severity": severity,
            "recommended_action": action,
            "pre_uplift_score": pre_uplift,
            "uplift_applied": uplift_applied,
            "component_scores": {
                "ja3": ja3,
                "cert": cert,
                "beacon": beacon,
                "graph": graph,
                "anomaly": anomaly,
            },
        }
