"""Isolation Forest inference — loads saved model and scores feature rows."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import yaml

from src.features.schema import SCORING_FEATURE_COLUMNS

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_CONFIG_PATH = _PROJECT_ROOT / "configs" / "default.yaml"
_CONFIG = yaml.safe_load(_CONFIG_PATH.read_text(encoding="utf-8")) or {}
_ANOMALY_CFG = _CONFIG.get("anomaly", {})

MODEL_PATH = _PROJECT_ROOT / "models" / "isolation_forest.joblib"
SCALER_PATH = _PROJECT_ROOT / "models" / "scaler.joblib"

SCORE_THRESHOLD: float = float(_ANOMALY_CFG.get("score_threshold", 0.70))
COMPOSITE_THRESHOLD: float = float(_ANOMALY_CFG.get("composite_threshold", 0.50))
UPLIFT_FACTOR: float = float(_ANOMALY_CFG.get("uplift_factor", 0.60))


class IsolationForestScorer:
    """Load a trained IsolationForest model and score individual feature rows."""

    def __init__(self) -> None:
        """Load model and scaler from disk if they exist."""
        self._model = None
        self._scaler = None
        self._loaded = False
        self._try_load()

    def _try_load(self) -> None:
        """Attempt to load model and scaler — silently skip if not trained yet."""
        if not MODEL_PATH.exists() or not SCALER_PATH.exists():
            logger.info("No trained model found at %s — anomaly scoring disabled", MODEL_PATH)
            return
        try:
            self._model = joblib.load(MODEL_PATH)
            self._scaler = joblib.load(SCALER_PATH)
            self._loaded = True
            logger.info("IsolationForest model loaded from %s", MODEL_PATH)
        except Exception as exc:
            logger.warning("Failed to load anomaly model: %s", exc)

    def is_ready(self) -> bool:
        """Return True if the model is loaded and ready to score."""
        return self._loaded

    def score(self, feature_row: dict[str, Any]) -> dict[str, object]:
        """Score one feature row and return anomaly score + uplift decision.

        Returns:
            anomaly_score (float): 0.0 to 1.0 (higher = more anomalous)
            is_anomaly (bool): True if score exceeds threshold
            finding (str | None): human-readable finding if anomalous
            model_ready (bool): False if model not trained yet
        """
        if not self._loaded:
            return {
                "anomaly_score": 0.0,
                "is_anomaly": False,
                "finding": None,
                "model_ready": False,
            }

        try:
            values = [float(feature_row.get(col, 0.0) or 0.0) for col in SCORING_FEATURE_COLUMNS]
            values = [0.0 if (v != v or v == float("inf") or v == float("-inf")) else v for v in values]
            X = np.array([values], dtype=float)
            X_scaled = self._scaler.transform(X)

            # IsolationForest score_samples returns negative values
            # More negative = more anomalous
            # We normalize to [0, 1] where 1 = most anomalous
            raw_score = float(self._model.score_samples(X_scaled)[0])

            # Typical range is roughly [-0.5, 0.5] — map to [0, 1]
            # score_samples closer to 0 = normal, more negative = anomalous
            anomaly_score = max(0.0, min(1.0, -raw_score * 2.0))

            is_anomaly = anomaly_score >= SCORE_THRESHOLD
            finding = None
            if is_anomaly:
                finding = f"Anomaly detector flagged this flow (score={anomaly_score:.2f})"
                logger.warning("Anomaly detected: score=%.3f", anomaly_score)

            return {
                "anomaly_score": round(anomaly_score, 4),
                "is_anomaly": is_anomaly,
                "finding": finding,
                "model_ready": True,
            }

        except Exception as exc:
            logger.error("Anomaly scoring failed: %s", exc)
            return {
                "anomaly_score": 0.0,
                "is_anomaly": False,
                "finding": None,
                "model_ready": True,
            }

    def apply_uplift(self, composite_score: float, anomaly_score: float) -> float:
        """Apply anomaly score uplift to composite score per architecture rules.

        Rule: IF anomaly_score > 0.7 AND composite_score < 0.5:
                  composite = max(composite, anomaly_score * 0.6)
        """
        if anomaly_score > SCORE_THRESHOLD and composite_score < COMPOSITE_THRESHOLD:
            uplifted = max(composite_score, anomaly_score * UPLIFT_FACTOR)
            logger.debug(
                "Uplift applied: composite %.3f → %.3f (anomaly=%.3f)",
                composite_score, uplifted, anomaly_score,
            )
            return round(uplifted, 4)
        return composite_score


# Singleton instance
_scorer_instance: IsolationForestScorer | None = None


def get_scorer() -> IsolationForestScorer:
    """Return the singleton IsolationForestScorer instance."""
    global _scorer_instance
    if _scorer_instance is None:
        _scorer_instance = IsolationForestScorer()
    return _scorer_instance
