"""Isolation Forest baseline builder — trains and saves the anomaly detection model."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import yaml
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from src.features.schema import SCORING_FEATURE_COLUMNS

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_CONFIG_PATH = _PROJECT_ROOT / "configs" / "default.yaml"
_CONFIG = yaml.safe_load(_CONFIG_PATH.read_text(encoding="utf-8")) or {}
_ANOMALY_CFG = _CONFIG.get("anomaly", {})

MODEL_PATH = _PROJECT_ROOT / "models" / "isolation_forest.joblib"
SCALER_PATH = _PROJECT_ROOT / "models" / "scaler.joblib"

CONTAMINATION: float = float(_ANOMALY_CFG.get("contamination", 0.05))
N_ESTIMATORS: int = int(_ANOMALY_CFG.get("n_estimators", 100))


class BaselineBuilder:
    """Train an IsolationForest on clean baseline feature rows and persist the model."""

    def __init__(self) -> None:
        """Initialize baseline builder with config-driven hyperparameters."""
        self._model: IsolationForest | None = None
        self._scaler: StandardScaler | None = None
        logger.info(
            "BaselineBuilder initialized — contamination=%.2f n_estimators=%d",
            CONTAMINATION, N_ESTIMATORS,
        )

    def train(self, feature_rows: list[dict[str, Any]]) -> dict[str, Any]:
        """Train IsolationForest on a list of feature row dicts.

        Args:
            feature_rows: List of feature dicts, each containing SCORING_FEATURE_COLUMNS.

        Returns:
            Summary dict with training stats.
        """
        if not feature_rows:
            raise ValueError("Cannot train on empty feature set")

        # Extract only the scoring features used by the model
        X = self._extract_matrix(feature_rows)

        if X.shape[0] < 10:
            raise ValueError(f"Need at least 10 samples to train, got {X.shape[0]}")

        logger.info("Training IsolationForest on %d samples, %d features", X.shape[0], X.shape[1])

        # Scale features before training
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        # Train model
        self._model = IsolationForest(
            n_estimators=N_ESTIMATORS,
            contamination=CONTAMINATION,
            random_state=42,
            n_jobs=-1,
        )
        self._model.fit(X_scaled)

        # Compute training scores to summarize
        raw_scores = self._model.score_samples(X_scaled)
        anomaly_labels = self._model.predict(X_scaled)
        n_anomalies = int(np.sum(anomaly_labels == -1))

        summary = {
            "samples_trained": X.shape[0],
            "features_used": SCORING_FEATURE_COLUMNS,
            "n_anomalies_in_training": n_anomalies,
            "anomaly_rate": round(n_anomalies / X.shape[0], 4),
            "score_mean": round(float(np.mean(raw_scores)), 4),
            "score_std": round(float(np.std(raw_scores)), 4),
        }

        logger.info("Training complete: %s", summary)
        return summary

    def save(self) -> None:
        """Persist trained model and scaler to disk."""
        if self._model is None or self._scaler is None:
            raise RuntimeError("Model not trained yet — call train() first")

        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self._model, MODEL_PATH)
        joblib.dump(self._scaler, SCALER_PATH)
        logger.info("Model saved to %s", MODEL_PATH)
        logger.info("Scaler saved to %s", SCALER_PATH)

    def train_and_save(self, feature_rows: list[dict[str, Any]]) -> dict[str, Any]:
        """Train and immediately save the model in one call."""
        summary = self.train(feature_rows)
        self.save()
        return summary

    def _extract_matrix(self, feature_rows: list[dict[str, Any]]) -> np.ndarray:
        """Extract SCORING_FEATURE_COLUMNS from feature rows into a numpy matrix."""
        rows = []
        for row in feature_rows:
            try:
                values = [float(row.get(col, 0.0) or 0.0) for col in SCORING_FEATURE_COLUMNS]
                # Replace NaN/inf with 0
                values = [0.0 if (v != v or v == float("inf") or v == float("-inf")) else v for v in values]
                rows.append(values)
            except Exception as exc:
                logger.debug("Skipping malformed feature row: %s", exc)
                continue

        if not rows:
            raise ValueError("No valid feature rows could be extracted")

        return np.array(rows, dtype=float)
