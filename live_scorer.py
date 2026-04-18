"""Standalone live flow scoring helper.

This module batches flow dictionaries, scores them via the existing step4 scoring
functions, and optionally ingests results into the Spectra database.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd


class LiveScorer:
    """Batch and score live flow records using supervised or unsupervised models.

    The scorer reuses functions from step4_score_flows and keeps a pending batch
    buffer that is flushed when batch_size is reached or when flush() is called.
    """

    def __init__(
        self,
        mode: str = "supervised",
        model_dir: str | Path = "models/ml",
        project_root: str | Path = ".",
        db_path: str | Path = "spectra.db",
        no_db: bool = False,
        batch_size: int = 10,
    ) -> None:
        """Initialize scorer configuration, imports, and model warm-up.

        Args:
            mode: Scoring mode, either "supervised" or "unsupervised".
            model_dir: Directory containing supervised model artifacts.
            project_root: Project root path used for unsupervised artifact paths.
            db_path: SQLite database path used by ingest_to_db.
            no_db: When True, skip database ingestion.
            batch_size: Number of pending flows required before auto-scoring.

        Raises:
            ValueError: If mode or batch_size are invalid.
            FileNotFoundError: If required model artifacts are missing.
        """
        if mode not in {"supervised", "unsupervised"}:
            raise ValueError("mode must be either 'supervised' or 'unsupervised'")
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")

        self.mode = mode
        self.project_root = Path(project_root).resolve()
        model_dir_path = Path(model_dir)
        if not model_dir_path.is_absolute():
            model_dir_path = self.project_root / model_dir_path
        self.model_dir = model_dir_path.resolve()

        db_path_obj = Path(db_path)
        if not db_path_obj.is_absolute():
            db_path_obj = self.project_root / db_path_obj
        self.db_path = db_path_obj.resolve()

        self.no_db = bool(no_db)
        self.batch_size = int(batch_size)
        self._pending: list[dict[str, Any]] = []

        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(logging.INFO)

        from step4_score_flows import (
            FLOW_FEATURE_COLUMNS,
            _score_to_severity,
            compute_module_scores,
            ingest_to_db,
            score_supervised,
            score_unsupervised,
        )

        self._flow_feature_columns: list[str] = list(FLOW_FEATURE_COLUMNS)
        self._score_supervised = score_supervised
        self._score_unsupervised = score_unsupervised
        self._ingest_to_db = ingest_to_db
        self._score_to_severity = _score_to_severity
        self._compute_module_scores = compute_module_scores

        # Warm-load model artifacts so first scoring call avoids cold load latency.
        self._preloaded_artifacts: dict[str, Any] = {}
        self._preload_models()

    def submit_flow(self, flow_dict: dict[str, Any]) -> list[dict[str, Any]]:
        """Submit a single flow record for batched scoring.

        Args:
            flow_dict: One flow dictionary, typically from a live flow aggregator.

        Returns:
            A list of scored flow dicts when batch_size is reached; otherwise [].
        """
        self._pending.append(dict(flow_dict))
        if len(self._pending) >= self.batch_size:
            return self._score_batch()
        return []

    def _score_batch(self) -> list[dict[str, Any]]:
        """Score and optionally ingest all currently pending flow records.

        Returns:
            Scored flow rows as a list of dicts (records orientation).
        """
        if not self._pending:
            return []

        df = pd.DataFrame(self._pending)
        scored_df = self._score_dataframe_internal(df)

        if not self.no_db:
            self._logger.info("DB ingestion started for %d flows", len(scored_df))
            self._ingest_to_db(scored_df, self.db_path)
            self._logger.info("DB ingestion finished for %d flows", len(scored_df))

        alerts_generated = int((scored_df.get("verdict", "BENIGN") != "BENIGN").sum())
        self._logger.info(
            "Batch scored: %d flows | mode=%s | alerts generated=%d",
            len(scored_df),
            self.mode,
            alerts_generated,
        )

        self._pending.clear()
        return scored_df.to_dict(orient="records")

    def flush(self) -> list[dict[str, Any]]:
        """Force-score all remaining pending flows, even below batch_size."""
        return self._score_batch()

    def score_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Score a DataFrame directly, bypassing the pending batch buffer.

        Args:
            df: Input DataFrame containing flow identity columns and/or features.

        Returns:
            Scored DataFrame from the selected scoring mode.
        """
        scored_df = self._score_dataframe_internal(df)

        if not self.no_db:
            self._logger.info("DB ingestion started for %d flows", len(scored_df))
            self._ingest_to_db(scored_df, self.db_path)
            self._logger.info("DB ingestion finished for %d flows", len(scored_df))

        alerts_generated = int((scored_df.get("verdict", "BENIGN") != "BENIGN").sum())
        self._logger.info(
            "DataFrame scored: %d flows | mode=%s | alerts generated=%d",
            len(scored_df),
            self.mode,
            alerts_generated,
        )

        return scored_df

    def _score_dataframe_internal(self, df: pd.DataFrame) -> pd.DataFrame:
        """Fill missing feature columns and execute scoring for the configured mode."""
        prepared = df.copy()
        for column in self._flow_feature_columns:
            if column not in prepared.columns:
                prepared[column] = 0.0

        prepared[self._flow_feature_columns] = (
            prepared[self._flow_feature_columns]
            .replace([np.inf, -np.inf], 0.0)
            .fillna(0.0)
        )

        if self.mode == "supervised":
            scored_df = self._score_supervised(prepared, self.model_dir)
        else:
            scored_df = self._score_unsupervised(prepared, self.project_root)

        return scored_df

    def _preload_models(self) -> None:
        """Warm-load model artifacts and raise actionable errors when missing."""
        if self.mode == "supervised":
            model_path = self.model_dir / "rf_flow_classifier.joblib"
            if not model_path.exists():
                raise FileNotFoundError(
                    f"Supervised model not found at {model_path}. "
                    "Run step3_train_model.py first (for supervised mode)."
                )
            self._preloaded_artifacts["rf_flow_classifier"] = joblib.load(model_path)
            self._logger.info("Preloaded supervised model from %s", model_path)
            return

        model_path = self.project_root / "models" / "isolation_forest.joblib"
        scaler_path = self.project_root / "models" / "scaler.joblib"

        if not model_path.exists():
            raise FileNotFoundError(
                f"Unsupervised model not found at {model_path}. "
                "Run step3_train_model.py first (for unsupervised mode)."
            )
        if not scaler_path.exists():
            raise FileNotFoundError(
                f"Scaler not found at {scaler_path}. "
                "Run step3_train_model.py first (for unsupervised mode)."
            )

        self._preloaded_artifacts["isolation_forest"] = joblib.load(model_path)
        self._preloaded_artifacts["scaler"] = joblib.load(scaler_path)
        self._logger.info(
            "Preloaded unsupervised artifacts from %s and %s",
            model_path,
            scaler_path,
        )
