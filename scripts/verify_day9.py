"""Day 9 — Anomaly detection verification script for Spectra."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.analysis.anomaly.baseline_builder import BaselineBuilder
from src.analysis.anomaly.isolation_forest import IsolationForestScorer, get_scorer
from src.pipeline.orchestrator import PipelineOrchestrator
from src.storage.database import get_db


def _pass(msg: str) -> None:
    print(f"PASS: {msg}")


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}")


def main() -> int:
    failed = False

    # Check 1 — Scorer handles missing model gracefully
    try:
        scorer = IsolationForestScorer()
        result = scorer.score({"regularity_score": 0.5})
        assert float(result["anomaly_score"]) == 0.0
        assert result["model_ready"] in (True, False)
        _pass(f"Check 1 - Scorer handles missing/present model gracefully (model_ready={result['model_ready']})")
    except Exception as exc:
        failed = True
        _fail(f"Check 1 - Scorer initialization failed ({exc})")

    # Check 2 — Run pipeline to get feature rows for training
    try:
        conn = get_db().get_connection()
        conn.execute("DELETE FROM tls_sessions")
        conn.execute("DELETE FROM flows")
        conn.commit()

        pcap_path = PROJECT_ROOT / "data" / "raw" / "pcap" / "test_sample.pcap"
        orchestrator = PipelineOrchestrator(str(pcap_path))
        summary = orchestrator.run()
        feature_rows = list(orchestrator._feature_rows)
        assert len(feature_rows) > 0
        _pass(f"Check 2 - Pipeline produced {len(feature_rows)} feature rows for training")
    except Exception as exc:
        failed = True
        _fail(f"Check 2 - Pipeline run for training data failed ({exc})")
        feature_rows = []

    # Check 3 — Train the baseline model
    try:
        assert feature_rows, "No feature rows available"
        builder = BaselineBuilder()
        training_summary = builder.train_and_save(feature_rows)
        assert training_summary["samples_trained"] > 0
        assert Path(PROJECT_ROOT / "models" / "isolation_forest.joblib").exists()
        assert Path(PROJECT_ROOT / "models" / "scaler.joblib").exists()
        _pass(
            f"Check 3 - Model trained and saved: "
            f"samples={training_summary['samples_trained']} "
            f"anomaly_rate={training_summary['anomaly_rate']}"
        )
    except Exception as exc:
        failed = True
        _fail(f"Check 3 - Model training failed ({exc})")

    # Check 4 — Reload scorer and confirm model is ready
    try:
        # Reset singleton to force reload
        import src.analysis.anomaly.isolation_forest as iso_module
        iso_module._scorer_instance = None
        scorer = get_scorer()
        assert scorer.is_ready(), "Model should be ready after training"
        _pass("Check 4 - Model reloaded from disk successfully")
    except Exception as exc:
        failed = True
        _fail(f"Check 4 - Model reload failed ({exc})")

    # Check 5 — Score feature rows, all in [0.0, 1.0]
    try:
        scorer = get_scorer()
        scored = 0
        anomalies = 0
        for row in feature_rows:
            result = scorer.score(row)
            score = float(result["anomaly_score"])
            assert 0.0 <= score <= 1.0, f"Score out of range: {score}"
            scored += 1
            if result["is_anomaly"]:
                anomalies += 1
        _pass(f"Check 5 - Scored {scored} rows, {anomalies} anomalies detected")
    except Exception as exc:
        failed = True
        _fail(f"Check 5 - Scoring real rows failed ({exc})")

    # Check 6 — Uplift logic works correctly
    try:
        scorer = get_scorer()
        # Should apply uplift: anomaly=0.8 > 0.7, composite=0.3 < 0.5
        uplifted = scorer.apply_uplift(composite_score=0.3, anomaly_score=0.8)
        expected = max(0.3, 0.8 * 0.6)  # = 0.48
        assert abs(uplifted - expected) < 0.01, f"Expected ~{expected}, got {uplifted}"

        # Should NOT apply uplift: composite already high
        no_uplift = scorer.apply_uplift(composite_score=0.7, anomaly_score=0.8)
        assert no_uplift == 0.7, f"Should not uplift high composite, got {no_uplift}"

        _pass(f"Check 6 - Uplift logic correct: uplift={uplifted:.3f}, no_uplift={no_uplift:.3f}")
    except Exception as exc:
        failed = True
        _fail(f"Check 6 - Uplift logic check failed ({exc})")

    if failed:
        print("✗ Day 9 verification FAILED — see errors above")
        return 1

    print("✓ Day 9 verification passed — Anomaly detection is ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())