"""
Step 3 — Train ML model on labeled TCP flows.

Supports two modes:

  --mode supervised   (default)
      Trains a RandomForestClassifier for binary benign/malicious classification.
      Requires labeled_flows.csv with a 'label' column (0=benign, 1=malicious).
      Best when you have both benign AND malicious examples.

  --mode unsupervised
      Trains Spectra's built-in IsolationForest (anomaly detection).
      Uses only the SCORING_FEATURE_COLUMNS that Spectra's scoring engine expects.
      Replaces models/isolation_forest.joblib and models/scaler.joblib.
      Best when you only have benign traffic to establish a baseline.

Usage:
    # Supervised (default) — needs labeled data
    python step3_train_model.py

    # Unsupervised — trains Spectra's IsolationForest on your benign baseline
    python step3_train_model.py --mode unsupervised

    # Use test_sample instead of real_traffic
    python step3_train_model.py --flows data/processed/labeled_flows.csv
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.preprocessing import StandardScaler

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Must match src/features/schema.py exactly
FLOW_FEATURE_COLUMNS = [
    "duration_ms", "total_packets", "total_bytes",
    "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
    "packet_rate_per_sec", "byte_rate_per_sec",
    "avg_packet_size", "min_packet_size", "max_packet_size", "std_packet_size",
    "mean_iat_ms", "min_iat_ms", "max_iat_ms", "std_iat_ms",
    "syn_count", "ack_count", "fin_count", "rst_count", "psh_count",
]

# Must match src/features/schema.py SCORING_FEATURE_COLUMNS exactly
# These are what Spectra's IsolationForest uses
SCORING_FEATURE_COLUMNS = [
    "regularity_score",
    "payload_consistency",
    "cert_age_normalized",
    "tls_version_encoded",
    "bytes_per_second",
    "packet_rate",
]


def compute_scoring_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Derive the 6 SCORING_FEATURE_COLUMNS from raw flow features.
    These approximate what Spectra's full pipeline computes.
    """
    out = pd.DataFrame(index=df.index)

    # regularity_score: low std_iat relative to mean_iat = regular/beaconing
    mean_iat = df["mean_iat_ms"].replace(0, np.nan)
    out["regularity_score"] = (1.0 - (df["std_iat_ms"] / mean_iat).clip(0, 1)).fillna(0.0)

    # payload_consistency: fwd/bwd balance — very one-sided = suspicious
    total = df["total_bytes"].replace(0, 1)
    ratio = (df["fwd_bytes"] / total).clip(0, 1)
    out["payload_consistency"] = 1.0 - (ratio - 0.5).abs() * 2  # 1=balanced, 0=all one way

    # cert_age_normalized: we don't have TLS here, default to 0
    out["cert_age_normalized"] = 0.0

    # tls_version_encoded: we don't have TLS here, default to 0
    out["tls_version_encoded"] = 0.0

    # bytes_per_second: raw byte rate
    out["bytes_per_second"] = df["byte_rate_per_sec"].fillna(0.0)

    # packet_rate: packets per second
    out["packet_rate"] = df["packet_rate_per_sec"].fillna(0.0)

    return out


def train_supervised(df: pd.DataFrame, model_dir: Path) -> None:
    """Train RandomForest for binary benign/malicious classification."""
    if "label" not in df.columns:
        logger.error("No 'label' column found. Run step2_label_flows.py first.")
        sys.exit(1)

    label_counts = df["label"].value_counts()
    logger.info("Label distribution:\n  benign(0): %d  malicious(1): %d",
                label_counts.get(0, 0), label_counts.get(1, 0))

    if label_counts.get(1, 0) == 0:
        logger.error(
            "No malicious samples found. Cannot train supervised model.\n"
            "Use --mode unsupervised, or add malicious data (see step2 output for guidance)."
        )
        sys.exit(1)

    if label_counts.get(0, 0) == 0:
        logger.error("No benign samples found. Check your labeled_flows.csv.")
        sys.exit(1)

    X = df[FLOW_FEATURE_COLUMNS].copy()
    y = df["label"].astype(int)

    # Clean up any inf/nan
    X = X.replace([np.inf, -np.inf], 0).fillna(0)

    # Train/test split — stratified to preserve class balance
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    logger.info("Training RandomForest on %d samples, %d features...", len(X_train), X_train.shape[1])

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",  # handles class imbalance
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    # Evaluate
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    logger.info("\n=== Classification Report ===\n%s", classification_report(y_test, y_pred))
    logger.info("Confusion Matrix:\n%s", confusion_matrix(y_test, y_pred))

    try:
        auc = roc_auc_score(y_test, y_prob)
        logger.info("ROC AUC: %.4f", auc)
    except Exception:
        pass

    # Cross-validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(clf, X, y, cv=cv, scoring="f1", n_jobs=-1)
    logger.info("5-Fold CV F1: %.4f ± %.4f", cv_scores.mean(), cv_scores.std())

    # Feature importance
    importances = pd.Series(clf.feature_importances_, index=FLOW_FEATURE_COLUMNS)
    top10 = importances.nlargest(10)
    logger.info("\nTop 10 features by importance:\n%s", top10.to_string())

    # Save model
    model_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, model_dir / "rf_flow_classifier.joblib")
    logger.info("Model saved to %s", model_dir / "rf_flow_classifier.joblib")

    # Save feature list so inference knows what to use
    pd.Series(FLOW_FEATURE_COLUMNS).to_csv(model_dir / "rf_feature_columns.csv", index=False, header=False)
    logger.info("Feature list saved to %s", model_dir / "rf_feature_columns.csv")


def train_unsupervised(df: pd.DataFrame, model_dir: Path, project_root: Path) -> None:
    """
    Train Spectra's IsolationForest using SCORING_FEATURE_COLUMNS.
    Saves to models/isolation_forest.joblib and models/scaler.joblib,
    replacing Spectra's existing (version-mismatched) model files.
    """
    logger.info("Training IsolationForest (unsupervised anomaly detection)...")

    # Use only benign flows if labels are available
    if "label" in df.columns:
        benign_df = df[df["label"] == 0].copy()
        logger.info("Using %d benign-labeled flows for baseline training", len(benign_df))
    else:
        benign_df = df.copy()
        logger.info("No labels found — using all %d flows as baseline", len(benign_df))

    if len(benign_df) < 10:
        logger.error("Need at least 10 samples. Got %d.", len(benign_df))
        sys.exit(1)

    # Compute scoring features
    scoring_feats = compute_scoring_features(benign_df)
    X = scoring_feats[SCORING_FEATURE_COLUMNS].replace([np.inf, -np.inf], 0).fillna(0)

    logger.info("Training on %d samples, %d features: %s",
                len(X), len(SCORING_FEATURE_COLUMNS), SCORING_FEATURE_COLUMNS)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Read contamination from Spectra config
    try:
        import yaml
        cfg_path = project_root / "configs" / "default.yaml"
        cfg = yaml.safe_load(cfg_path.read_text()) or {}
        contamination = float(cfg.get("anomaly", {}).get("contamination", 0.05))
        n_estimators = int(cfg.get("anomaly", {}).get("n_estimators", 100))
    except Exception:
        contamination, n_estimators = 0.05, 100

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_scaled)

    labels = model.predict(X_scaled)
    n_anomalies = int((labels == -1).sum())
    logger.info("Training complete. Flagged %d/%d as anomalies (contamination=%.2f)",
                n_anomalies, len(X), contamination)

    # Save to Spectra's expected model paths
    spectra_model_dir = project_root / "models"
    spectra_model_dir.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, spectra_model_dir / "isolation_forest.joblib")
    joblib.dump(scaler, spectra_model_dir / "scaler.joblib")
    logger.info("Saved isolation_forest.joblib and scaler.joblib to %s", spectra_model_dir)

    # Also save to our ml/ models dir for reference
    model_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_dir / "isolation_forest.joblib")
    joblib.dump(scaler, model_dir / "scaler.joblib")
    logger.info("Backup copy saved to %s", model_dir)


def main():
    parser = argparse.ArgumentParser(description="Train ML model on TCP flows")
    parser.add_argument("--flows", default="data/processed/labeled_flows.csv",
                        help="Path to labeled_flows.csv (from step2)")
    parser.add_argument("--mode", choices=["supervised", "unsupervised"], default="supervised",
                        help="supervised=RandomForest, unsupervised=IsolationForest")
    parser.add_argument("--model-dir", default="models/ml",
                        help="Directory to save trained model files")
    parser.add_argument("--project-root", default=".",
                        help="Project root directory (where configs/ lives)")
    args = parser.parse_args()

    flows_path = Path(args.flows)
    if not flows_path.exists():
        logger.error("Flows file not found: %s\nRun step1 and step2 first.", flows_path)
        sys.exit(1)

    df = pd.read_csv(flows_path)
    logger.info("Loaded %d flows from %s", len(df), flows_path)

    model_dir = Path(args.model_dir)
    project_root = Path(args.project_root).resolve()

    if args.mode == "supervised":
        train_supervised(df, model_dir)
    else:
        train_unsupervised(df, model_dir, project_root)


if __name__ == "__main__":
    main()