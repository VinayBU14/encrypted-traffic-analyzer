"""
Retrain the IsolationForest anomaly model on a PCAP file.

Usage:
    python scripts/retrain_model.py --pcap data/raw/pcap/real_traffic.pcap
    python scripts/retrain_model.py --pcap data/raw/pcap/real_traffic.pcap --clear

This script:
1. Runs the full ingestion pipeline on the provided PCAP
2. Collects feature rows from all reconstructed flows
3. Trains a new IsolationForest model on those features
4. Saves model + scaler to models/
5. Prints a training summary

Run this whenever you capture new baseline (clean) traffic.
Delete models/isolation_forest.joblib and models/scaler.joblib first
if you want a completely fresh model (no warm start).
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.pipeline.runner import run_pipeline

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def main() -> int:
    parser = argparse.ArgumentParser(description="Retrain Spectra anomaly model on a PCAP file")
    parser.add_argument("--pcap", required=True, help="Path to the .pcap or .pcapng file")
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Wipe alerts/flows/tls_sessions from DB before ingestion",
    )
    args = parser.parse_args()

    pcap_path = Path(args.pcap)
    if not pcap_path.is_file():
        logger.error("PCAP not found: %s", pcap_path)
        return 1

    logger.info("Starting retrain pipeline on: %s", pcap_path)
    summary = run_pipeline(str(pcap_path), retrain=True, clear=args.clear)

    print("\n=== Retrain Summary ===")
    for key, value in summary.items():
        print(f"  {key}: {value}")

    feature_rows = summary.get("feature_rows", 0)
    if feature_rows == 0:
        print("\n[ERROR] No feature rows were produced.")
        print("  Possible causes:")
        print("  1. No TLS/TCP traffic on configured ports (check configs/default.yaml tls_tcp_ports)")
        print("  2. PCAP is empty or corrupt")
        print("  3. All flows were whitelisted")
        print("  Run: python scripts/diagnose_tls.py to inspect packet layers")
        return 1

    print(f"\n[OK] Model retrained on {feature_rows} feature rows.")
    print("  Models saved to: models/isolation_forest.joblib + models/scaler.joblib")
    print("  Restart the API server to load the new model.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())