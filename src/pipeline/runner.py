"""Pipeline runner — CLI entry point that wires all stages end to end."""

from __future__ import annotations

import argparse
import logging
import sqlite3
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.analysis.anomaly.isolation_forest import get_scorer
from src.analysis.beacon.analyzer import BeaconAnalyzer
from src.analysis.certificate.analyzer import CertificateAnalyzer
from src.analysis.ja3.analyzer import JA3Analyzer
from src.graph.builder import GraphBuilder
from src.graph.queries import run_all_queries
from src.pipeline.orchestrator import PipelineOrchestrator
from src.scoring.alert_builder import AlertBuilder
from src.scoring.deduplicator import Deduplicator
from src.scoring.engine import ScoringEngine
from src.scoring.whitelist import Whitelist
from src.storage.database import get_db
from src.storage.repositories import alert_repository, flow_repository, session_repository

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def run_pipeline(pcap_path: str, retrain: bool = False, clear: bool = False) -> dict:
    """Run the full Spectra pipeline on a PCAP file.

    Stages:
        1. Ingest PCAP → flows → TLS sessions → feature rows  (orchestrator)
        2. Build infrastructure graph from flows + sessions
        3. Score each flow through all 4 analysis modules
        4. Compute composite score via scoring engine
        5. Build and persist alerts for non-clean, non-whitelisted flows

    Args:
        pcap_path: Path to the .pcap file to analyse.
        retrain: If True, retrain the anomaly model on this PCAP's features.
        clear: If True, wipe flows/alerts/tls_sessions before running (prevents stale accumulation).

    Returns:
        Summary dict with pipeline statistics.
    """
    start_time = time.time()
    logger.info("=== Spectra pipeline starting: %s ===", pcap_path)

    # --- Optionally clear stale DB data before ingestion ---
    if clear:
        db_path = PROJECT_ROOT / "data" / "spectra.db"
        with sqlite3.connect(str(db_path)) as _clear_conn:
            _clear_conn.execute("DELETE FROM alerts")
            _clear_conn.execute("DELETE FROM flows")
            _clear_conn.execute("DELETE FROM tls_sessions")
            _clear_conn.commit()
        logger.info("[runner] DB cleared (alerts, flows, tls_sessions).")

    # --- Stage 1: Ingestion + flow reconstruction + feature engineering ---
    orchestrator = PipelineOrchestrator(pcap_path)
    pipeline_summary = orchestrator.run()
    feature_rows = list(orchestrator._feature_rows)
    logger.info(
        "Stage 1 complete: %d packets → %d flows → %d feature rows",
        pipeline_summary["packets_processed"],
        pipeline_summary["flows_completed"],
        len(feature_rows),
    )

    conn = get_db().get_connection()

    # --- Stage 2: Build infrastructure graph ---
    flows = flow_repository.get_recent_flows(conn, limit=10000)
    sessions = session_repository.get_recent_sessions(conn, limit=10000)
    graph_builder = GraphBuilder()
    graph = graph_builder.build(flows, sessions)
    logger.info(
        "Stage 2 complete: graph built with %d nodes, %d edges",
        graph.number_of_nodes(), graph.number_of_edges(),
    )

    # --- Optionally retrain anomaly model ---
    if retrain and feature_rows:
        logger.info("Retraining anomaly model on %d feature rows...", len(feature_rows))
        from src.analysis.anomaly.baseline_builder import BaselineBuilder
        builder = BaselineBuilder()
        train_summary = builder.train_and_save(feature_rows)
        logger.info("Anomaly model retrained: %s", train_summary)

    # --- Stage 3-5: Score each flow and build alerts ---
    ja3_analyzer = JA3Analyzer()
    cert_analyzer = CertificateAnalyzer()
    beacon_analyzer = BeaconAnalyzer()
    anomaly_scorer = get_scorer()
    scoring_engine = ScoringEngine()
    alert_builder = AlertBuilder()
    deduplicator = Deduplicator()
    whitelist = Whitelist()

    # Group flows by src/dst for beacon detection
    flow_groups: dict[tuple[str, str], list] = {}
    for flow in flows:
        key = (flow.src_ip, flow.dst_ip)
        flow_groups.setdefault(key, []).append(flow)

    # Map flow_id → session for quick lookup
    session_map = {s.flow_id: s for s in sessions}

    alerts_created = 0
    alerts_suppressed = 0
    alerts_whitelisted = 0
    flows_scored = 0

    for feature_row in feature_rows:
        flow_id = feature_row.get("flow_id")
        src_ip = str(feature_row.get("src_ip", ""))
        dst_ip = str(feature_row.get("dst_ip", ""))

        session = session_map.get(flow_id)

        # --- Whitelist check ---
        dst_domain = session.sni_domain if session else None
        if whitelist.is_whitelisted(dst_ip, dst_domain):
            alerts_whitelisted += 1
            continue

        # --- JA3 score ---
        ja3_result = ja3_analyzer.score(session)
        ja3_score = float(ja3_result["ja3_score"])

        # --- Certificate score ---
        cert_result = cert_analyzer.score(session)
        cert_score = float(cert_result["cert_score"])

        # --- Beacon score ---
        beacon_flows = flow_groups.get((src_ip, dst_ip), [])
        beacon_result = beacon_analyzer.score(beacon_flows)
        beacon_score = float(beacon_result["beacon_score"])

        # --- Graph score ---
        graph_result = run_all_queries(graph, dst_ip)
        graph_score = float(graph_result["graph_score"])

        # --- Anomaly score ---
        anomaly_result = anomaly_scorer.score(feature_row)
        anomaly_score = float(anomaly_result["anomaly_score"])

        # --- Composite score ---
        score_result = scoring_engine.compute(
            ja3_score=ja3_score,
            cert_score=cert_score,
            beacon_score=beacon_score,
            graph_score=graph_score,
            anomaly_score=anomaly_score,
        )
        composite = score_result["composite_score"]
        severity = score_result["severity"]
        flows_scored += 1

        # Skip clean flows
        if severity == "CLEAN":
            continue

        # --- Deduplication check ---
        if deduplicator.is_duplicate(src_ip, dst_ip):
            alerts_suppressed += 1
            continue

        # --- Collect all findings ---
        all_findings: list[str] = []
        if ja3_result.get("finding"):
            all_findings.append(ja3_result["finding"])
        all_findings.extend(cert_result.get("findings", []))
        if beacon_result.get("finding"):
            all_findings.append(beacon_result["finding"])
        all_findings.extend(graph_result.get("findings", []))
        if anomaly_result.get("finding"):
            all_findings.append(anomaly_result["finding"])

        # --- Build and persist alert ---
        alert = alert_builder.build(
            flow_id=flow_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_domain=dst_domain,
            composite_score=composite,
            severity=severity,
            recommended_action=score_result["recommended_action"],
            ja3_score=ja3_score,
            cert_score=cert_score,
            beacon_score=beacon_score,
            graph_score=graph_score,
            anomaly_score=anomaly_score,
            findings=all_findings,
        )
        alert_repository.insert_alert(conn, alert)
        deduplicator.register(src_ip, dst_ip)
        alerts_created += 1

    elapsed = round(time.time() - start_time, 2)
    summary = {
        "pcap_path": pcap_path,
        "elapsed_seconds": elapsed,
        "packets_processed": pipeline_summary["packets_processed"],
        "flows_completed": pipeline_summary["flows_completed"],
        "feature_rows": len(feature_rows),
        "flows_scored": flows_scored,
        "alerts_created": alerts_created,
        "alerts_suppressed": alerts_suppressed,
        "alerts_whitelisted": alerts_whitelisted,
        "graph_nodes": graph.number_of_nodes(),
        "graph_edges": graph.number_of_edges(),
    }

    logger.info("=== Pipeline complete in %.2fs: %s ===", elapsed, summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Spectra — encrypted traffic analyzer"
    )
    parser.add_argument(
        "--pcap", required=True, help="Path to the .pcap file to analyze"
    )
    parser.add_argument(
        "--retrain", action="store_true",
        help="Retrain the anomaly detection model on this PCAP's features"
    )
    parser.add_argument(
        "--clear", action="store_true",
        help="Clear flows, alerts, and tls_sessions from DB before running"
    )
    args = parser.parse_args()

    if not Path(args.pcap).is_file():
        logger.error("PCAP file not found: %s", args.pcap)
        return 1

    summary = run_pipeline(args.pcap, retrain=args.retrain, clear=args.clear)

    print("\n=== Spectra Pipeline Summary ===")
    for key, value in summary.items():
        print(f"  {key}: {value}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())