"""
Step 4 — Score new TCP flows using the trained model.

Takes a raw PCAP (or a pre-extracted flows CSV) and runs it through
the trained model to predict benign vs malicious per flow.

Usage:
    # Score a new PCAP with the supervised RandomForest
    python step4_score_flows.py --pcap data/raw/pcap/real_traffic.pcap

    # Score a pre-extracted flows CSV
    python step4_score_flows.py --flows data/processed/tcp_flows.csv

    # Score using the unsupervised IsolationForest
    python step4_score_flows.py --pcap data/raw/pcap/real_traffic.pcap --mode unsupervised

    # Skip DB ingestion (CSV only)
    python step4_score_flows.py --pcap data/raw/pcap/real_traffic.pcap --no-db
"""

from __future__ import annotations

import argparse
import logging
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

FLOW_FEATURE_COLUMNS = [
    "duration_ms", "total_packets", "total_bytes",
    "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
    "packet_rate_per_sec", "byte_rate_per_sec",
    "avg_packet_size", "min_packet_size", "max_packet_size", "std_packet_size",
    "mean_iat_ms", "min_iat_ms", "max_iat_ms", "std_iat_ms",
    "syn_count", "ack_count", "fin_count", "rst_count", "psh_count",
]

SCORING_FEATURE_COLUMNS = [
    "regularity_score", "payload_consistency", "cert_age_normalized",
    "tls_version_encoded", "bytes_per_second", "packet_rate",
]


def compute_scoring_features(df: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame(index=df.index)
    mean_iat = df["mean_iat_ms"].replace(0, np.nan)
    out["regularity_score"] = (1.0 - (df["std_iat_ms"] / mean_iat).clip(0, 1)).fillna(0.0)
    total = df["total_bytes"].replace(0, 1)
    ratio = (df["fwd_bytes"] / total).clip(0, 1)
    out["payload_consistency"] = 1.0 - (ratio - 0.5).abs() * 2
    out["cert_age_normalized"] = 0.0
    out["tls_version_encoded"] = 0.0
    out["bytes_per_second"] = df["byte_rate_per_sec"].fillna(0.0)
    out["packet_rate"] = df["packet_rate_per_sec"].fillna(0.0)
    return out


def compute_module_scores(df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute heuristic sub-scores for each detection module.
    All scores are in [0.0, 1.0] where higher = more suspicious.

    These are derived entirely from observable flow metadata —
    no payload inspection required.
    """
    result = df.copy()

    # ── JA3 Fingerprint Score ────────────────────────────────────────────────
    # Proxy: flows on port 443/8443 with unusual traffic shapes (very low or
    # very high packet rates) suggest non-browser TLS clients (malware, C2).
    # High std_iat relative to mean suggests scripted/automated connections.
    is_tls_port = result["dst_port"].isin([443, 8443, 993, 995, 465]).astype(float)
    pkt_rate = result["packet_rate_per_sec"].fillna(0.0)
    # Abnormal packet rate: very low (<1 pkt/s) or very high (>500 pkt/s)
    pkt_rate_anomaly = (
        ((pkt_rate < 1.0) & (pkt_rate > 0.0)).astype(float) * 0.6
        + (pkt_rate > 500.0).astype(float) * 0.8
    ).clip(0, 1)
    mean_iat = result["mean_iat_ms"].replace(0, np.nan)
    std_iat  = result["std_iat_ms"].fillna(0.0)
    iat_cv   = (std_iat / mean_iat).fillna(0.0).clip(0, 5) / 5.0  # coeff of variation, normalized
    # Suspicious: very LOW iat_cv on TLS port = automated/scripted client
    automated_tls = (is_tls_port * (1.0 - iat_cv.clip(0, 1))).clip(0, 1)
    result["ja3_score"] = (
        0.4 * pkt_rate_anomaly
        + 0.4 * automated_tls
        + 0.2 * is_tls_port * (result["syn_count"].fillna(0) > 3).astype(float)
    ).clip(0, 1).round(4)

    # ── Beacon Detection Score ───────────────────────────────────────────────
    # Beaconing = periodic, regular, low-volume connections.
    # Signals: high regularity (low std_iat/mean_iat ratio), small packet size,
    # many short sessions, consistent byte counts.
    regularity = (1.0 - (std_iat / mean_iat).clip(0, 1)).fillna(0.0)
    small_pkts = (result["avg_packet_size"].fillna(0) < 200).astype(float)
    low_volume = (result["total_bytes"].fillna(0) < 5000).astype(float)
    # Short duration but many packets = classic beacon heartbeat
    duration_sec = (result["duration_ms"].fillna(0) / 1000.0).replace(0, np.nan)
    high_pkt_density = (result["total_packets"].fillna(0) / duration_sec).fillna(0).clip(0, 100) / 100.0
    result["beacon_score"] = (
        0.45 * regularity
        + 0.25 * small_pkts
        + 0.20 * low_volume
        + 0.10 * high_pkt_density
    ).clip(0, 1).round(4)

    # ── Certificate Risk Score ───────────────────────────────────────────────
    # Without decrypting, we proxy cert risk via:
    # - Very short-lived connections (cert not cached = first contact)
    # - RST/FIN anomalies (cert rejected / TLS failure)
    # - Connections to non-standard TLS ports
    non_std_tls = (~result["dst_port"].isin([443, 8443])).astype(float) * 0.5
    rst_ratio = (
        result["rst_count"].fillna(0) /
        result["total_packets"].replace(0, 1)
    ).clip(0, 1)
    fin_ratio = (
        result["fin_count"].fillna(0) /
        result["total_packets"].replace(0, 1)
    ).clip(0, 1)
    # Very short duration + high RST suggests TLS handshake failure
    very_short = (result["duration_ms"].fillna(0) < 500).astype(float)
    tls_failure_proxy = (very_short * rst_ratio).clip(0, 1)
    result["cert_score"] = (
        0.35 * non_std_tls
        + 0.35 * tls_failure_proxy
        + 0.20 * rst_ratio
        + 0.10 * fin_ratio
    ).clip(0, 1).round(4)

    # ── Graph Proximity Score ────────────────────────────────────────────────
    # Measures how "connected" each flow's dst_ip is to other suspicious flows.
    # Proxy: flows sharing dst_ip with many other flows = infrastructure reuse.
    dst_ip_counts = result["dst_ip"].map(result["dst_ip"].value_counts())
    # Normalize: IPs seen in >10 flows get max score
    dst_freq_score = (dst_ip_counts / dst_ip_counts.max().clip(min=1)).clip(0, 1).fillna(0.0)
    # Also penalize flows where src talks to many different destinations
    src_fan_out = result["src_ip"].map(result["dst_ip"].groupby(result["src_ip"]).nunique())
    max_fan_out = src_fan_out.max() if src_fan_out.max() > 0 else 1
    fan_out_score = (src_fan_out / max_fan_out).clip(0, 1).fillna(0.0)
    result["graph_score"] = (
        0.60 * dst_freq_score
        + 0.40 * fan_out_score
    ).clip(0, 1).round(4)

    return result


def score_supervised(df: pd.DataFrame, model_dir: Path) -> pd.DataFrame:
    model_path = model_dir / "rf_flow_classifier.joblib"
    if not model_path.exists():
        logger.error("Model not found at %s. Run step3_train_model.py --mode supervised first.", model_path)
        sys.exit(1)

    clf = joblib.load(model_path)
    X = df[FLOW_FEATURE_COLUMNS].replace([np.inf, -np.inf], 0).fillna(0)

    df["prediction"] = clf.predict(X)
    df["malicious_probability"] = clf.predict_proba(X)[:, 1]
    df["verdict"] = df["prediction"].map({0: "BENIGN", 1: "MALICIOUS"})

    # Compute per-module heuristic scores from flow metadata
    df = compute_module_scores(df)

    return df


def score_unsupervised(df: pd.DataFrame, project_root: Path) -> pd.DataFrame:
    model_path = project_root / "models" / "isolation_forest.joblib"
    scaler_path = project_root / "models" / "scaler.joblib"

    if not model_path.exists():
        logger.error("IsolationForest model not found at %s. Run step3 --mode unsupervised first.", model_path)
        sys.exit(1)

    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)

    scoring_feats = compute_scoring_features(df)
    X = scoring_feats[SCORING_FEATURE_COLUMNS].replace([np.inf, -np.inf], 0).fillna(0)
    X_scaled = scaler.transform(X)

    raw_scores = model.score_samples(X_scaled)
    anomaly_scores = np.clip(-raw_scores * 2.0, 0, 1)

    df["anomaly_score"] = anomaly_scores.round(4)
    df["prediction"] = (anomaly_scores >= 0.70).astype(int)
    df["verdict"] = df["prediction"].map({0: "BENIGN", 1: "ANOMALY"})

    # Compute per-module heuristic scores from flow metadata
    df = compute_module_scores(df)

    return df


def _get_composite_score(row: pd.Series) -> float:
    """
    Weighted composite of all detection module scores.

    Weights reflect signal reliability:
      - Anomaly (ML)       40% — strongest signal from IsolationForest
      - Beacon Detection   20% — reliable C2 indicator
      - JA3 Fingerprint    15% — TLS client heuristic
      - Certificate Risk   15% — handshake anomaly proxy
      - Graph Proximity    10% — infrastructure clustering
    """
    anomaly  = float(row.get("anomaly_score", 0.0) or 0.0)
    ja3      = float(row.get("ja3_score", 0.0) or 0.0)
    beacon   = float(row.get("beacon_score", 0.0) or 0.0)
    cert     = float(row.get("cert_score", 0.0) or 0.0)
    graph    = float(row.get("graph_score", 0.0) or 0.0)

    # Fall back to malicious_probability if anomaly_score not available
    if anomaly == 0.0 and "malicious_probability" in row.index:
        prob = row.get("malicious_probability")
        if pd.notna(prob):
            anomaly = float(prob)

    composite = (
        0.40 * anomaly
        + 0.20 * beacon
        + 0.15 * ja3
        + 0.15 * cert
        + 0.10 * graph
    )
    return round(float(np.clip(composite, 0.0, 1.0)), 4)


def _score_to_severity(score: float) -> str:
    """Map composite score to severity label matching the dashboard thresholds."""
    if score >= 0.90:
        return "CRITICAL"
    if score >= 0.75:
        return "HIGH"
    if score >= 0.60:
        return "MEDIUM"
    if score >= 0.30:
        return "LOW"
    return "CLEAN"


def ingest_to_db(df: pd.DataFrame, db_path: Path) -> None:
    """
    Write scored flows into spectra.db.

    - Every row → flows table
    - Rows with verdict != BENIGN → alerts table
    """
    if not db_path.exists():
        logger.error(
            "Database not found at %s. Make sure spectra.db exists "
            "(run the app at least once to initialise the schema).",
            db_path,
        )
        return

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    now_ts = datetime.now(timezone.utc).timestamp()

    flows_inserted = 0
    alerts_inserted = 0
    skipped = 0

    try:
        for _, row in df.iterrows():
            flow_id = str(uuid.uuid4())
            composite_score = _get_composite_score(row)
            verdict = str(row.get("verdict", "BENIGN"))

            # ── flows table ──────────────────────────────────────────────────
            # status: ACTIVE for anomalies, CLOSED otherwise
            status = "ACTIVE" if verdict not in ("BENIGN",) else "CLOSED"

            # Build tcp_flags string from flag counts
            flags = []
            for flag in ("syn", "ack", "fin", "rst", "psh"):
                col = f"{flag}_count"
                if row.get(col, 0) > 0:
                    flags.append(flag.upper())
            import json as _json2
            flags_dict = {f: True for f in flags}
            tcp_flags_str = _json2.dumps(flags_dict)

            try:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO flows (
                        flow_id, src_ip, dst_ip, src_port, dst_port,
                        protocol, start_time, end_time, duration_ms,
                        packet_count, bytes_total, upload_bytes, download_bytes,
                        status, tcp_flags, created_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        flow_id,
                        str(row.get("src_ip", "")),
                        str(row.get("dst_ip", "")),
                        int(row.get("src_port", 0)),
                        int(row.get("dst_port", 0)),
                        "TCP",
                        now_ts,
                        now_ts + float(row.get("duration_ms", 0)) / 1000.0,
                        float(row.get("duration_ms", 0)),
                        int(row.get("total_packets", 0)),
                        int(row.get("total_bytes", 0)),
                        int(row.get("fwd_bytes", 0)),
                        int(row.get("bwd_bytes", 0)),
                        status,
                        tcp_flags_str,
                        now_ts,
                    ),
                )
                flows_inserted += 1
            except sqlite3.Error as e:
                logger.warning("Flow insert failed: %s", e)
                skipped += 1
                continue

            # ── alerts table — only for non-benign flows ─────────────────────
            if verdict in ("BENIGN",):
                continue

            severity = _score_to_severity(composite_score)
            anomaly_score_val = float(row.get("anomaly_score", composite_score))
            ja3_score_val     = float(row.get("ja3_score", 0.0) or 0.0)
            beacon_score_val  = float(row.get("beacon_score", 0.0) or 0.0)
            cert_score_val    = float(row.get("cert_score", 0.0) or 0.0)
            graph_score_val   = float(row.get("graph_score", 0.0) or 0.0)

            # Build a human-readable findings list
            findings: list[str] = []
            if composite_score >= 0.90:
                findings.append("Extremely high anomaly score — likely malicious")
            elif composite_score >= 0.75:
                findings.append("High anomaly score detected")
            elif composite_score >= 0.60:
                findings.append("Moderate anomaly score detected")
            else:
                findings.append("Low-level anomaly detected")

            if ja3_score_val >= 0.60:
                findings.append(f"Suspicious TLS client fingerprint pattern (JA3 score: {ja3_score_val:.2f})")
            if beacon_score_val >= 0.60:
                findings.append(f"Beaconing behavior detected — periodic C2-like intervals (score: {beacon_score_val:.2f})")
            if cert_score_val >= 0.50:
                findings.append(f"Certificate anomaly proxy triggered — TLS handshake irregularity (score: {cert_score_val:.2f})")
            if graph_score_val >= 0.60:
                findings.append(f"Infrastructure clustering — destination shared across many flows (score: {graph_score_val:.2f})")

            pkt_rate = float(row.get("packet_rate_per_sec", 0))
            if pkt_rate > 1000:
                findings.append(f"High packet rate: {pkt_rate:.0f} pkt/s")

            byte_rate = float(row.get("byte_rate_per_sec", 0))
            if byte_rate > 1_000_000:
                findings.append(f"High byte rate: {byte_rate/1e6:.2f} MB/s")

            rst = int(row.get("rst_count", 0))
            if rst > 5:
                findings.append(f"Excessive RST flags: {rst}")

            syn = int(row.get("syn_count", 0))
            total_pkts = max(int(row.get("total_packets", 1)), 1)
            if syn / total_pkts > 0.5:
                findings.append(f"SYN flood pattern: {syn}/{total_pkts} packets are SYN")

            import json as _json
            findings_str = _json.dumps(findings)

            recommended = {
                "CRITICAL": "Block immediately — isolate source host",
                "HIGH":     "Investigate and consider blocking source IP",
                "MEDIUM":   "Monitor closely — flag for review",
                "LOW":      "Log and monitor",
                "CLEAN":    "No action required",
            }.get(severity, "Review manually")

            try:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO alerts (
                        alert_id, flow_id, timestamp, severity,
                        composite_score, ja3_score, beacon_score,
                        cert_score, graph_score, anomaly_score,
                        src_ip, dst_ip, dst_domain,
                        findings, recommended_action, is_suppressed,
                        created_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        str(uuid.uuid4()),
                        flow_id,
                        now_ts,
                        severity,
                        round(composite_score, 4),
                        round(ja3_score_val, 4),     # ja3_score
                        round(beacon_score_val, 4),  # beacon_score
                        round(cert_score_val, 4),    # cert_score
                        round(graph_score_val, 4),   # graph_score
                        round(anomaly_score_val, 4),
                        str(row.get("src_ip", "")),
                        str(row.get("dst_ip", "")),
                        "",    # dst_domain — not available from PCAP flow
                        findings_str,
                        recommended,
                        0,     # is_suppressed = False
                        now_ts,  # created_at
                    ),
                )
                alerts_inserted += 1
            except sqlite3.Error as e:
                logger.warning("Alert insert failed: %s", e)

        conn.commit()
        logger.info(
            "DB ingestion complete — flows: %d inserted, %d skipped | alerts: %d inserted",
            flows_inserted, skipped, alerts_inserted,
        )

    except Exception as exc:
        conn.rollback()
        logger.error("DB ingestion rolled back due to error: %s", exc)
        raise
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="Score TCP flows using trained model")
    parser.add_argument("--pcap", help="Raw PCAP to extract flows from and score")
    parser.add_argument("--flows", help="Pre-extracted flows CSV to score directly")
    parser.add_argument("--mode", choices=["supervised", "unsupervised"], default="supervised")
    parser.add_argument("--model-dir", default="models/ml")
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--out", default="data/processed/scored_flows.csv")
    parser.add_argument("--db", default="spectra.db",
                        help="Path to spectra.db (default: spectra.db)")
    parser.add_argument("--no-db", action="store_true",
                        help="Skip writing to the database (CSV output only)")
    args = parser.parse_args()

    if not args.pcap and not args.flows:
        logger.error("Provide either --pcap or --flows")
        sys.exit(1)

    if args.pcap:
        sys.path.insert(0, str(Path(__file__).parent))
        from step1_extract_tcp_flows import extract_flows
        df = extract_flows(args.pcap)
    else:
        df = pd.read_csv(args.flows)
        logger.info("Loaded %d flows from %s", len(df), args.flows)

    project_root = Path(args.project_root).resolve()
    model_dir = Path(args.model_dir)

    if args.mode == "supervised":
        df = score_supervised(df, model_dir)
    else:
        df = score_unsupervised(df, project_root)

    # ── Summary ──────────────────────────────────────────────────────────────
    verdict_counts = df["verdict"].value_counts()
    logger.info("\n=== Scoring Results ===")
    for verdict, count in verdict_counts.items():
        logger.info("  %s: %d flows", verdict, count)

    if "malicious_probability" in df.columns:
        top = df.nlargest(10, "malicious_probability")[
            ["src_ip", "src_port", "dst_ip", "dst_port", "total_packets",
             "total_bytes", "malicious_probability", "verdict"]
        ]
    elif "anomaly_score" in df.columns:
        top = df.nlargest(10, "anomaly_score")[
            ["src_ip", "src_port", "dst_ip", "dst_port", "total_packets",
             "total_bytes", "anomaly_score", "verdict"]
        ]
    else:
        top = df.head(10)

    logger.info("\nTop suspicious flows:\n%s", top.to_string(index=False))

    # ── Save CSV ──────────────────────────────────────────────────────────────
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)
    logger.info("\nFull results saved to %s", out_path)

    # ── Ingest to DB ──────────────────────────────────────────────────────────
    if not args.no_db:
        db_path = Path(args.db)
        logger.info("Ingesting results into database: %s", db_path)
        ingest_to_db(df, db_path)
    else:
        logger.info("Skipping DB ingestion (--no-db flag set)")


if __name__ == "__main__":
    main()