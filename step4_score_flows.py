"""
Step 4 — Score new TCP flows using the trained model.

Usage:
    python step4_score_flows.py --pcap data/raw/pcap/real_traffic.pcap --mode unsupervised --db data/spectra.db
    python step4_score_flows.py --flows data/processed/tcp_flows.csv --mode unsupervised --db data/spectra.db
    python step4_score_flows.py --pcap data/raw/pcap/real_traffic.pcap --no-db
"""

from __future__ import annotations

import argparse
import hashlib
import json as _json
import logging
import sqlite3
import sys
import time
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


# ── Alert ID helpers ──────────────────────────────────────────────────────────

def make_alert_id(src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str) -> str:
    raw = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def make_beacon_alert_id(src_ip: str, dst_ip: str, dst_port: int) -> str:
    epoch_minute = int(time.time() // 60)
    raw = f"beacon:{src_ip}:{dst_ip}:{dst_port}:{epoch_minute}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ── Feature engineering ───────────────────────────────────────────────────────

def compute_scoring_features(df: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame(index=df.index)
    mean_iat = df["mean_iat_ms"].replace(0, np.nan)
    out["regularity_score"]    = (1.0 - (df["std_iat_ms"] / mean_iat).clip(0, 1)).fillna(0.0)
    total                      = df["total_bytes"].replace(0, 1)
    ratio                      = (df["fwd_bytes"] / total).clip(0, 1)
    out["payload_consistency"] = 1.0 - (ratio - 0.5).abs() * 2
    out["cert_age_normalized"] = 0.0
    out["tls_version_encoded"] = 0.0
    out["bytes_per_second"]    = df["byte_rate_per_sec"].fillna(0.0)
    out["packet_rate"]         = df["packet_rate_per_sec"].fillna(0.0)
    return out


def compute_module_scores(df: pd.DataFrame) -> pd.DataFrame:
    result = df.copy()

    # JA3 Score
    is_tls_port     = result["dst_port"].isin([443, 8443, 993, 995, 465]).astype(float)
    pkt_rate        = result["packet_rate_per_sec"].fillna(0.0)
    pkt_rate_anomaly = (
        ((pkt_rate < 1.0) & (pkt_rate > 0.0)).astype(float) * 0.6
        + (pkt_rate > 500.0).astype(float) * 0.8
    ).clip(0, 1)
    mean_iat   = result["mean_iat_ms"].replace(0, np.nan)
    std_iat    = result["std_iat_ms"].fillna(0.0)
    iat_cv     = (std_iat / mean_iat).fillna(0.0).clip(0, 5) / 5.0
    automated  = (is_tls_port * (1.0 - iat_cv.clip(0, 1))).clip(0, 1)
    result["ja3_score"] = (
        0.4 * pkt_rate_anomaly
        + 0.4 * automated
        + 0.2 * is_tls_port * (result["syn_count"].fillna(0) > 3).astype(float)
    ).clip(0, 1).round(4)

    # Beacon Score
    regularity   = (1.0 - (std_iat / mean_iat).clip(0, 1)).fillna(0.0)
    small_pkts   = (result["avg_packet_size"].fillna(0) < 200).astype(float)
    low_volume   = (result["total_bytes"].fillna(0) < 5000).astype(float)
    duration_sec = (result["duration_ms"].fillna(0) / 1000.0).replace(0, np.nan)
    high_density = (result["total_packets"].fillna(0) / duration_sec).fillna(0).clip(0, 100) / 100.0
    result["beacon_score"] = (
        0.45 * regularity + 0.25 * small_pkts + 0.20 * low_volume + 0.10 * high_density
    ).clip(0, 1).round(4)

    # Certificate Risk Score
    non_std_tls = (~result["dst_port"].isin([443, 8443])).astype(float) * 0.5
    rst_ratio   = (result["rst_count"].fillna(0) / result["total_packets"].replace(0, 1)).clip(0, 1)
    fin_ratio   = (result["fin_count"].fillna(0) / result["total_packets"].replace(0, 1)).clip(0, 1)
    very_short  = (result["duration_ms"].fillna(0) < 500).astype(float)
    tls_failure = (very_short * rst_ratio).clip(0, 1)
    result["cert_score"] = (
        0.35 * non_std_tls + 0.35 * tls_failure + 0.20 * rst_ratio + 0.10 * fin_ratio
    ).clip(0, 1).round(4)

    # Graph Proximity Score
    dst_ip_counts = result["dst_ip"].map(result["dst_ip"].value_counts())
    dst_freq      = (dst_ip_counts / dst_ip_counts.max().clip(min=1)).clip(0, 1).fillna(0.0)
    src_fan_out   = result["src_ip"].map(result["dst_ip"].groupby(result["src_ip"]).nunique())
    max_fan       = src_fan_out.max() if src_fan_out.max() > 0 else 1
    fan_score     = (src_fan_out / max_fan).clip(0, 1).fillna(0.0)
    result["graph_score"] = (0.60 * dst_freq + 0.40 * fan_score).clip(0, 1).round(4)

    return result


def score_supervised(df: pd.DataFrame, model_dir: Path) -> pd.DataFrame:
    model_path = model_dir / "rf_flow_classifier.joblib"
    if not model_path.exists():
        logger.error("Model not found at %s", model_path)
        sys.exit(1)
    clf = joblib.load(model_path)
    X   = df[FLOW_FEATURE_COLUMNS].replace([np.inf, -np.inf], 0).fillna(0)
    df["prediction"]          = clf.predict(X)
    df["malicious_probability"] = clf.predict_proba(X)[:, 1]
    df["verdict"]             = df["prediction"].map({0: "BENIGN", 1: "MALICIOUS"})
    df = compute_module_scores(df)
    return df


def score_unsupervised(df: pd.DataFrame, project_root: Path) -> pd.DataFrame:
    model_path  = project_root / "models" / "isolation_forest.joblib"
    scaler_path = project_root / "models" / "scaler.joblib"
    if not model_path.exists():
        logger.error("IsolationForest model not found at %s", model_path)
        sys.exit(1)
    model  = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    feats  = compute_scoring_features(df)
    X      = feats[SCORING_FEATURE_COLUMNS].replace([np.inf, -np.inf], 0).fillna(0)
    X_sc   = scaler.transform(X)
    raw    = model.score_samples(X_sc)
    anomaly_scores = np.clip(-raw * 2.0, 0, 1)
    df["anomaly_score"] = anomaly_scores.round(4)
    df["prediction"]    = (anomaly_scores >= 0.70).astype(int)
    df["verdict"]       = df["prediction"].map({0: "BENIGN", 1: "ANOMALY"})
    df = compute_module_scores(df)
    return df


def _get_composite_score(row: pd.Series) -> float:
    anomaly = float(row.get("anomaly_score", 0.0) or 0.0)
    ja3     = float(row.get("ja3_score", 0.0) or 0.0)
    beacon  = float(row.get("beacon_score", 0.0) or 0.0)
    cert    = float(row.get("cert_score", 0.0) or 0.0)
    graph   = float(row.get("graph_score", 0.0) or 0.0)
    if anomaly == 0.0 and "malicious_probability" in row.index:
        prob = row.get("malicious_probability")
        if pd.notna(prob):
            anomaly = float(prob)
    composite = 0.40*anomaly + 0.20*beacon + 0.15*ja3 + 0.15*cert + 0.10*graph
    return round(float(np.clip(composite, 0.0, 1.0)), 4)


def _score_to_severity(score: float) -> str:
    if score >= 0.90: return "CRITICAL"
    if score >= 0.75: return "HIGH"
    if score >= 0.60: return "MEDIUM"
    if score >= 0.30: return "LOW"
    return "CLEAN"


# ── Supabase + Groq hooks ─────────────────────────────────────────────────────

def _mirror_to_supabase(alert_dict: dict) -> None:
    try:
        from src.integrations.supabase_client import mirror_alert
        mirror_alert(alert_dict)
    except Exception as e:
        logger.debug("Supabase mirror skipped: %s", e)


def _run_groq_analysis(alert_dict: dict, db_path: Path) -> None:
    import threading
    def _worker():
        try:
            from src.integrations.groq_client import analyse_and_store
            analyse_and_store(alert_dict, str(db_path))
        except Exception as e:
            logger.debug("Groq analysis skipped: %s", e)
    threading.Thread(target=_worker, daemon=True).start()


# ── DB helpers ────────────────────────────────────────────────────────────────

def _ensure_schema(db_path: Path) -> None:
    """
    Ensure spectra.db exists with the full unified schema.
    Replaces the old 'if not db_path.exists(): return' guard that caused
    'no such table: alerts' errors.
    """
    from init_db import init_db
    init_db(str(db_path))


def _ensure_groq_columns(conn: sqlite3.Connection) -> None:
    existing = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    for col, t in [
        ("groq_summary","TEXT"), ("groq_explanation","TEXT"),
        ("groq_action","TEXT"),  ("groq_threat_type","TEXT"),
        ("groq_confidence","TEXT"),
    ]:
        if col not in existing:
            conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} {t}")
            logger.info("Added column %s to alerts", col)
    conn.commit()


def _alert_insert_sql() -> str:
    return """
        INSERT INTO alerts (
            alert_id, flow_id, timestamp, created_at, severity,
            composite_score, ja3_score, beacon_score, cert_score, graph_score, anomaly_score,
            src_ip, dst_ip, dst_domain,
            findings, recommended_action,
            is_suppressed, is_live, is_beacon
        ) VALUES (?,?,?,?,?, ?,?,?,?,?,?, ?,?,?, ?,?, ?,?,?)
    """


def _alert_params(
    alert_id, flow_id, now_ts, severity, composite_score,
    ja3_score_val, beacon_score_val, cert_score_val, graph_score_val, anomaly_score_val,
    src_ip, dst_ip, findings_str, recommended, is_beacon=0,
) -> tuple:
    return (
        alert_id, flow_id, now_ts, now_ts, severity,
        round(composite_score, 4), round(ja3_score_val, 4), round(beacon_score_val, 4),
        round(cert_score_val, 4), round(graph_score_val, 4), round(anomaly_score_val, 4),
        src_ip, dst_ip, "",
        findings_str, recommended,
        0, 0, int(is_beacon),   # is_live=0 for PCAP flows
    )


# ── Main ingestion ────────────────────────────────────────────────────────────

def ingest_to_db(df: pd.DataFrame, db_path: Path) -> None:
    """
    Write scored flows into spectra.db.
    - Always creates/migrates the schema first (no more 'no such table' errors).
    - Uses unified column names from init_db.py.
    - Upserts alerts with deterministic IDs; beacon alerts always INSERT.
    - Fires Supabase mirror + Groq analysis for HIGH/CRITICAL alerts.
    """
    # ── Ensure schema exists (key fix) ────────────────────────────────────────
    _ensure_schema(db_path)

    conn = sqlite3.connect(str(db_path), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    now_ts = datetime.now(timezone.utc).timestamp()

    _ensure_groq_columns(conn)

    flows_inserted = alerts_inserted = alerts_updated = skipped = 0

    try:
        for _, row in df.iterrows():
            composite_score = _get_composite_score(row)
            verdict         = str(row.get("verdict", "BENIGN"))

            src_ip   = str(row.get("src_ip", ""))
            dst_ip   = str(row.get("dst_ip", ""))
            src_port = int(row.get("src_port", 0))
            dst_port = int(row.get("dst_port", 0))

            flags_dict = {}
            for flag in ("syn", "ack", "fin", "rst", "psh"):
                col = f"{flag}_count"
                if row.get(col, 0) > 0:
                    flags_dict[flag.upper()] = True
            tcp_flags_str = _json.dumps(flags_dict)

            flow_id = hashlib.sha256(
                f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-TCP".encode()
            ).hexdigest()[:32]

            dur_ms  = float(row.get("duration_ms", 0))
            dur_s   = dur_ms / 1000.0

            try:
                conn.execute("""
                    INSERT OR IGNORE INTO flows (
                        flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
                        start_time, end_time, duration_ms,
                        packet_count, bytes_total, upload_bytes, download_bytes,
                        packet_rate_per_sec, byte_rate_per_sec, avg_packet_size,
                        tcp_flags, syn_count, rst_count, fin_count,
                        composite_score, anomaly_score, ja3_score, beacon_score,
                        cert_score, graph_score,
                        status, verdict, severity, source, is_live, created_at
                    ) VALUES (?,?,?,?,?,?, ?,?,?, ?,?,?,?, ?,?,?, ?,?,?,?, ?,?,?,?,?,?,
                              ?,?,?,?,?,?)""",
                    (
                        flow_id, src_ip, dst_ip, src_port, dst_port, "TCP",
                        now_ts, now_ts + dur_s, dur_ms,
                        int(row.get("total_packets", 0)),
                        int(row.get("total_bytes", 0)),
                        int(row.get("fwd_bytes", 0)),
                        int(row.get("bwd_bytes", 0)),
                        float(row.get("packet_rate_per_sec", 0)),
                        float(row.get("byte_rate_per_sec", 0)),
                        float(row.get("avg_packet_size", 0)),
                        tcp_flags_str,
                        int(row.get("syn_count", 0)),
                        int(row.get("rst_count", 0)),
                        int(row.get("fin_count", 0)),
                        round(composite_score, 4),
                        round(float(row.get("anomaly_score", 0) or 0), 4),
                        round(float(row.get("ja3_score",     0) or 0), 4),
                        round(float(row.get("beacon_score",  0) or 0), 4),
                        round(float(row.get("cert_score",    0) or 0), 4),
                        round(float(row.get("graph_score",   0) or 0), 4),
                        "ACTIVE" if verdict != "BENIGN" else "CLOSED",
                        verdict,
                        _score_to_severity(composite_score),
                        "pcap", 0, now_ts,
                    ),
                )
                flows_inserted += 1
            except sqlite3.Error as e:
                logger.warning("Flow insert failed: %s", e)
                skipped += 1
                continue

            if verdict in ("BENIGN", "CLEAN"):
                continue

            # ── Alert ─────────────────────────────────────────────────────────
            severity          = _score_to_severity(composite_score)
            anomaly_score_val = float(row.get("anomaly_score", composite_score) or 0)
            ja3_score_val     = float(row.get("ja3_score",    0) or 0)
            beacon_score_val  = float(row.get("beacon_score", 0) or 0)
            cert_score_val    = float(row.get("cert_score",   0) or 0)
            graph_score_val   = float(row.get("graph_score",  0) or 0)

            findings: list[str] = []
            if composite_score >= 0.90:   findings.append("Extremely high anomaly score — likely malicious")
            elif composite_score >= 0.75: findings.append("High anomaly score detected")
            elif composite_score >= 0.60: findings.append("Moderate anomaly score detected")
            else:                         findings.append("Low-level anomaly detected")
            if ja3_score_val   >= 0.60: findings.append(f"Suspicious TLS fingerprint (JA3={ja3_score_val:.2f})")
            if beacon_score_val >= 0.60: findings.append(f"Beaconing detected (beacon={beacon_score_val:.2f})")
            if cert_score_val  >= 0.50: findings.append(f"Certificate anomaly (cert={cert_score_val:.2f})")
            if graph_score_val >= 0.60: findings.append(f"Infrastructure clustering (graph={graph_score_val:.2f})")

            pkt_rate = float(row.get("packet_rate_per_sec", 0))
            if pkt_rate > 1000:
                findings.append(f"High packet rate: {pkt_rate:.0f} pkt/s")
            rst = int(row.get("rst_count", 0))
            if rst > 5:
                findings.append(f"Excessive RST flags: {rst}")
            syn = int(row.get("syn_count", 0))
            total_pkts = max(int(row.get("total_packets", 1)), 1)
            if syn / total_pkts > 0.5:
                findings.append(f"SYN flood pattern: {syn}/{total_pkts}")

            findings_str = _json.dumps(findings)
            recommended  = {
                "CRITICAL": "Block immediately — isolate source host",
                "HIGH":     "Investigate and consider blocking source IP",
                "MEDIUM":   "Monitor closely — flag for review",
                "LOW":      "Log and monitor",
                "CLEAN":    "No action required",
            }.get(severity, "Review manually")

            is_beacon = beacon_score_val >= 0.60 and severity in ("HIGH", "CRITICAL")
            alert_id  = make_beacon_alert_id(src_ip, dst_ip, dst_port) if is_beacon \
                        else make_alert_id(src_ip, src_port, dst_ip, dst_port, "TCP")

            try:
                if is_beacon:
                    conn.execute(
                        _alert_insert_sql(),
                        _alert_params(
                            alert_id, flow_id, now_ts, severity, composite_score,
                            ja3_score_val, beacon_score_val, cert_score_val,
                            graph_score_val, anomaly_score_val,
                            src_ip, dst_ip, findings_str, recommended, is_beacon=1,
                        ),
                    )
                    alerts_inserted += 1
                else:
                    existing = conn.execute(
                        "SELECT alert_id FROM alerts WHERE alert_id=?", (alert_id,)
                    ).fetchone()
                    if existing:
                        conn.execute("""
                            UPDATE alerts SET
                                composite_score=?, severity=?, ja3_score=?, beacon_score=?,
                                cert_score=?, graph_score=?, anomaly_score=?,
                                findings=?, recommended_action=?, timestamp=?
                            WHERE alert_id=?""",
                            (round(composite_score,4), severity,
                             round(ja3_score_val,4), round(beacon_score_val,4),
                             round(cert_score_val,4), round(graph_score_val,4),
                             round(anomaly_score_val,4),
                             findings_str, recommended, now_ts, alert_id))
                        alerts_updated += 1
                    else:
                        conn.execute(
                            _alert_insert_sql(),
                            _alert_params(
                                alert_id, flow_id, now_ts, severity, composite_score,
                                ja3_score_val, beacon_score_val, cert_score_val,
                                graph_score_val, anomaly_score_val,
                                src_ip, dst_ip, findings_str, recommended,
                            ),
                        )
                        alerts_inserted += 1

                if severity in ("HIGH", "CRITICAL"):
                    alert_dict = {
                        "alert_id": alert_id, "flow_id": flow_id,
                        "severity": severity,
                        "composite_score": round(composite_score, 4),
                        "anomaly_score":   round(anomaly_score_val, 4),
                        "ja3_score":       round(ja3_score_val, 4),
                        "beacon_score":    round(beacon_score_val, 4),
                        "cert_score":      round(cert_score_val, 4),
                        "graph_score":     round(graph_score_val, 4),
                        "src_ip": src_ip, "src_port": src_port,
                        "dst_ip": dst_ip, "dst_port": dst_port,
                        "findings": findings,
                        "recommended_action": recommended,
                        "timestamp": now_ts,
                        "is_suppressed": 0,
                        "is_live": 0,
                    }
                    _mirror_to_supabase(alert_dict)
                    _run_groq_analysis(alert_dict, db_path)

            except sqlite3.Error as e:
                logger.warning("Alert upsert failed: %s", e)

        conn.commit()
        logger.info(
            "DB ingestion done — flows: %d inserted, %d skipped | alerts: %d inserted, %d updated",
            flows_inserted, skipped, alerts_inserted, alerts_updated,
        )
    except Exception as exc:
        conn.rollback()
        logger.error("DB ingestion rolled back: %s", exc)
        raise
    finally:
        conn.close()


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Score TCP flows using trained model")
    parser.add_argument("--pcap")
    parser.add_argument("--flows")
    parser.add_argument("--mode", choices=["supervised", "unsupervised"], default="supervised")
    parser.add_argument("--model-dir", default="models/ml")
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--out", default="data/processed/scored_flows.csv")
    parser.add_argument("--db",  default="data/spectra.db")
    parser.add_argument("--no-db", action="store_true")
    args = parser.parse_args()

    if not args.pcap and not args.flows:
        logger.error("Provide either --pcap or --flows"); sys.exit(1)

    if args.pcap:
        sys.path.insert(0, str(Path(__file__).parent))
        from step1_extract_tcp_flows import extract_flows
        df = extract_flows(args.pcap)
    else:
        df = pd.read_csv(args.flows)
        logger.info("Loaded %d flows from %s", len(df), args.flows)

    project_root = Path(args.project_root).resolve()
    model_dir    = Path(args.model_dir)

    if args.mode == "supervised":
        df = score_supervised(df, model_dir)
    else:
        df = score_unsupervised(df, project_root)

    verdict_counts = df["verdict"].value_counts()
    logger.info("=== Scoring Results ===")
    for v, c in verdict_counts.items():
        logger.info("  %s: %d flows", v, c)

    if "malicious_probability" in df.columns:
        top = df.nlargest(10, "malicious_probability")[
            ["src_ip","src_port","dst_ip","dst_port","total_packets","total_bytes","malicious_probability","verdict"]
        ]
    elif "anomaly_score" in df.columns:
        top = df.nlargest(10, "anomaly_score")[
            ["src_ip","src_port","dst_ip","dst_port","total_packets","total_bytes","anomaly_score","verdict"]
        ]
    else:
        top = df.head(10)
    logger.info("Top suspicious flows:\n%s", top.to_string(index=False))

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)
    logger.info("Results saved to %s", out_path)

    if not args.no_db:
        db_path = Path(args.db)
        logger.info("Ingesting into %s", db_path)
        ingest_to_db(df, db_path)
    else:
        logger.info("Skipping DB ingestion (--no-db)")


if __name__ == "__main__":
    main()