"""
Debug ingestion — runs one row at a time with full error output.
Place in project root and run: python debug_ingest.py
"""
import sqlite3
import uuid
import pandas as pd
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = "data/spectra.db"
CSV_PATH = "data/processed/scored_flows.csv"

print("=== Schema Inspection ===")
conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row

# Print full schema for flows and alerts
for table in ("flows", "alerts"):
    print(f"\n--- {table} ---")
    schema = conn.execute(f"SELECT sql FROM sqlite_master WHERE name='{table}'").fetchone()
    print(schema[0])

print("\n=== Loading CSV ===")
df = pd.read_csv(CSV_PATH)
print(f"Rows: {len(df)}, Columns: {list(df.columns)}")

print("\n=== Test inserting first ANOMALY row into flows ===")
row = df[df["verdict"] != "BENIGN"].iloc[0]
print("Row data:", row.to_dict())

now_ts = datetime.now(timezone.utc).timestamp()
flow_id = str(uuid.uuid4())

# Try minimal insert first — just required fields
try:
    conn.execute("""
        INSERT INTO flows (flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
                           start_time, end_time, duration_ms, packet_count,
                           bytes_total, upload_bytes, download_bytes, status, tcp_flags)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
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
        "ACTIVE",
        "",
    ))
    conn.commit()
    count = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
    print(f"SUCCESS — flows table now has {count} rows")
except Exception as e:
    print(f"FAILED — {type(e).__name__}: {e}")
    conn.rollback()

print("\n=== Test inserting alert row ===")
composite_score = float(row.get("anomaly_score", 0.5))
try:
    conn.execute("""
        INSERT INTO alerts (alert_id, flow_id, timestamp, severity,
                            composite_score, ja3_score, beacon_score,
                            cert_score, graph_score, anomaly_score,
                            src_ip, dst_ip, dst_domain,
                            findings, recommended_action, is_suppressed)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        str(uuid.uuid4()),
        flow_id,
        now_ts,
        "HIGH",
        round(composite_score, 4),
        0.0, 0.0, 0.0, 0.0,
        round(composite_score, 4),
        str(row.get("src_ip", "")),
        str(row.get("dst_ip", "")),
        "",
        "Test finding",
        "Investigate",
        0,
    ))
    conn.commit()
    count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    print(f"SUCCESS — alerts table now has {count} rows")
except Exception as e:
    print(f"FAILED — {type(e).__name__}: {e}")
    conn.rollback()

conn.close()