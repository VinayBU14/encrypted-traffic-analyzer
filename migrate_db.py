"""
migrate_db.py
Run this ONCE from the project root to add missing columns to your live spectra.db.

Usage:
    python migrate_db.py

It is safe to run multiple times — uses IF NOT EXISTS logic.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
DB_PATH = os.getenv("SPECTRA_DB", str(PROJECT_ROOT / "data" / "spectra.db"))


def migrate(db_path: str) -> None:
    print(f"Migrating: {db_path}")
    if not Path(db_path).exists():
        print(f"  ERROR: Database file not found at {db_path}")
        return

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")

    # ── alerts table ──────────────────────────────────────────────────────────
    existing_alert_cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    alert_additions = [
        ("dst_port",  "INTEGER DEFAULT 0"),
        ("is_live",   "INTEGER DEFAULT 0"),
    ]
    for col, defn in alert_additions:
        if col not in existing_alert_cols:
            conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} {defn}")
            print(f"  + alerts.{col} ({defn})")
        else:
            print(f"  ✓ alerts.{col} already exists")

    # ── flows table ───────────────────────────────────────────────────────────
    existing_flow_cols = {r[1] for r in conn.execute("PRAGMA table_info(flows)").fetchall()}
    flow_additions = [
        ("is_live",          "INTEGER DEFAULT 0"),
        ("source",           "TEXT DEFAULT 'pcap'"),
        ("severity",         "TEXT"),
        ("verdict",          "TEXT"),
        ("composite_score",  "REAL DEFAULT 0"),
        ("anomaly_score",    "REAL DEFAULT 0"),
        ("ja3_score",        "REAL DEFAULT 0"),
        ("beacon_score",     "REAL DEFAULT 0"),
        ("cert_score",       "REAL DEFAULT 0"),
        ("graph_score",      "REAL DEFAULT 0"),
    ]
    for col, defn in flow_additions:
        if col not in existing_flow_cols:
            conn.execute(f"ALTER TABLE flows ADD COLUMN {col} {defn}")
            print(f"  + flows.{col} ({defn})")
        else:
            print(f"  ✓ flows.{col} already exists")

    conn.commit()
    conn.close()
    print("Migration complete.")


if __name__ == "__main__":
    migrate(DB_PATH)