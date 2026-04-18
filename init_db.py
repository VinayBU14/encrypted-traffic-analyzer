"""
init_db.py
==========
Run this ONCE before starting the API or pipeline to create / migrate spectra.db.

Usage:
    python init_db.py                        # creates data/spectra.db
    python init_db.py --db spectra.db        # creates spectra.db in project root
    python init_db.py --db data/spectra.db   # (default)

Safe to run multiple times — all statements use IF NOT EXISTS / ADD COLUMN guards.
"""

from __future__ import annotations

import argparse
import sqlite3
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("spectra.init_db")

# ── Full unified schema ───────────────────────────────────────────────────────
SCHEMA = """
-- ────────────────────────────────────────────────────────────────────────────
-- flows
-- Stores every reconstructed network flow (both PCAP pipeline and live capture)
-- ────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS flows (
    flow_id           TEXT    PRIMARY KEY,
    src_ip            TEXT    NOT NULL DEFAULT '',
    dst_ip            TEXT    NOT NULL DEFAULT '',
    src_port          INTEGER NOT NULL DEFAULT 0,
    dst_port          INTEGER NOT NULL DEFAULT 0,
    protocol          TEXT    NOT NULL DEFAULT 'TCP',

    -- timing
    start_time        REAL    DEFAULT 0,
    end_time          REAL    DEFAULT 0,
    duration_ms       REAL    DEFAULT 0,

    -- volume
    packet_count      INTEGER DEFAULT 0,
    bytes_total       INTEGER DEFAULT 0,
    upload_bytes      INTEGER DEFAULT 0,
    download_bytes    INTEGER DEFAULT 0,

    -- rates (computed, useful for dashboard queries)
    packet_rate_per_sec REAL  DEFAULT 0,
    byte_rate_per_sec   REAL  DEFAULT 0,
    avg_packet_size     REAL  DEFAULT 0,

    -- TCP flags
    tcp_flags         TEXT    DEFAULT '{}',
    syn_count         INTEGER DEFAULT 0,
    ack_count         INTEGER DEFAULT 0,
    fin_count         INTEGER DEFAULT 0,
    rst_count         INTEGER DEFAULT 0,
    psh_count         INTEGER DEFAULT 0,

    -- TLS
    is_tls            INTEGER DEFAULT 0,
    tls_version       TEXT    DEFAULT '',
    cipher            TEXT    DEFAULT '',
    ja3               TEXT    DEFAULT '',

    -- scores (written by scoring pipeline and live capture)
    composite_score   REAL    DEFAULT 0,
    anomaly_score     REAL    DEFAULT 0,
    ja3_score         REAL    DEFAULT 0,
    beacon_score      REAL    DEFAULT 0,
    cert_score        REAL    DEFAULT 0,
    graph_score       REAL    DEFAULT 0,

    -- metadata
    status            TEXT    DEFAULT 'CLOSED',
    verdict           TEXT    DEFAULT 'BENIGN',
    severity          TEXT    DEFAULT 'CLEAN',
    source            TEXT    DEFAULT 'pcap',
    is_live           INTEGER DEFAULT 0,

    created_at        REAL    DEFAULT 0
);

-- ────────────────────────────────────────────────────────────────────────────
-- alerts
-- One row per (flow, alert_type) pair.  Beacon alerts can have multiple rows.
-- ────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    alert_id            TEXT    PRIMARY KEY,
    flow_id             TEXT    NOT NULL DEFAULT '',

    -- timing
    timestamp           REAL    DEFAULT 0,
    created_at          REAL    DEFAULT 0,

    severity            TEXT    DEFAULT 'LOW',

    -- scores
    composite_score     REAL    DEFAULT 0,
    anomaly_score       REAL    DEFAULT 0,
    ja3_score           REAL    DEFAULT 0,
    beacon_score        REAL    DEFAULT 0,
    cert_score          REAL    DEFAULT 0,
    graph_score         REAL    DEFAULT 0,

    -- network details
    src_ip              TEXT    DEFAULT '',
    src_port            INTEGER DEFAULT 0,
    dst_ip              TEXT    DEFAULT '',
    dst_port            INTEGER DEFAULT 0,
    dst_domain          TEXT    DEFAULT '',

    -- human-readable detail
    findings            TEXT    DEFAULT '[]',
    recommended_action  TEXT    DEFAULT '',

    -- flags
    is_suppressed       INTEGER DEFAULT 0,
    is_live             INTEGER DEFAULT 0,
    is_beacon           INTEGER DEFAULT 0,

    -- Groq AI analysis (populated asynchronously)
    groq_summary        TEXT    DEFAULT '',
    groq_explanation    TEXT    DEFAULT '',
    groq_action         TEXT    DEFAULT '',
    groq_threat_type    TEXT    DEFAULT '',
    groq_confidence     TEXT    DEFAULT '',

    FOREIGN KEY (flow_id) REFERENCES flows(flow_id)
);

-- ────────────────────────────────────────────────────────────────────────────
-- tls_sessions
-- ────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tls_sessions (
    session_id        TEXT PRIMARY KEY,
    flow_id           TEXT,
    tls_version       TEXT,
    cipher_suite      TEXT,
    server_name       TEXT,
    cert_fingerprint  TEXT,
    cert_issuer       TEXT,
    cert_subject      TEXT,
    cert_not_before   TEXT,
    cert_not_after    TEXT,
    ja3_hash          TEXT,
    created_at        REAL DEFAULT 0
);

-- ────────────────────────────────────────────────────────────────────────────
-- graph_entities
-- ────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS graph_entities (
    entity_id    TEXT PRIMARY KEY,
    entity_type  TEXT,
    value        TEXT,
    risk_score   REAL DEFAULT 0,
    first_seen   REAL DEFAULT 0,
    last_seen    REAL DEFAULT 0,
    metadata     TEXT DEFAULT '{}'
);

-- ────────────────────────────────────────────────────────────────────────────
-- live_capture_status  (single-row control table)
-- ────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS live_capture_status (
    id               INTEGER PRIMARY KEY CHECK (id = 1),
    is_running       INTEGER DEFAULT 0,
    interface        TEXT    DEFAULT '',
    bpf_filter       TEXT    DEFAULT '',
    packets_captured INTEGER DEFAULT 0,
    tls_packets      INTEGER DEFAULT 0,
    bytes_seen       INTEGER DEFAULT 0,
    active_flows     INTEGER DEFAULT 0,
    started_at       REAL    DEFAULT 0,
    updated_at       REAL    DEFAULT 0
);
INSERT OR IGNORE INTO live_capture_status (id) VALUES (1);

-- ────────────────────────────────────────────────────────────────────────────
-- indices
-- ────────────────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_flows_src_ip      ON flows  (src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_dst_ip      ON flows  (dst_ip);
CREATE INDEX IF NOT EXISTS idx_flows_is_live     ON flows  (is_live);
CREATE INDEX IF NOT EXISTS idx_flows_created     ON flows  (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp  ON alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_flow       ON alerts (flow_id);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip     ON alerts (src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_is_live    ON alerts (is_live);
CREATE INDEX IF NOT EXISTS idx_alerts_severity   ON alerts (severity);
"""

# Columns to ADD if they're missing (for existing databases — migration)
MIGRATION_COLUMNS = [
    # table,    column,               type,       default
    # flows — scoring fields
    ("flows",   "composite_score",    "REAL",     "0"),
    ("flows",   "anomaly_score",      "REAL",     "0"),
    ("flows",   "ja3_score",          "REAL",     "0"),
    ("flows",   "beacon_score",       "REAL",     "0"),
    ("flows",   "cert_score",         "REAL",     "0"),
    ("flows",   "graph_score",        "REAL",     "0"),
    ("flows",   "verdict",            "TEXT",     "'BENIGN'"),
    ("flows",   "severity",           "TEXT",     "'CLEAN'"),
    ("flows",   "source",             "TEXT",     "'pcap'"),
    ("flows",   "is_live",            "INTEGER",  "0"),
    # flows — rate/size fields
    ("flows",   "packet_rate_per_sec","REAL",     "0"),
    ("flows",   "byte_rate_per_sec",  "REAL",     "0"),
    ("flows",   "avg_packet_size",    "REAL",     "0"),
    # flows — TLS fields
    ("flows",   "is_tls",             "INTEGER",  "0"),
    ("flows",   "tls_version",        "TEXT",     "''"),
    ("flows",   "cipher",             "TEXT",     "''"),
    ("flows",   "ja3",                "TEXT",     "''"),
    # flows — TCP flag counts
    ("flows",   "syn_count",          "INTEGER",  "0"),
    ("flows",   "ack_count",          "INTEGER",  "0"),
    ("flows",   "fin_count",          "INTEGER",  "0"),
    ("flows",   "rst_count",          "INTEGER",  "0"),
    ("flows",   "psh_count",          "INTEGER",  "0"),

    # alerts — missing fields that caused 0-values in the dashboard
    ("alerts",  "created_at",         "REAL",     "0"),
    ("alerts",  "anomaly_score",       "REAL",     "0"),
    ("alerts",  "src_port",           "INTEGER",  "0"),
    ("alerts",  "dst_ip",             "TEXT",     "''"),
    ("alerts",  "dst_port",           "INTEGER",  "0"),
    ("alerts",  "is_live",            "INTEGER",  "0"),
    ("alerts",  "is_beacon",          "INTEGER",  "0"),
    ("alerts",  "groq_summary",       "TEXT",     "''"),
    ("alerts",  "groq_explanation",   "TEXT",     "''"),
    ("alerts",  "groq_action",        "TEXT",     "''"),
    ("alerts",  "groq_threat_type",   "TEXT",     "''"),
    ("alerts",  "groq_confidence",    "TEXT",     "''"),
]


def init_db(db_path: str = "data/spectra.db") -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=15)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    # Create all tables
    conn.executescript(SCHEMA)

    # Migrate existing tables (add missing columns)
    existing_cols: dict[str, set] = {}
    for table in ("flows", "alerts", "tls_sessions", "graph_entities", "live_capture_status"):
        try:
            rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
            existing_cols[table] = {r[1] for r in rows}
        except Exception:
            existing_cols[table] = set()

    added = 0
    for table, col, col_type, default in MIGRATION_COLUMNS:
        if col not in existing_cols.get(table, set()):
            try:
                conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN {col} {col_type} DEFAULT {default}"
                )
                log.info("Migrated: added %s.%s", table, col)
                added += 1
            except sqlite3.OperationalError as e:
                log.debug("Skip %s.%s: %s", table, col, e)

    conn.commit()
    conn.close()
    log.info("Database ready at %s  (migrated %d column(s))", db_path, added)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="data/spectra.db")
    args = parser.parse_args()
    init_db(args.db)
    print(f"Done — {args.db} is ready.")