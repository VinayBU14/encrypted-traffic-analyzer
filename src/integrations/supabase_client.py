"""
src/integrations/supabase_client.py
Mirrors HIGH and CRITICAL alerts to Supabase.

Setup:
    pip install supabase python-dotenv

.env (project root):
    SUPABASE_URL=https://your-project.supabase.co
    SUPABASE_KEY=your-service-role-key

Run this SQL once in Supabase SQL editor:
--------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    alert_id            TEXT PRIMARY KEY,
    flow_id             TEXT,
    timestamp           FLOAT,
    severity            TEXT,
    composite_score     FLOAT,
    ja3_score           FLOAT,
    beacon_score        FLOAT,
    cert_score          FLOAT,
    graph_score         FLOAT,
    anomaly_score       FLOAT,
    src_ip              TEXT,
    src_port            INTEGER DEFAULT 0,
    dst_ip              TEXT,
    dst_port            INTEGER DEFAULT 0,
    dst_domain          TEXT,
    findings            TEXT,
    recommended_action  TEXT,
    is_suppressed       INTEGER DEFAULT 0,
    is_live             INTEGER DEFAULT 0,
    is_beacon           INTEGER DEFAULT 0,
    groq_summary        TEXT,
    groq_explanation    TEXT,
    groq_action         TEXT,
    groq_threat_type    TEXT,
    groq_confidence     TEXT,
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_is_live   ON alerts (is_live);
--------------------------------------------------------------

Fixes vs previous version:
  - Uses 'timestamp' column (float) which matches unified schema in init_db.py
  - src_port is now included in the payload (was missing before)
  - is_beacon included in payload
  - _serialise is safe for None values
  - bulk_mirror_from_sqlite falls back to created_at if timestamp missing
"""

from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

_client = None

MIRROR_SEVERITIES = {"HIGH", "CRITICAL"}


def is_configured() -> bool:
    return bool(SUPABASE_URL and SUPABASE_KEY)


def _get_client():
    global _client
    if _client:
        return _client
    if not is_configured():
        raise EnvironmentError("SUPABASE_URL and SUPABASE_KEY not set in .env")
    try:
        from supabase import create_client
        _client = create_client(SUPABASE_URL, SUPABASE_KEY)
        return _client
    except ImportError:
        raise ImportError("supabase not installed. Run: pip install supabase")


def _build_payload(alert: dict) -> dict:
    """Build the Supabase upsert payload from an alert dict."""
    return {
        "alert_id":           str(alert.get("alert_id", "")),
        "flow_id":            str(alert.get("flow_id", "")),
        "timestamp":          alert.get("timestamp") or alert.get("created_at"),
        "severity":           alert.get("severity"),
        "composite_score":    float(alert.get("composite_score", 0)),
        "ja3_score":          float(alert.get("ja3_score", 0)),
        "beacon_score":       float(alert.get("beacon_score", 0)),
        "cert_score":         float(alert.get("cert_score", 0)),
        "graph_score":        float(alert.get("graph_score", 0)),
        "anomaly_score":      float(alert.get("anomaly_score", 0)),
        "src_ip":             alert.get("src_ip", ""),
        "src_port":           int(alert.get("src_port", 0)),
        "dst_ip":             alert.get("dst_ip", ""),
        "dst_port":           int(alert.get("dst_port", 0)),
        "dst_domain":         alert.get("dst_domain", ""),
        "findings":           _serialise(alert.get("findings", [])),
        "recommended_action": alert.get("recommended_action", ""),
        "is_suppressed":      int(alert.get("is_suppressed", 0)),
        "is_live":            int(alert.get("is_live", 0)),
        "is_beacon":          int(alert.get("is_beacon", 0)),
    }


def mirror_alert_any_severity(alert: dict) -> Optional[dict]:
    """
    Upsert any alert to Supabase regardless of severity.
    This ensures every generated alert_id is recorded.
    """
    if not is_configured():
        return None
    if not alert.get("alert_id"):
        return None
    try:
        payload = _build_payload(alert)
        client = _get_client()
        resp = client.table("alerts").upsert(payload, on_conflict="alert_id").execute()
        logger.debug("Supabase mirror OK: %s (%s)", alert["alert_id"], alert.get("severity"))
        return resp.data
    except Exception as e:
        logger.warning("Supabase mirror failed for %s: %s", alert.get("alert_id"), e)
        return None


def mirror_alert(alert: dict) -> Optional[dict]:
    """
    Upsert a single alert to Supabase.
    Only processes HIGH and CRITICAL — silently skips others.
    """
    if alert.get("severity") not in MIRROR_SEVERITIES:
        return None
    if not is_configured():
        return None

    try:
        payload = _build_payload(alert)
        client = _get_client()
        resp = client.table("alerts").upsert(payload, on_conflict="alert_id").execute()
        logger.debug("Supabase mirror OK: %s (%s)", alert["alert_id"], alert.get("severity"))
        return resp.data
    except Exception as e:
        logger.warning("Supabase mirror failed for %s: %s", alert.get("alert_id"), e)
        return None


def patch_groq_fields(alert_id: str, groq_data: dict) -> Optional[dict]:
    """Write Groq analysis results back to the Supabase row."""
    if not is_configured():
        return None
    try:
        client = _get_client()
        resp = (
            client.table("alerts")
            .update({
                "groq_summary":     groq_data.get("summary", ""),
                "groq_explanation": groq_data.get("explanation", ""),
                "groq_action":      groq_data.get("action", ""),
                "groq_threat_type": groq_data.get("threat_type", ""),
                "groq_confidence":  groq_data.get("confidence", ""),
            })
            .eq("alert_id", alert_id)
            .execute()
        )
        return resp.data
    except Exception as e:
        logger.warning("Supabase groq patch failed for %s: %s", alert_id, e)
        return None


def bulk_mirror_from_sqlite(db_path: str = "data/spectra.db", limit: int = 500) -> int:
    """
    One-shot backfill: push existing HIGH/CRITICAL alerts from SQLite → Supabase.
    """
    import sqlite3
    if not is_configured():
        print("Supabase not configured. Set SUPABASE_URL and SUPABASE_KEY in .env")
        return 0

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    # Find the right timestamp column to sort by
    cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    order_col = "timestamp" if "timestamp" in cols else "created_at"

    rows = conn.execute(
        f"SELECT * FROM alerts WHERE severity IN ('HIGH','CRITICAL') "
        f"ORDER BY {order_col} DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()

    count = 0
    for row in rows:
        if mirror_alert(dict(row)):
            count += 1
    print(f"Bulk mirror: {count}/{len(rows)} alerts sent to Supabase")
    return count


def _serialise(value) -> str:
    import json
    if value is None:
        return "[]"
    if isinstance(value, str):
        return value
    return json.dumps(value)


if __name__ == "__main__":
    print(f"Configured: {is_configured()}")
    if is_configured():
        bulk_mirror_from_sqlite()