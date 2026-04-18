"""Repository functions for alerts table operations."""

from __future__ import annotations

import json
import logging
import sqlite3

from src.storage.models import AlertRecord

logger = logging.getLogger(__name__)


def _row_to_alert(row: sqlite3.Row) -> AlertRecord:
    """
    FIX: Safely read all columns including src_port, dst_port, is_live,
    is_beacon, groq_* which may be absent in older DB rows.
    Use dict access with fallback defaults instead of direct column access
    so KeyError never propagates when an older DB row is returned.
    """
    d = dict(row)
    findings_raw = d.get("findings") or "[]"
    if isinstance(findings_raw, str):
        try:
            findings = json.loads(findings_raw)
        except Exception:
            findings = [findings_raw] if findings_raw else []
    else:
        findings = findings_raw if isinstance(findings_raw, list) else []

    return AlertRecord(
        alert_id=          d.get("alert_id", ""),
        timestamp=         float(d.get("timestamp") or 0),
        severity=          d.get("severity", "LOW"),
        composite_score=   float(d.get("composite_score") or 0),
        src_ip=            d.get("src_ip", ""),
        findings=          findings,
        is_suppressed=     bool(d.get("is_suppressed", 0)),
        created_at=        float(d.get("created_at") or 0),
        flow_id=           d.get("flow_id"),
        ja3_score=         float(d.get("ja3_score") or 0),
        beacon_score=      float(d.get("beacon_score") or 0),
        cert_score=        float(d.get("cert_score") or 0),
        graph_score=       float(d.get("graph_score") or 0),
        anomaly_score=     float(d.get("anomaly_score") or 0),
        dst_domain=        d.get("dst_domain", ""),
        dst_ip=            d.get("dst_ip", ""),
        recommended_action=d.get("recommended_action", ""),
        src_port=          int(d.get("src_port") or 0),
        dst_port=          int(d.get("dst_port") or 0),
        is_live=           int(d.get("is_live") or 0),
        is_beacon=         int(d.get("is_beacon") or 0),
        groq_summary=      d.get("groq_summary", "") or "",
        groq_explanation=  d.get("groq_explanation", "") or "",
        groq_action=       d.get("groq_action", "") or "",
        groq_threat_type=  d.get("groq_threat_type", "") or "",
        groq_confidence=   d.get("groq_confidence", "") or "",
    )


def insert_alert(conn: sqlite3.Connection, alert: AlertRecord) -> None:
    """Insert an alert into the alerts table."""
    conn.execute(
        """
        INSERT OR IGNORE INTO alerts (
            alert_id, flow_id, timestamp, created_at, severity,
            composite_score, anomaly_score, ja3_score, beacon_score,
            cert_score, graph_score,
            src_ip, src_port, dst_ip, dst_port, dst_domain,
            findings, recommended_action,
            is_suppressed, is_live, is_beacon
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert.alert_id,
            alert.flow_id,
            alert.timestamp,
            alert.created_at,
            alert.severity,
            alert.composite_score,
            alert.anomaly_score or 0,
            alert.ja3_score or 0,
            alert.beacon_score or 0,
            alert.cert_score or 0,
            alert.graph_score or 0,
            alert.src_ip,
            alert.src_port or 0,
            alert.dst_ip or "",
            alert.dst_port or 0,
            alert.dst_domain or "",
            json.dumps(alert.findings),
            alert.recommended_action or "",
            int(alert.is_suppressed),
            getattr(alert, "is_live", 0),
            getattr(alert, "is_beacon", 0),
        ),
    )
    conn.commit()
    logger.info("Inserted alert: %s", alert.alert_id)


def get_alert_by_id(conn: sqlite3.Connection, alert_id: str) -> AlertRecord | None:
    """Fetch a single alert by alert_id."""
    row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    if row is None:
        return None
    return _row_to_alert(row)


def get_alerts_by_severity(conn: sqlite3.Connection, severity: str) -> list[AlertRecord]:
    """Return all alerts that match a severity value."""
    rows = conn.execute(
        "SELECT * FROM alerts WHERE severity = ? ORDER BY timestamp DESC",
        (severity,),
    ).fetchall()
    return [_row_to_alert(row) for row in rows]


def get_recent_alerts(conn: sqlite3.Connection, limit: int = 50) -> list[AlertRecord]:
    """Return recent alerts ordered by timestamp descending."""
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [_row_to_alert(row) for row in rows]


def get_alerts_by_src_ip(conn: sqlite3.Connection, src_ip: str) -> list[AlertRecord]:
    """Return all alerts for a source IP ordered by timestamp descending."""
    rows = conn.execute(
        "SELECT * FROM alerts WHERE src_ip = ? ORDER BY timestamp DESC",
        (src_ip,),
    ).fetchall()
    return [_row_to_alert(row) for row in rows]


def suppress_alert(conn: sqlite3.Connection, alert_id: str) -> None:
    """Suppress an alert by setting is_suppressed to 1."""
    conn.execute("UPDATE alerts SET is_suppressed = 1 WHERE alert_id = ?", (alert_id,))
    conn.commit()
    logger.info("Suppressed alert: %s", alert_id)


def get_alert_counts_by_severity(conn: sqlite3.Connection) -> dict[str, int]:
    """Return aggregated alert counts grouped by severity."""
    rows = conn.execute(
        "SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity"
    ).fetchall()
    return {str(row["severity"]): int(row["count"]) for row in rows}