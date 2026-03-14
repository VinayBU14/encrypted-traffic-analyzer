
"""Repository functions for alerts table operations."""

from __future__ import annotations

import json
import logging
import sqlite3

from src.storage.models import AlertRecord

logger = logging.getLogger(__name__)


def _row_to_alert(row: sqlite3.Row) -> AlertRecord:
    findings = json.loads(row["findings"]) if row["findings"] else []
    return AlertRecord(
        alert_id=row["alert_id"],
        timestamp=row["timestamp"],
        severity=row["severity"],
        composite_score=row["composite_score"],
        src_ip=row["src_ip"],
        findings=findings,
        is_suppressed=bool(row["is_suppressed"]),
        created_at=row["created_at"],
        flow_id=row["flow_id"],
        ja3_score=row["ja3_score"],
        beacon_score=row["beacon_score"],
        cert_score=row["cert_score"],
        graph_score=row["graph_score"],
        anomaly_score=row["anomaly_score"],
        dst_domain=row["dst_domain"],
        dst_ip=row["dst_ip"],
        recommended_action=row["recommended_action"],
    )


def insert_alert(conn: sqlite3.Connection, alert: AlertRecord) -> None:
    """Insert an alert into the alerts table."""
    conn.execute(
        """
        INSERT INTO alerts (
            alert_id, flow_id, timestamp, severity, composite_score,
            ja3_score, beacon_score, cert_score, graph_score, anomaly_score,
            src_ip, dst_domain, dst_ip, findings, recommended_action,
            is_suppressed, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert.alert_id,
            alert.flow_id,
            alert.timestamp,
            alert.severity,
            alert.composite_score,
            alert.ja3_score,
            alert.beacon_score,
            alert.cert_score,
            alert.graph_score,
            alert.anomaly_score,
            alert.src_ip,
            alert.dst_domain,
            alert.dst_ip,
            json.dumps(alert.findings),
            alert.recommended_action,
            int(alert.is_suppressed),
            alert.created_at,
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
