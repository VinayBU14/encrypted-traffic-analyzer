"""Alerts router — endpoints to query and manage security alerts."""

from __future__ import annotations

import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from src.api.dependencies import get_db_conn
from src.api.schemas.alert_schema import AlertResponse
from src.storage.repositories import alert_repository

router = APIRouter(prefix="/alerts", tags=["alerts"])

DBConn = Annotated[sqlite3.Connection, Depends(get_db_conn)]


def _alert_to_response(alert) -> dict:
    return {
        "alert_id": alert.alert_id,
        "flow_id": alert.flow_id,
        "timestamp": alert.timestamp,
        "severity": alert.severity,
        "composite_score": alert.composite_score,
        "ja3_score": alert.ja3_score,
        "beacon_score": alert.beacon_score,
        "cert_score": alert.cert_score,
        "graph_score": alert.graph_score,
        "anomaly_score": alert.anomaly_score,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "dst_domain": alert.dst_domain,
        "findings": alert.findings,
        "recommended_action": alert.recommended_action,
        "is_suppressed": alert.is_suppressed,
    }


@router.get("", response_model=list[AlertResponse])
def list_alerts(
    limit: int = Query(default=50, le=500),
    severity: str | None = Query(default=None),
    conn: DBConn = None,
) -> list[dict]:
    """Return recent alerts, optionally filtered by severity."""
    if severity:
        alerts = alert_repository.get_alerts_by_severity(conn, severity.upper())
    else:
        alerts = alert_repository.get_recent_alerts(conn, limit=limit)
    return [_alert_to_response(a) for a in alerts]


@router.get("/stats")
def alert_stats(conn: DBConn = None) -> dict:
    """Return alert counts grouped by severity."""
    return alert_repository.get_alert_counts_by_severity(conn)


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(alert_id: str, conn: DBConn = None) -> dict:
    """Return a single alert by alert_id."""
    alert = alert_repository.get_alert_by_id(conn, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return _alert_to_response(alert)


@router.post("/{alert_id}/suppress")
def suppress_alert(alert_id: str, conn: DBConn = None) -> dict:
    """Suppress an alert by alert_id."""
    alert = alert_repository.get_alert_by_id(conn, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    alert_repository.suppress_alert(conn, alert_id)
    return {"status": "suppressed", "alert_id": alert_id}


@router.get("/src/{src_ip}", response_model=list[AlertResponse])
def get_alerts_by_ip(src_ip: str, conn: DBConn = None) -> list[dict]:
    """Return all alerts for a given source IP."""
    alerts = alert_repository.get_alerts_by_src_ip(conn, src_ip)
    return [_alert_to_response(a) for a in alerts]