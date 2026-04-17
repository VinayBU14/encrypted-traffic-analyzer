"""Alerts router — endpoints to query and manage security alerts."""

from __future__ import annotations

import sqlite3
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query

from src.analysis.explainer.ai_explainer import AIExplainer
from src.analysis.explainer.rule_explainer import RuleExplainer
from src.api.dependencies import get_db_conn
from src.api.schemas.alert_schema import AlertResponse
from src.storage.repositories import alert_repository, flow_repository, session_repository

router = APIRouter(prefix="/alerts", tags=["alerts"])

DBConn = Annotated[sqlite3.Connection, Depends(get_db_conn)]
_rule_explainer = RuleExplainer()
_ai_explainer = AIExplainer()


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


@router.get("/{alert_id}/explain")
def explain_alert(alert_id: str, conn: DBConn = None) -> dict:
    """Generate AI-powered explanation for a specific alert."""
    _ = (flow_repository, session_repository)
    result: dict[str, Any] = {"alert_id": alert_id, "available": False, "error": None}
    try:
        alert = alert_repository.get_alert_by_id(conn, alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

        alert_dict: dict[str, Any] = {
            "alert_id": alert.alert_id,
            "flow_id": alert.flow_id,
            "severity": alert.severity,
            "composite_score": alert.composite_score,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "dst_domain": alert.dst_domain,
            "findings": alert.findings or [],
            "recommended_action": alert.recommended_action or "",
            "ja3_score": alert.ja3_score or 0.0,
            "cert_score": alert.cert_score or 0.0,
            "beacon_score": alert.beacon_score or 0.0,
            "graph_score": alert.graph_score or 0.0,
            "anomaly_score": alert.anomaly_score or 0.0,
        }

        feature_row: dict[str, Any] = {
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
        }

        ja3_result: dict[str, Any] = {"ja3_score": alert_dict["ja3_score"], "finding": None}
        cert_result: dict[str, Any] = {"cert_score": alert_dict["cert_score"], "findings": []}
        beacon_result: dict[str, Any] = {
            "beacon_score": alert_dict["beacon_score"],
            "finding": None,
            "mean_interval_seconds": 0.0,
        }
        graph_result: dict[str, Any] = {"graph_score": alert_dict["graph_score"], "findings": []}

        for finding in alert_dict["findings"]:
            fl = str(finding).lower()
            if "ja3" in fl:
                ja3_result["finding"] = finding
            elif "cert" in fl or "certificate" in fl or "self-signed" in fl:
                cert_result["findings"].append(finding)
            elif "beacon" in fl or "periodic" in fl or "interval" in fl:
                beacon_result["finding"] = finding
            elif "ip" in fl or "graph" in fl or "infrastructure" in fl or "device" in fl:
                graph_result["findings"].append(finding)

        rule_explanation = _rule_explainer.explain(
            feature_row=feature_row,
            alert=alert_dict,
            ja3_result=ja3_result,
            cert_result=cert_result,
            beacon_result=beacon_result,
            graph_result=graph_result,
        )

        final_explanation = _ai_explainer.explain(rule_explanation)
        final_explanation["available"] = True
        return final_explanation
    except HTTPException:
        raise
    except Exception as exc:
        result["error"] = str(exc)
        result["plain_english"] = "Explanation generation failed — see raw alert data."
        return result


@router.get("/src/{src_ip}", response_model=list[AlertResponse])
def get_alerts_by_ip(src_ip: str, conn: DBConn = None) -> list[dict]:
    """Return all alerts for a given source IP."""
    alerts = alert_repository.get_alerts_by_src_ip(conn, src_ip)
    return [_alert_to_response(a) for a in alerts]


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