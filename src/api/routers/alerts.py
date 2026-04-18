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
_ai_explainer   = AIExplainer()


def _row_to_dict(conn: sqlite3.Connection, alert_id: str) -> dict:
    """
    Read a raw row from the alerts table and return a full dict including
    all columns — src_port, dst_port, is_live, is_beacon, groq_* fields.
    This avoids the AlertRecord dataclass silently dropping new columns.
    """
    row = conn.execute("SELECT * FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
    if row is None:
        return {}
    return dict(row)


def _alert_to_response(alert) -> dict:
    """Convert AlertRecord to response dict. Also accepts a plain dict."""
    if isinstance(alert, dict):
        return {
            "alert_id":          alert.get("alert_id", ""),
            "flow_id":           alert.get("flow_id"),
            "timestamp":         alert.get("timestamp"),
            "severity":          alert.get("severity", ""),
            "composite_score":   alert.get("composite_score", 0),
            "ja3_score":         alert.get("ja3_score", 0),
            "beacon_score":      alert.get("beacon_score", 0),
            "cert_score":        alert.get("cert_score", 0),
            "graph_score":       alert.get("graph_score", 0),
            "anomaly_score":     alert.get("anomaly_score", 0),
            "src_ip":            alert.get("src_ip", ""),
            "src_port":          alert.get("src_port", 0),
            "dst_ip":            alert.get("dst_ip", ""),
            "dst_port":          alert.get("dst_port", 0),
            "dst_domain":        alert.get("dst_domain", ""),
            "findings":          alert.get("findings", []),
            "recommended_action":alert.get("recommended_action", ""),
            "is_suppressed":     alert.get("is_suppressed", 0),
            "is_live":           alert.get("is_live", 0),
            "is_beacon":         alert.get("is_beacon", 0),
            "groq_summary":      alert.get("groq_summary", ""),
            "groq_explanation":  alert.get("groq_explanation", ""),
            "groq_action":       alert.get("groq_action", ""),
            "groq_threat_type":  alert.get("groq_threat_type", ""),
            "groq_confidence":   alert.get("groq_confidence", ""),
        }
    # AlertRecord dataclass
    return {
        "alert_id":          alert.alert_id,
        "flow_id":           alert.flow_id,
        "timestamp":         alert.timestamp,
        "severity":          alert.severity,
        "composite_score":   alert.composite_score,
        "ja3_score":         alert.ja3_score,
        "beacon_score":      alert.beacon_score,
        "cert_score":        alert.cert_score,
        "graph_score":       alert.graph_score,
        "anomaly_score":     alert.anomaly_score,
        "src_ip":            alert.src_ip,
        "src_port":          getattr(alert, "src_port", 0),
        "dst_ip":            alert.dst_ip,
        "dst_port":          getattr(alert, "dst_port", 0),
        "dst_domain":        alert.dst_domain,
        "findings":          alert.findings,
        "recommended_action":alert.recommended_action,
        "is_suppressed":     alert.is_suppressed,
        "is_live":           getattr(alert, "is_live", 0),
        "is_beacon":         getattr(alert, "is_beacon", 0),
        "groq_summary":      "",
        "groq_explanation":  "",
        "groq_action":       "",
        "groq_threat_type":  "",
        "groq_confidence":   "",
    }


def _get_alerts_raw(conn: sqlite3.Connection, limit: int = 200,
                    severity: str | None = None, source: str | None = None) -> list[dict]:
    """
    Query alerts directly so we get ALL columns, including src_port, dst_port,
    is_live, is_beacon, groq_* fields that AlertRecord doesn't expose.
    """
    cols      = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    order_col = "timestamp" if "timestamp" in cols else "created_at"

    conditions = []
    params: list[Any] = []

    if severity:
        conditions.append("severity = ?")
        params.append(severity.upper())

    if source == "live" and "is_live" in cols:
        conditions.append("is_live = 1")
    elif source == "pcap" and "is_live" in cols:
        conditions.append("(is_live = 0 OR is_live IS NULL)")

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params.append(limit)

    rows = conn.execute(
        f"SELECT * FROM alerts {where} ORDER BY {order_col} DESC LIMIT ?",
        params,
    ).fetchall()

    import json
    result = []
    for row in rows:
        d = dict(row)
        # Parse findings JSON string → list
        findings = d.get("findings", "[]")
        if isinstance(findings, str):
            try:
                d["findings"] = json.loads(findings)
            except Exception:
                d["findings"] = [findings] if findings else []
        result.append(d)
    return result


@router.get("", response_model=list[AlertResponse])
def list_alerts(
    limit:    int          = Query(default=50, le=500),
    severity: str | None   = Query(default=None),
    source:   str | None   = Query(default=None, description="'live' or 'pcap' to filter by source"),
    conn:     DBConn       = None,
) -> list[dict]:
    """Return recent alerts, optionally filtered by severity and/or source."""
    return _get_alerts_raw(conn, limit=limit, severity=severity, source=source)


@router.get("/stats")
def alert_stats(
    source: str | None = Query(default=None, description="'live' or 'pcap'"),
    conn:   DBConn     = None,
) -> dict:
    """Return alert counts grouped by severity, optionally filtered by source."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    has_is_live = "is_live" in cols

    if source == "live" and has_is_live:
        where = "WHERE is_live=1"
    elif source == "pcap" and has_is_live:
        where = "WHERE (is_live=0 OR is_live IS NULL)"
    else:
        where = ""

    rows = conn.execute(
        f"SELECT severity, COUNT(*) AS count FROM alerts {where} GROUP BY severity"
    ).fetchall()
    return {str(row["severity"]): int(row["count"]) for row in rows}


@router.get("/{alert_id}/explain")
def explain_alert(alert_id: str, conn: DBConn = None) -> dict:
    """Generate AI-powered explanation for a specific alert."""
    result: dict[str, Any] = {"alert_id": alert_id, "available": False, "error": None}
    try:
        alert = alert_repository.get_alert_by_id(conn, alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

        # Also fetch raw row to get src_port, dst_port, groq fields
        raw_row = _row_to_dict(conn, alert_id)

        alert_dict: dict[str, Any] = {
            "alert_id":           alert.alert_id,
            "flow_id":            alert.flow_id,
            "severity":           alert.severity,
            "composite_score":    alert.composite_score,
            "src_ip":             alert.src_ip,
            "src_port":           raw_row.get("src_port", 0),
            "dst_ip":             alert.dst_ip,
            "dst_port":           raw_row.get("dst_port", 0),
            "dst_domain":         alert.dst_domain,
            "findings":           alert.findings or [],
            "recommended_action": alert.recommended_action or "",
            "ja3_score":          alert.ja3_score or 0.0,
            "cert_score":         alert.cert_score or 0.0,
            "beacon_score":       alert.beacon_score or 0.0,
            "graph_score":        alert.graph_score or 0.0,
            "anomaly_score":      alert.anomaly_score or 0.0,
            "is_live":            raw_row.get("is_live", 0),
        }

        feature_row: dict[str, Any] = {"src_ip": alert.src_ip, "dst_ip": alert.dst_ip}
        ja3_result    = {"ja3_score": alert_dict["ja3_score"],    "finding": None}
        cert_result   = {"cert_score": alert_dict["cert_score"],   "findings": []}
        beacon_result = {"beacon_score": alert_dict["beacon_score"], "finding": None, "mean_interval_seconds": 0.0}
        graph_result  = {"graph_score": alert_dict["graph_score"],  "findings": []}

        for finding in alert_dict["findings"]:
            fl = str(finding).lower()
            if "ja3" in fl:
                ja3_result["finding"] = finding
            elif any(k in fl for k in ("cert", "certificate", "self-signed")):
                cert_result["findings"].append(finding)
            elif any(k in fl for k in ("beacon", "periodic", "interval")):
                beacon_result["finding"] = finding
            elif any(k in fl for k in ("ip", "graph", "infrastructure", "device")):
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
    alerts = alert_repository.get_alerts_by_src_ip(conn, src_ip)
    return [_alert_to_response(a) for a in alerts]


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(alert_id: str, conn: DBConn = None) -> dict:
    # Use raw query to get all columns
    d = _row_to_dict(conn, alert_id)
    if not d:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    # Parse findings
    import json
    findings = d.get("findings", "[]")
    if isinstance(findings, str):
        try:   d["findings"] = json.loads(findings)
        except: d["findings"] = [findings] if findings else []
    return _alert_to_response(d)


@router.post("/{alert_id}/suppress")
def suppress_alert(alert_id: str, conn: DBConn = None) -> dict:
    alert = alert_repository.get_alert_by_id(conn, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    alert_repository.suppress_alert(conn, alert_id)
    return {"status": "suppressed", "alert_id": alert_id}