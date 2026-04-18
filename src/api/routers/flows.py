"""Flows router — endpoints to query reconstructed network flows."""

from __future__ import annotations

import json
import sqlite3
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query

from src.api.dependencies import get_db_conn
from src.api.schemas.flow_schema import FlowResponse
from src.storage.repositories import flow_repository

router = APIRouter(prefix="/flows", tags=["flows"])
DBConn = Annotated[sqlite3.Connection, Depends(get_db_conn)]


def _s(v: Any, default: str = "") -> str:
    """Return string, replacing None with default."""
    return default if v is None else str(v)

def _f(v: Any, default: float = 0.0) -> float:
    """Return float, replacing None with default."""
    return default if v is None else float(v)

def _i(v: Any, default: int = 0) -> int:
    """Return int, replacing None with default."""
    return default if v is None else int(v)


def _parse_tcp_flags(value: Any) -> dict:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except (json.JSONDecodeError, ValueError):
            return {}
    return {}


def _flow_to_response(flow) -> dict:
    if isinstance(flow, dict):
        return {
            "flow_id":         _s(flow.get("flow_id")),
            "src_ip":          _s(flow.get("src_ip")),
            "dst_ip":          _s(flow.get("dst_ip")),
            "src_port":        _i(flow.get("src_port")),
            "dst_port":        _i(flow.get("dst_port")),
            "protocol":        _s(flow.get("protocol"), "TCP"),
            "start_time":      _f(flow.get("start_time")),
            "end_time":        flow.get("end_time"),
            "duration_ms":     flow.get("duration_ms"),
            "packet_count":    _i(flow.get("packet_count")),
            "bytes_total":     _i(flow.get("bytes_total")),
            "upload_bytes":    _i(flow.get("upload_bytes")),
            "download_bytes":  _i(flow.get("download_bytes")),
            "status":          _s(flow.get("status"), "CLOSED"),
            "tcp_flags":       _parse_tcp_flags(flow.get("tcp_flags", {})),
            "is_live":         _i(flow.get("is_live")),
            "severity":        _s(flow.get("severity"), "CLEAN"),
            "composite_score": _f(flow.get("composite_score")),
            "anomaly_score":   _f(flow.get("anomaly_score")),
            "ja3_score":       _f(flow.get("ja3_score")),
            "beacon_score":    _f(flow.get("beacon_score")),
            "cert_score":      _f(flow.get("cert_score")),
            "graph_score":     _f(flow.get("graph_score")),
            "verdict":         _s(flow.get("verdict"), "BENIGN"),
            "source":          _s(flow.get("source"), "pcap"),
        }
    # AlertRecord / ORM object
    return {
        "flow_id":         _s(getattr(flow, "flow_id", None)),
        "src_ip":          _s(getattr(flow, "src_ip", None)),
        "dst_ip":          _s(getattr(flow, "dst_ip", None)),
        "src_port":        _i(getattr(flow, "src_port", 0)),
        "dst_port":        _i(getattr(flow, "dst_port", 0)),
        "protocol":        _s(getattr(flow, "protocol", None), "TCP"),
        "start_time":      _f(getattr(flow, "start_time", 0)),
        "end_time":        getattr(flow, "end_time", None),
        "duration_ms":     getattr(flow, "duration_ms", None),
        "packet_count":    _i(getattr(flow, "packet_count", 0)),
        "bytes_total":     _i(getattr(flow, "bytes_total", 0)),
        "upload_bytes":    _i(getattr(flow, "upload_bytes", 0)),
        "download_bytes":  _i(getattr(flow, "download_bytes", 0)),
        "status":          _s(getattr(flow, "status", None), "CLOSED"),
        "tcp_flags":       _parse_tcp_flags(getattr(flow, "tcp_flags", {})),
        "is_live":         0,
        "severity":        "CLEAN",
        "composite_score": 0.0,
        "anomaly_score":   0.0,
        "ja3_score":       0.0,
        "beacon_score":    0.0,
        "cert_score":      0.0,
        "graph_score":     0.0,
        "verdict":         "BENIGN",
        "source":          "pcap",
    }


def _get_flows_raw(conn: sqlite3.Connection, limit: int = 200,
                   source: str | None = None) -> list[dict[str, Any]]:
    cols      = {r[1] for r in conn.execute("PRAGMA table_info(flows)").fetchall()}
    order_col = "start_time" if "start_time" in cols else "created_at"
    has_is_live = "is_live" in cols

    if source == "live" and has_is_live:
        where = "WHERE is_live=1"
    elif source == "pcap" and has_is_live:
        where = "WHERE (is_live=0 OR is_live IS NULL)"
    else:
        where = ""

    rows = conn.execute(
        f"SELECT * FROM flows {where} ORDER BY {order_col} DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


@router.get("", response_model=list[FlowResponse])
def list_flows(
    limit:  int          = Query(default=50, le=500),
    source: str | None   = Query(default=None, description="'live' or 'pcap'"),
    conn:   DBConn       = None,
) -> list[dict]:
    return [_flow_to_response(f) for f in _get_flows_raw(conn, limit=limit, source=source)]


@router.get("/{flow_id}", response_model=FlowResponse)
def get_flow(flow_id: str, conn: DBConn = None) -> dict:
    flow = flow_repository.get_flow_by_id(conn, flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail=f"Flow {flow_id} not found")
    return _flow_to_response(flow)


@router.get("/src/{src_ip}", response_model=list[FlowResponse])
def get_flows_by_src(
    src_ip: str,
    dst_ip: str = Query(...),
    conn:   DBConn = None,
) -> list[dict]:
    flows = flow_repository.get_flows_by_src_dst(conn, src_ip, dst_ip)
    return [_flow_to_response(f) for f in flows]