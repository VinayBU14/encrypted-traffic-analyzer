"""Flows router — endpoints to query reconstructed network flows."""

from __future__ import annotations

import sqlite3
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query

from src.api.dependencies import get_db_conn
from src.api.schemas.flow_schema import FlowResponse
from src.storage.repositories import flow_repository

router = APIRouter(prefix="/flows", tags=["flows"])
DBConn = Annotated[sqlite3.Connection, Depends(get_db_conn)]


def _flow_to_response(flow) -> dict:
    if isinstance(flow, dict):
        return {
            "flow_id":       flow.get("flow_id", ""),
            "src_ip":        flow.get("src_ip", ""),
            "dst_ip":        flow.get("dst_ip", ""),
            "src_port":      flow.get("src_port", 0),
            "dst_port":      flow.get("dst_port", 0),
            "protocol":      flow.get("protocol", ""),
            "start_time":    flow.get("start_time"),
            "end_time":      flow.get("end_time"),
            "duration_ms":   flow.get("duration_ms"),
            "packet_count":  flow.get("packet_count", 0),
            "bytes_total":   flow.get("bytes_total", 0),
            "upload_bytes":  flow.get("upload_bytes", 0),
            "download_bytes":flow.get("download_bytes", 0),
            "status":        flow.get("status", ""),
            "tcp_flags":     flow.get("tcp_flags", {}),
            "is_live":       flow.get("is_live", 0),
            "severity":      flow.get("severity", ""),
            "composite_score": flow.get("composite_score", 0),
        }
    return {
        "flow_id":       flow.flow_id,
        "src_ip":        flow.src_ip,
        "dst_ip":        flow.dst_ip,
        "src_port":      flow.src_port,
        "dst_port":      flow.dst_port,
        "protocol":      flow.protocol,
        "start_time":    flow.start_time,
        "end_time":      flow.end_time,
        "duration_ms":   flow.duration_ms,
        "packet_count":  flow.packet_count,
        "bytes_total":   flow.bytes_total,
        "upload_bytes":  flow.upload_bytes,
        "download_bytes":flow.download_bytes,
        "status":        flow.status,
        "tcp_flags":     flow.tcp_flags,
        "is_live":       0,
        "severity":      "",
        "composite_score": 0,
    }


def _get_flows_raw(conn: sqlite3.Connection, limit: int = 200,
                   source: str | None = None) -> list[dict[str, Any]]:
    """Direct SQL query so we get all columns including is_live, severity, scores."""
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