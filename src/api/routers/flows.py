"""Flows router — endpoints to query reconstructed network flows."""

from __future__ import annotations

import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from src.api.dependencies import get_db_conn
from src.api.schemas.flow_schema import FlowResponse
from src.storage.repositories import flow_repository

router = APIRouter(prefix="/flows", tags=["flows"])

DBConn = Annotated[sqlite3.Connection, Depends(get_db_conn)]


def _flow_to_response(flow) -> dict:
    return {
        "flow_id": flow.flow_id,
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
        "start_time": flow.start_time,
        "end_time": flow.end_time,
        "duration_ms": flow.duration_ms,
        "packet_count": flow.packet_count,
        "bytes_total": flow.bytes_total,
        "upload_bytes": flow.upload_bytes,
        "download_bytes": flow.download_bytes,
        "status": flow.status,
        "tcp_flags": flow.tcp_flags,
    }


@router.get("", response_model=list[FlowResponse])
def list_flows(
    limit: int = Query(default=50, le=500),
    conn: DBConn = None,
) -> list[dict]:
    """Return the most recent flows ordered by start_time descending."""
    flows = flow_repository.get_recent_flows(conn, limit=limit)
    return [_flow_to_response(f) for f in flows]


@router.get("/{flow_id}", response_model=FlowResponse)
def get_flow(
    flow_id: str,
    conn: DBConn = None,
) -> dict:
    """Return a single flow by flow_id."""
    flow = flow_repository.get_flow_by_id(conn, flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail=f"Flow {flow_id} not found")
    return _flow_to_response(flow)


@router.get("/src/{src_ip}", response_model=list[FlowResponse])
def get_flows_by_src(
    src_ip: str,
    dst_ip: str = Query(..., description="Destination IP to filter by"),
    conn: DBConn = None,
) -> list[dict]:
    """Return flows for a given src/dst IP pair."""
    flows = flow_repository.get_flows_by_src_dst(conn, src_ip, dst_ip)
    return [_flow_to_response(f) for f in flows]