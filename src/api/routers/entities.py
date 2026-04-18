"""Entities router — graph node queries for the infrastructure view."""

from __future__ import annotations

import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from src.api.dependencies import get_db_conn
from src.api.schemas.entity_schema import GraphResponse
from src.graph.builder import GraphBuilder
from src.graph.serializer import GraphSerializer
from src.storage.repositories import flow_repository, session_repository

router = APIRouter(prefix="/entities", tags=["entities"])

DBConn = Annotated[sqlite3.Connection, Depends(get_db_conn)]


def _get_flows_for_graph(conn, limit: int, source: str | None):
    """Get flows filtered by source for graph building."""
    import sqlite3 as _sq
    cols = {r[1] for r in conn.execute("PRAGMA table_info(flows)").fetchall()}
    has_is_live = "is_live" in cols
    order = "start_time" if "start_time" in cols else "created_at"
    if source == "live" and has_is_live:
        where = "WHERE is_live=1"
    elif source == "pcap" and has_is_live:
        where = "WHERE (is_live=0 OR is_live IS NULL)"
    else:
        where = ""
    rows = conn.execute(
        f"SELECT * FROM flows {where} ORDER BY {order} DESC LIMIT ?", (limit,)
    ).fetchall()
    # Convert to FlowRecord-compatible objects using the repository helper
    return flow_repository.get_recent_flows(conn, limit=limit) if not where else [
        type('R', (), dict(r))() for r in rows
    ]


@router.get("/graph", response_model=GraphResponse)
def get_graph(
    limit: int = Query(default=1000, le=5000),
    source: str | None = Query(default=None, description="'live' or 'pcap'"),
    conn: DBConn = None,
) -> dict:
    """Return the infrastructure graph, optionally filtered to live or PCAP flows."""
    import sqlite3 as _sq
    cols = {r[1] for r in conn.execute("PRAGMA table_info(flows)").fetchall()}
    has_is_live = "is_live" in cols
    order = "start_time" if "start_time" in cols else "created_at"
    if source == "live" and has_is_live:
        where = "WHERE is_live=1"
    elif source == "pcap" and has_is_live:
        where = "WHERE (is_live=0 OR is_live IS NULL)"
    else:
        where = ""
    if where:
        rows = conn.execute(
            f"SELECT * FROM flows {where} ORDER BY {order} DESC LIMIT ?", (limit,)
        ).fetchall()
        flows = [dict(r) for r in rows]
        # Build minimal FlowRecord-like objects
        from src.storage.models import FlowRecord
        import json as _json
        flow_objs = []
        for fw in flows:
            try:
                flow_objs.append(FlowRecord(
                    flow_id=fw.get("flow_id",""), src_ip=fw.get("src_ip",""),
                    dst_ip=fw.get("dst_ip",""), src_port=fw.get("src_port",0),
                    dst_port=fw.get("dst_port",0), protocol=fw.get("protocol","TCP"),
                    start_time=fw.get("start_time",0), packet_count=fw.get("packet_count",0),
                    bytes_total=fw.get("bytes_total",0), upload_bytes=fw.get("upload_bytes",0),
                    download_bytes=fw.get("download_bytes",0),
                    packet_sizes=_json.loads(fw["packet_sizes"]) if fw.get("packet_sizes") else [],
                    inter_arrival_ms=_json.loads(fw["inter_arrival_ms"]) if fw.get("inter_arrival_ms") else [],
                    tcp_flags=_json.loads(fw["tcp_flags"]) if fw.get("tcp_flags") else {},
                    created_at=fw.get("created_at",0), end_time=fw.get("end_time"),
                    duration_ms=fw.get("duration_ms"), status=fw.get("status","ACTIVE"),
                ))
            except Exception:
                pass
    else:
        flow_objs = flow_repository.get_recent_flows(conn, limit=limit)
    sessions = session_repository.get_recent_sessions(conn, limit=limit)
    builder = GraphBuilder()
    serializer = GraphSerializer()
    graph = builder.build(flow_objs, sessions)
    return serializer.to_dict(graph)


@router.get("/high-risk")
def get_high_risk_nodes(
    threshold: float = Query(default=0.30, ge=0.0, le=1.0),
    limit: int = Query(default=1000, le=5000),
    source: str | None = Query(default=None, description="'live' or 'pcap'"),
    conn: DBConn = None,
) -> list[dict]:
    """Return graph nodes with risk score above the given threshold."""
    flows = flow_repository.get_recent_flows(conn, limit=limit)
    sessions = session_repository.get_recent_sessions(conn, limit=limit)
    builder = GraphBuilder()
    serializer = GraphSerializer()
    graph = builder.build(flows, sessions)
    return serializer.get_high_risk_nodes(graph, threshold=threshold)