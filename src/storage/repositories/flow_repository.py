
"""Repository functions for flows table operations."""

from __future__ import annotations

import json
import logging
import sqlite3

from src.storage.models import FlowRecord

logger = logging.getLogger(__name__)


def _row_to_flow(row: sqlite3.Row) -> FlowRecord:
    packet_sizes = json.loads(row["packet_sizes"]) if row["packet_sizes"] else []
    inter_arrival_ms = json.loads(row["inter_arrival_ms"]) if row["inter_arrival_ms"] else []
    tcp_flags = json.loads(row["tcp_flags"]) if row["tcp_flags"] else {}
    return FlowRecord(
        flow_id=row["flow_id"],
        src_ip=row["src_ip"],
        dst_ip=row["dst_ip"],
        src_port=row["src_port"],
        dst_port=row["dst_port"],
        protocol=row["protocol"],
        start_time=row["start_time"],
        packet_count=row["packet_count"],
        bytes_total=row["bytes_total"],
        upload_bytes=row["upload_bytes"],
        download_bytes=row["download_bytes"],
        packet_sizes=packet_sizes,
        inter_arrival_ms=inter_arrival_ms,
        tcp_flags=tcp_flags,
        created_at=row["created_at"],
        end_time=row["end_time"],
        duration_ms=row["duration_ms"],
        status=row["status"],
    )


def insert_flow(conn: sqlite3.Connection, flow: FlowRecord) -> None:
    """Insert a flow record into the flows table."""
    conn.execute(
        """
        INSERT INTO flows (
            flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
            start_time, end_time, duration_ms, packet_count, bytes_total,
            upload_bytes, download_bytes, packet_sizes, inter_arrival_ms,
            tcp_flags, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            flow.flow_id,
            flow.src_ip,
            flow.dst_ip,
            flow.src_port,
            flow.dst_port,
            flow.protocol,
            flow.start_time,
            flow.end_time,
            flow.duration_ms,
            flow.packet_count,
            flow.bytes_total,
            flow.upload_bytes,
            flow.download_bytes,
            json.dumps(flow.packet_sizes),
            json.dumps(flow.inter_arrival_ms),
            json.dumps(flow.tcp_flags),
            flow.status,
            flow.created_at,
        ),
    )
    conn.commit()
    logger.info("Inserted flow: %s", flow.flow_id)


def get_flow_by_id(conn: sqlite3.Connection, flow_id: str) -> FlowRecord | None:
    """Fetch a single flow by flow_id."""
    row = conn.execute("SELECT * FROM flows WHERE flow_id = ?", (flow_id,)).fetchone()
    if row is None:
        return None
    return _row_to_flow(row)


def get_flows_by_src_dst(conn: sqlite3.Connection, src_ip: str, dst_ip: str) -> list[FlowRecord]:
    """Return flows for a src/dst pair ordered by start_time ascending."""
    rows = conn.execute(
        """
        SELECT * FROM flows
        WHERE src_ip = ? AND dst_ip = ?
        ORDER BY start_time ASC
        """,
        (src_ip, dst_ip),
    ).fetchall()
    return [_row_to_flow(row) for row in rows]


def get_active_flows(conn: sqlite3.Connection) -> list[FlowRecord]:
    """Return all active flows."""
    rows = conn.execute("SELECT * FROM flows WHERE status = 'ACTIVE'").fetchall()
    return [_row_to_flow(row) for row in rows]


def update_flow_status(conn: sqlite3.Connection, flow_id: str, status: str) -> None:
    """Update status for a flow record."""
    conn.execute("UPDATE flows SET status = ? WHERE flow_id = ?", (status, flow_id))
    conn.commit()
    logger.info("Updated flow status: flow_id=%s status=%s", flow_id, status)


def get_recent_flows(conn: sqlite3.Connection, limit: int = 100) -> list[FlowRecord]:
    """Return most recent flows ordered by start_time descending."""
    rows = conn.execute(
        "SELECT * FROM flows ORDER BY start_time DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [_row_to_flow(row) for row in rows]
