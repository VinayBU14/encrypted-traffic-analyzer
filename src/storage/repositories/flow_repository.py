"""Repository functions for flows table operations."""

from __future__ import annotations

import json
import logging
import sqlite3

from src.storage.models import FlowRecord

logger = logging.getLogger(__name__)


def _row_to_flow(row: sqlite3.Row) -> FlowRecord:
    """
    FIX: Safely read all columns using dict access with defaults.
    Previously used direct column name access which raised KeyError when
    is_live, composite_score, severity and other new columns were absent.
    """
    d = dict(row)

    # Parse JSON list fields safely
    def _parse_list(val) -> list:
        if not val:
            return []
        if isinstance(val, list):
            return val
        try:
            return json.loads(val)
        except Exception:
            return []

    def _parse_dict(val) -> dict:
        if not val:
            return {}
        if isinstance(val, dict):
            return val
        try:
            return json.loads(val)
        except Exception:
            return {}

    return FlowRecord(
        flow_id=             d.get("flow_id", ""),
        src_ip=              d.get("src_ip", ""),
        dst_ip=              d.get("dst_ip", ""),
        src_port=            int(d.get("src_port") or 0),
        dst_port=            int(d.get("dst_port") or 0),
        protocol=            d.get("protocol", "TCP"),
        start_time=          float(d.get("start_time") or 0),
        packet_count=        int(d.get("packet_count") or 0),
        bytes_total=         int(d.get("bytes_total") or 0),
        upload_bytes=        int(d.get("upload_bytes") or 0),
        download_bytes=      int(d.get("download_bytes") or 0),
        packet_sizes=        _parse_list(d.get("packet_sizes")),
        inter_arrival_ms=    _parse_list(d.get("inter_arrival_ms")),
        tcp_flags=           _parse_dict(d.get("tcp_flags")),
        created_at=          float(d.get("created_at") or 0),
        end_time=            float(d.get("end_time")) if d.get("end_time") is not None else None,
        duration_ms=         float(d.get("duration_ms")) if d.get("duration_ms") is not None else None,
        status=              d.get("status", "CLOSED"),
        composite_score=     float(d.get("composite_score") or 0),
        anomaly_score=       float(d.get("anomaly_score") or 0),
        ja3_score=           float(d.get("ja3_score") or 0),
        beacon_score=        float(d.get("beacon_score") or 0),
        cert_score=          float(d.get("cert_score") or 0),
        graph_score=         float(d.get("graph_score") or 0),
        verdict=             d.get("verdict", "BENIGN"),
        severity=            d.get("severity", "CLEAN"),
        source=              d.get("source", "pcap"),
        is_live=             int(d.get("is_live") or 0),
        packet_rate_per_sec= float(d.get("packet_rate_per_sec") or 0),
        byte_rate_per_sec=   float(d.get("byte_rate_per_sec") or 0),
        avg_packet_size=     float(d.get("avg_packet_size") or 0),
        syn_count=           int(d.get("syn_count") or 0),
        rst_count=           int(d.get("rst_count") or 0),
        fin_count=           int(d.get("fin_count") or 0),
        ack_count=           int(d.get("ack_count") or 0),
        psh_count=           int(d.get("psh_count") or 0),
    )


def insert_flow(conn: sqlite3.Connection, flow: FlowRecord) -> None:
    """Insert a flow record into the flows table."""
    conn.execute(
        """
        INSERT OR IGNORE INTO flows (
            flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
            start_time, end_time, duration_ms, packet_count, bytes_total,
            upload_bytes, download_bytes, packet_sizes, inter_arrival_ms,
            tcp_flags, status, created_at,
            composite_score, anomaly_score, ja3_score, beacon_score,
            cert_score, graph_score, verdict, severity, source, is_live,
            packet_rate_per_sec, byte_rate_per_sec, avg_packet_size,
            syn_count, rst_count, fin_count, ack_count, psh_count
        ) VALUES (
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?, ?, ?
        )
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
            getattr(flow, "composite_score", 0),
            getattr(flow, "anomaly_score", 0),
            getattr(flow, "ja3_score", 0),
            getattr(flow, "beacon_score", 0),
            getattr(flow, "cert_score", 0),
            getattr(flow, "graph_score", 0),
            getattr(flow, "verdict", "BENIGN"),
            getattr(flow, "severity", "CLEAN"),
            getattr(flow, "source", "pcap"),
            getattr(flow, "is_live", 0),
            getattr(flow, "packet_rate_per_sec", 0),
            getattr(flow, "byte_rate_per_sec", 0),
            getattr(flow, "avg_packet_size", 0),
            getattr(flow, "syn_count", 0),
            getattr(flow, "rst_count", 0),
            getattr(flow, "fin_count", 0),
            getattr(flow, "ack_count", 0),
            getattr(flow, "psh_count", 0),
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