
"""Flow tracking logic for grouping packets into bidirectional 5-tuple flows."""

from __future__ import annotations

import ipaddress
import logging
import uuid
from pathlib import Path
from typing import Any

import yaml

from src.storage.models import FlowRecord


FlowKey = tuple[str, int, str, int, str]


class FlowTracker:
    """Track active bidirectional flows and finalize completed or timed-out flows."""

    def __init__(self) -> None:
        """Initialize flow tracking state and load timeout/min-packet configuration."""
        config_path = Path(__file__).resolve().parents[2] / "configs" / "default.yaml"
        config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        network = config.get("network", {})

        self.flow_timeout_seconds: float = float(network.get("flow_timeout_seconds", 60))
        self.min_packets_per_flow: int = int(network.get("min_packets_per_flow", 1))

        self._active_flows: dict[FlowKey, FlowRecord] = {}
        self._completed_flows: list[FlowRecord] = []
        self._last_packet_ts: dict[FlowKey, float] = {}
        self._first_direction: dict[FlowKey, tuple[str, str]] = {}
        self._total_packets_processed: int = 0
        self._logger = logging.getLogger(__name__)

    def add_packet(self, packet: dict[str, Any]) -> list[FlowRecord]:
        """Add a normalized packet to flow state and return any newly completed flows."""
        completed_now: list[FlowRecord] = []
        try:
            key = self._build_flow_key(packet)
            timestamp = float(packet["timestamp"])
            src_ip = str(packet["src_ip"])
            dst_ip = str(packet["dst_ip"])
            src_port = int(packet["src_port"])
            dst_port = int(packet["dst_port"])
            protocol = str(packet["protocol"])
            packet_size = int(packet["packet_size"])
            packet_flags = packet.get("tcp_flags", {})

            if key not in self._active_flows:
                self._active_flows[key] = FlowRecord(
                    flow_id=str(uuid.uuid4()),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    start_time=timestamp,
                    packet_count=0,
                    bytes_total=0,
                    upload_bytes=0,
                    download_bytes=0,
                    packet_sizes=[],
                    inter_arrival_ms=[],
                    tcp_flags={"SYN": 0, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0},
                    created_at=timestamp,
                    end_time=timestamp,
                    status="ACTIVE",
                )
                self._first_direction[key] = (src_ip, dst_ip)
                self._last_packet_ts[key] = timestamp

            flow = self._active_flows[key]

            flow.packet_count += 1
            flow.bytes_total += packet_size
            flow.packet_sizes.append(float(packet_size))

            first_src, first_dst = self._first_direction[key]
            if src_ip == first_src and dst_ip == first_dst:
                flow.upload_bytes += packet_size
            else:
                flow.download_bytes += packet_size

            last_ts = self._last_packet_ts.get(key, timestamp)
            gap = max(0.0, timestamp - last_ts)
            if flow.packet_count > 1:
                flow.inter_arrival_ms.append(gap)
            self._last_packet_ts[key] = timestamp

            for name in ("SYN", "ACK", "FIN", "RST", "PSH"):
                if bool(packet_flags.get(name, False)):
                    flow.tcp_flags[name] = flow.tcp_flags.get(name, 0) + 1

            flow.end_time = timestamp
            self._total_packets_processed += 1

            if bool(packet_flags.get("FIN", False)) or bool(packet_flags.get("RST", False)):
                flow.status = "CLOSED"
                if flow.packet_count >= self.min_packets_per_flow:
                    completed_now.append(self._finalize_flow(key))
                else:
                    self._active_flows.pop(key, None)
                    self._last_packet_ts.pop(key, None)
                    self._first_direction.pop(key, None)

            return completed_now
        except Exception as exc:
            self._logger.debug("Failed to add packet to flow tracker: %s", exc)
            return completed_now

    def check_timeouts(self, current_time: float) -> list[FlowRecord]:
        """Finalize any active flows that exceeded configured inactivity timeout."""
        timed_out: list[FlowRecord] = []
        for key, flow in list(self._active_flows.items()):
            if flow.end_time is None:
                continue
            if (current_time - flow.end_time) > self.flow_timeout_seconds:
                flow.status = "TIMEOUT"
                if flow.packet_count >= self.min_packets_per_flow:
                    timed_out.append(self._finalize_flow(key))
                else:
                    self._active_flows.pop(key, None)
                    self._last_packet_ts.pop(key, None)
                    self._first_direction.pop(key, None)
        return timed_out

    def get_all_completed(self) -> list[FlowRecord]:
        """Return and clear all accumulated completed flows."""
        completed = list(self._completed_flows)
        self._completed_flows.clear()
        return completed

    def get_stats(self) -> dict[str, int]:
        """Return active/completed flow counters and total processed packet count."""
        return {
            "active_flows": len(self._active_flows),
            "completed_flows": len(self._completed_flows),
            "total_packets_processed": self._total_packets_processed,
        }

    def _build_flow_key(self, packet: dict[str, Any]) -> FlowKey:
        src_ip = str(packet["src_ip"])
        dst_ip = str(packet["dst_ip"])
        src_port = int(packet["src_port"])
        dst_port = int(packet["dst_port"])
        protocol = str(packet["protocol"]).upper()

        src_ip_obj = ipaddress.ip_address(src_ip)
        dst_ip_obj = ipaddress.ip_address(dst_ip)

        if src_ip_obj < dst_ip_obj:
            return (src_ip, src_port, dst_ip, dst_port, protocol)
        if src_ip_obj == dst_ip_obj:
            if src_port <= dst_port:
                return (src_ip, src_port, dst_ip, dst_port, protocol)
            return (dst_ip, dst_port, src_ip, src_port, protocol)
        return (dst_ip, dst_port, src_ip, src_port, protocol)

    def _finalize_flow(self, key: FlowKey) -> FlowRecord:
        """Finalize a flow, compute duration, and move it to completed flow storage."""
        flow = self._active_flows.pop(key)
        self._last_packet_ts.pop(key, None)
        self._first_direction.pop(key, None)
        flow.end_time = flow.end_time if flow.end_time is not None else flow.start_time
        flow.duration_ms = (flow.end_time - flow.start_time) * 1000.0
        self._completed_flows.append(flow)
        self._logger.debug(
            "Flow finalized: %s:%d -> %s:%d | %d pkts",
            flow.src_ip,
            flow.src_port,
            flow.dst_ip,
            flow.dst_port,
            flow.packet_count,
        )
        return flow
