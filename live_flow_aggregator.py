"""Standalone live flow aggregation and feature extraction.

This module groups normalized packets into bidirectional TCP flows, times out inactive
flows, and computes flow-level features compatible with the project's offline extractor.

The implementation is intentionally standalone:
- no imports from project-local modules
- no dpkt dependency
- only stdlib + numpy + pandas
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Mapping, TypedDict

import numpy as np
import pandas as pd

FLOW_FEATURE_COLUMNS: list[str] = [
    "duration_ms",
    "total_packets",
    "total_bytes",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "packet_rate_per_sec",
    "byte_rate_per_sec",
    "avg_packet_size",
    "min_packet_size",
    "max_packet_size",
    "std_packet_size",
    "mean_iat_ms",
    "min_iat_ms",
    "max_iat_ms",
    "std_iat_ms",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
]


class TcpFlags(TypedDict, total=False):
    """Normalized TCP flag dictionary.

    Callers may provide either lowercase keys (syn, ack, fin, rst, psh) or uppercase
    keys (SYN, ACK, FIN, RST, PSH).
    """

    syn: bool
    ack: bool
    fin: bool
    rst: bool
    psh: bool
    SYN: bool
    ACK: bool
    FIN: bool
    RST: bool
    PSH: bool


class NormalizedPacket(TypedDict):
    """Expected packet schema from live ingestion."""

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_size: int
    payload_size: int
    tcp_flags: TcpFlags
    has_tls_layer: bool
    raw_packet: object


FlowPacketTuple = tuple[float, int, str, int, str, int, dict[str, bool]]
FlowKey = tuple[str, int, str, int]


class LiveFlowAggregator:
    """Aggregate live packets into bidirectional flows and emit feature rows on timeout.

    Each active flow stores packet tuples in the form:
        (timestamp, packet_size, src_ip, src_port, dst_ip, dst_port, tcp_flags)

    Timed-out flows (or all flows on flush) are converted into dict rows containing:
    - flow identity fields: flow_id, src_ip, src_port, dst_ip, dst_port
    - 22 feature fields in FLOW_FEATURE_COLUMNS order
    """

    def __init__(self, flow_timeout_seconds: float = 60.0, min_packets: int = 2) -> None:
        """Initialize flow aggregator configuration and active state.

        Args:
            flow_timeout_seconds: Inactivity timeout used to complete flows.
            min_packets: Minimum packet count required to emit a completed flow.
        """
        if flow_timeout_seconds < 0:
            raise ValueError("flow_timeout_seconds must be >= 0")
        if min_packets < 1:
            raise ValueError("min_packets must be >= 1")

        self.flow_timeout_seconds = float(flow_timeout_seconds)
        self.min_packets = int(min_packets)

        self._active_flows: dict[FlowKey, list[FlowPacketTuple]] = defaultdict(list)
        self._last_seen: dict[FlowKey, float] = {}

    @staticmethod
    def canonical_key(src_ip: str, sport: int, dst_ip: str, dport: int) -> FlowKey:
        """Build a bidirectional canonical flow key (lower endpoint first).

        This matches the comparison logic used by the offline extraction script.
        """
        a = (src_ip, sport)
        b = (dst_ip, dport)
        if a <= b:
            return (src_ip, sport, dst_ip, dport)
        return (dst_ip, dport, src_ip, sport)

    @staticmethod
    def _safe_float(value: Any) -> float:
        """Convert numeric-like input to finite float; fallback to 0.0."""
        try:
            fvalue = float(value)
            return 0.0 if (np.isnan(fvalue) or np.isinf(fvalue)) else fvalue
        except Exception:
            return 0.0

    @staticmethod
    def _flag_is_set(flags: Mapping[str, bool], lower_key: str, upper_key: str) -> bool:
        """Return True when either lowercase or uppercase TCP flag key is truthy."""
        return bool(flags.get(lower_key) or flags.get(upper_key))

    def add_packet(self, packet_dict: Mapping[str, Any]) -> list[dict[str, Any]]:
        """Add one normalized packet, timeout stale flows, and return completed rows.

        Args:
            packet_dict: Normalized packet dictionary from live capture.

        Returns:
            A list of completed flow rows (possibly empty). Each row is a dict suitable
            for direct conversion into a one-row pandas DataFrame.
        """
        required_keys = {
            "timestamp",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "packet_size",
            "tcp_flags",
        }
        if not required_keys.issubset(packet_dict.keys()):
            return []

        try:
            timestamp = float(packet_dict["timestamp"])
            src_ip = str(packet_dict["src_ip"])
            dst_ip = str(packet_dict["dst_ip"])
            src_port = int(packet_dict["src_port"])
            dst_port = int(packet_dict["dst_port"])
            packet_size = int(packet_dict["packet_size"])
        except Exception:
            return []

        tcp_flags_raw = packet_dict.get("tcp_flags", {})
        tcp_flags: dict[str, bool] = {
            "syn": bool(tcp_flags_raw.get("syn") or tcp_flags_raw.get("SYN")),
            "ack": bool(tcp_flags_raw.get("ack") or tcp_flags_raw.get("ACK")),
            "fin": bool(tcp_flags_raw.get("fin") or tcp_flags_raw.get("FIN")),
            "rst": bool(tcp_flags_raw.get("rst") or tcp_flags_raw.get("RST")),
            "psh": bool(tcp_flags_raw.get("psh") or tcp_flags_raw.get("PSH")),
        }

        key = self.canonical_key(src_ip, src_port, dst_ip, dst_port)
        self._active_flows[key].append(
            (timestamp, packet_size, src_ip, src_port, dst_ip, dst_port, tcp_flags)
        )
        self._last_seen[key] = timestamp

        timed_out_keys: list[FlowKey] = []
        for flow_key, last_seen in self._last_seen.items():
            if (timestamp - last_seen) > self.flow_timeout_seconds:
                timed_out_keys.append(flow_key)

        completed: list[dict[str, Any]] = []
        for flow_key in timed_out_keys:
            packets = self._active_flows.pop(flow_key, [])
            self._last_seen.pop(flow_key, None)
            if len(packets) >= self.min_packets:
                completed.append(self._build_feature_row(flow_key, packets))

        return completed

    def flush_all(self) -> list[dict[str, Any]]:
        """Force-complete all active flows meeting min_packets and clear active state."""
        completed: list[dict[str, Any]] = []
        for key, packets in list(self._active_flows.items()):
            if len(packets) >= self.min_packets:
                completed.append(self._build_feature_row(key, packets))

        self._active_flows.clear()
        self._last_seen.clear()
        return completed

    def get_active_flow_count(self) -> int:
        """Return the number of currently active canonical flows."""
        return len(self._active_flows)

    def _build_feature_row(self, key: FlowKey, packets: list[FlowPacketTuple]) -> dict[str, Any]:
        """Compute feature dict for one completed flow using offline-equivalent formulas."""
        src_ip, src_port, dst_ip, dst_port = key

        packets = sorted(packets, key=lambda pkt: pkt[0])
        times = [pkt[0] for pkt in packets]
        sizes = [pkt[1] for pkt in packets]

        duration_s = times[-1] - times[0] if len(times) > 1 else 0.0
        duration_ms = duration_s * 1000.0

        fwd_sizes = [
            pkt[1]
            for pkt in packets
            if (pkt[2] == src_ip and pkt[3] == src_port)
        ]
        bwd_sizes = [
            pkt[1]
            for pkt in packets
            if not (pkt[2] == src_ip and pkt[3] == src_port)
        ]

        fwd_bytes = sum(fwd_sizes)
        bwd_bytes = sum(bwd_sizes)
        total_bytes = sum(sizes)
        total_packets = len(packets)

        packet_rate = (total_packets / duration_s) if duration_s > 0 else 0.0
        byte_rate = (total_bytes / duration_s) if duration_s > 0 else 0.0

        iats = [(times[i] - times[i - 1]) * 1000.0 for i in range(1, len(times))]

        syn_count = sum(1 for pkt in packets if self._flag_is_set(pkt[6], "syn", "SYN"))
        ack_count = sum(1 for pkt in packets if self._flag_is_set(pkt[6], "ack", "ACK"))
        fin_count = sum(1 for pkt in packets if self._flag_is_set(pkt[6], "fin", "FIN"))
        rst_count = sum(1 for pkt in packets if self._flag_is_set(pkt[6], "rst", "RST"))
        psh_count = sum(1 for pkt in packets if self._flag_is_set(pkt[6], "psh", "PSH"))

        size_array = np.array(sizes, dtype=float)
        iat_array = np.array(iats, dtype=float) if iats else np.array([0.0])

        row = {
            "flow_id": f"{src_ip}:{src_port}-{dst_ip}:{dst_port}",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "duration_ms": self._safe_float(duration_ms),
            "total_packets": self._safe_float(total_packets),
            "total_bytes": self._safe_float(total_bytes),
            "fwd_packets": self._safe_float(len(fwd_sizes)),
            "bwd_packets": self._safe_float(len(bwd_sizes)),
            "fwd_bytes": self._safe_float(fwd_bytes),
            "bwd_bytes": self._safe_float(bwd_bytes),
            "packet_rate_per_sec": self._safe_float(packet_rate),
            "byte_rate_per_sec": self._safe_float(byte_rate),
            "avg_packet_size": self._safe_float(float(np.mean(size_array))),
            "min_packet_size": self._safe_float(float(np.min(size_array))),
            "max_packet_size": self._safe_float(float(np.max(size_array))),
            "std_packet_size": self._safe_float(float(np.std(size_array))) if len(size_array) > 1 else 0.0,
            "mean_iat_ms": self._safe_float(float(np.mean(iat_array))),
            "min_iat_ms": self._safe_float(float(np.min(iat_array))),
            "max_iat_ms": self._safe_float(float(np.max(iat_array))),
            "std_iat_ms": self._safe_float(float(np.std(iat_array))) if len(iat_array) > 1 else 0.0,
            "syn_count": self._safe_float(syn_count),
            "ack_count": self._safe_float(ack_count),
            "fin_count": self._safe_float(fin_count),
            "rst_count": self._safe_float(rst_count),
            "psh_count": self._safe_float(psh_count),
        }

        ordered_row: dict[str, Any] = {
            "flow_id": row["flow_id"],
            "src_ip": row["src_ip"],
            "src_port": row["src_port"],
            "dst_ip": row["dst_ip"],
            "dst_port": row["dst_port"],
        }
        for column in FLOW_FEATURE_COLUMNS:
            ordered_row[column] = row[column]

        return ordered_row

    @staticmethod
    def rows_to_dataframe(rows: list[dict[str, Any]]) -> pd.DataFrame:
        """Convert completed flow rows into a pandas DataFrame with stable columns."""
        base_columns = ["flow_id", "src_ip", "src_port", "dst_ip", "dst_port"] + FLOW_FEATURE_COLUMNS
        if not rows:
            return pd.DataFrame(columns=base_columns)
        return pd.DataFrame(rows, columns=base_columns)
