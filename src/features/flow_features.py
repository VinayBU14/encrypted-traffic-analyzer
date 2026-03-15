
"""Flow-level statistical feature extraction from FlowRecord objects."""

from __future__ import annotations

import logging

import numpy as np

from src.features.schema import FLOW_FEATURE_COLUMNS
from src.storage.models import FlowRecord


class FlowFeatureExtractor:
    """Compute canonical flow feature values from a reconstructed flow record."""

    def __init__(self) -> None:
        """Initialize flow feature extractor logger."""
        self._logger = logging.getLogger(__name__)

    def extract(self, flow: FlowRecord) -> dict[str, float]:
        """Extract all flow feature columns as float values with safe fallbacks."""
        duration_ms = self._safe_float(flow.duration_ms if flow.duration_ms is not None else 0.0)
        duration_seconds = duration_ms / 1000.0 if duration_ms > 0.0 else 0.0

        total_packets = self._safe_float(flow.packet_count)
        total_bytes = self._safe_float(flow.bytes_total)
        fwd_bytes = self._safe_float(flow.upload_bytes)
        bwd_bytes = self._safe_float(flow.download_bytes)

        if total_packets > 0.0 and total_bytes > 0.0:
            fwd_packets = float(round(total_packets * (fwd_bytes / total_bytes)))
            bwd_packets = max(0.0, total_packets - fwd_packets)
        else:
            fwd_packets = 0.0
            bwd_packets = 0.0

        packet_rate_per_sec = (total_packets / duration_seconds) if duration_seconds > 0.0 else 0.0
        byte_rate_per_sec = (total_bytes / duration_seconds) if duration_seconds > 0.0 else 0.0

        packet_sizes = [self._safe_float(value) for value in flow.packet_sizes]
        iats = [self._safe_float(value) for value in flow.inter_arrival_ms]

        features: dict[str, float] = {
            "duration_ms": duration_ms,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "fwd_packets": self._safe_float(fwd_packets),
            "bwd_packets": self._safe_float(bwd_packets),
            "fwd_bytes": fwd_bytes,
            "bwd_bytes": bwd_bytes,
            "packet_rate_per_sec": self._safe_float(packet_rate_per_sec),
            "byte_rate_per_sec": self._safe_float(byte_rate_per_sec),
            "avg_packet_size": self._safe_stat(packet_sizes, "mean"),
            "min_packet_size": self._safe_stat(packet_sizes, "min"),
            "max_packet_size": self._safe_stat(packet_sizes, "max"),
            "std_packet_size": self._safe_stat(packet_sizes, "std"),
            "mean_iat_ms": self._safe_stat(iats, "mean"),
            "min_iat_ms": self._safe_stat(iats, "min"),
            "max_iat_ms": self._safe_stat(iats, "max"),
            "std_iat_ms": self._safe_stat(iats, "std"),
            "syn_count": self._safe_float(flow.tcp_flags.get("SYN", 0)),
            "ack_count": self._safe_float(flow.tcp_flags.get("ACK", 0)),
            "fin_count": self._safe_float(flow.tcp_flags.get("FIN", 0)),
            "rst_count": self._safe_float(flow.tcp_flags.get("RST", 0)),
            "psh_count": self._safe_float(flow.tcp_flags.get("PSH", 0)),
        }

        for column in FLOW_FEATURE_COLUMNS:
            if column not in features:
                features[column] = 0.0

        self._logger.debug("Extracted flow features for flow_id=%s", flow.flow_id)
        return {column: self._safe_float(features[column]) for column in FLOW_FEATURE_COLUMNS}

    def _safe_stat(self, values: list[float], stat: str) -> float:
        """Safely compute requested statistic and return 0.0 on empty inputs/errors."""
        try:
            if not values:
                return 0.0

            arr = np.asarray(values, dtype=float)
            if arr.size == 0:
                return 0.0

            if stat == "mean":
                return self._safe_float(float(np.mean(arr)))
            if stat == "min":
                return self._safe_float(float(np.min(arr)))
            if stat == "max":
                return self._safe_float(float(np.max(arr)))
            if stat == "std":
                if arr.size < 2:
                    return 0.0
                return self._safe_float(float(np.std(arr)))

            return 0.0
        except Exception as exc:
            self._logger.debug("Failed to compute stat '%s': %s", stat, exc)
            return 0.0

    def _safe_float(self, value: object) -> float:
        try:
            parsed = float(value)
            if np.isnan(parsed) or np.isinf(parsed):
                return 0.0
            return parsed
        except Exception:
            return 0.0
