
"""Packet normalization utilities for converting raw packets into flat dictionaries."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class PacketNormalizer:
    """Normalize raw packet objects into a stable dict schema for downstream modules."""

    def normalize(self, packet: object) -> dict[str, Any] | None:
        """Normalize a raw packet into the Spectra packet dict schema."""
        try:
            timestamp = float(getattr(packet, "sniff_timestamp"))

            ip_layer = getattr(packet, "ip")
            src_ip = str(getattr(ip_layer, "src"))
            dst_ip = str(getattr(ip_layer, "dst"))

            is_tcp = hasattr(packet, "tcp")
            is_udp = hasattr(packet, "udp")
            if not is_tcp and not is_udp:
                raise ValueError("Packet missing TCP/UDP layer")

            protocol = "TCP" if is_tcp else "UDP"
            transport_layer = getattr(packet, "tcp") if is_tcp else getattr(packet, "udp")
            src_port = int(getattr(transport_layer, "srcport"))
            dst_port = int(getattr(transport_layer, "dstport"))

            packet_size = int(getattr(packet, "length"))
            ip_header_size = self._extract_ip_header_length(ip_layer)
            transport_header_size = self._extract_transport_header_length(packet, protocol)
            payload_size = max(0, packet_size - ip_header_size - transport_header_size)

            tcp_flags = self._extract_tcp_flags(packet)
            has_tls_layer = self._has_tls_layer(packet)

            return {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "packet_size": packet_size,
                "payload_size": payload_size,
                "tcp_flags": tcp_flags,
                "has_tls_layer": has_tls_layer,
                "raw_packet": packet,
            }
        except Exception as exc:
            logger.debug("Failed to normalize packet: %s", exc)
            return None

    def _extract_tcp_flags(self, packet: object) -> dict[str, bool]:
        """Extract normalized TCP flags from a packet, or all-false values if unavailable."""
        default_flags = {
            "SYN": False,
            "ACK": False,
            "FIN": False,
            "RST": False,
            "PSH": False,
            "URG": False,
        }
        if not hasattr(packet, "tcp"):
            return default_flags

        try:
            tcp_layer = getattr(packet, "tcp")
            flags_value = getattr(tcp_layer, "flags", None)
            if flags_value is None:
                return default_flags

            # PyShark commonly exposes flags as hex string (e.g., "0x00000018").
            flags_int = int(str(flags_value), 16)
            return {
                "FIN": bool(flags_int & 0x01),
                "SYN": bool(flags_int & 0x02),
                "RST": bool(flags_int & 0x04),
                "PSH": bool(flags_int & 0x08),
                "ACK": bool(flags_int & 0x10),
                "URG": bool(flags_int & 0x20),
            }
        except Exception as exc:
            logger.debug("Failed to parse TCP flags, returning defaults: %s", exc)
            return default_flags

    def _has_tls_layer(self, packet: object) -> bool:
        try:
            layers = getattr(packet, "layers", [])
            for layer in layers:
                layer_name = str(getattr(layer, "layer_name", "")).upper()
                if layer_name in {"TLS", "SSL"}:
                    return True
            return hasattr(packet, "tls") or hasattr(packet, "ssl")
        except Exception:
            return False

    def _extract_ip_header_length(self, ip_layer: object) -> int:
        header_len_raw = getattr(ip_layer, "hdr_len", None)
        if header_len_raw is None:
            return 20
        header_len = int(str(header_len_raw), 0)
        if header_len <= 15:
            return header_len * 4
        return header_len

    def _extract_transport_header_length(self, packet: object, protocol: str) -> int:
        if protocol == "UDP":
            return 8

        tcp_layer = getattr(packet, "tcp")
        header_len_raw = getattr(tcp_layer, "hdr_len", None)
        if header_len_raw is None:
            return 20
        header_len = int(str(header_len_raw), 0)
        if header_len <= 15:
            return header_len * 4
        return header_len
