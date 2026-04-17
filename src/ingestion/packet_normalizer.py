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
            # FIXED: PyShark exposes sniff_timestamp as a string like "1234567890.123456".
            # Older Wireshark captures or certain capture types expose it differently.
            # We try sniff_timestamp first, then fall back to frame.time_epoch.
            timestamp = self._extract_timestamp(packet)
            if timestamp is None:
                return None

            # Accept both IPv4 (ip) and IPv6 (ipv6) layers
            ip_layer = self._get_ip_layer(packet)
            if ip_layer is None:
                return None

            src_ip = str(getattr(ip_layer, "src", None) or getattr(ip_layer, "src_host", ""))
            dst_ip = str(getattr(ip_layer, "dst", None) or getattr(ip_layer, "dst_host", ""))
            if not src_ip or not dst_ip:
                return None

            is_tcp = hasattr(packet, "tcp")
            is_udp = hasattr(packet, "udp")
            if not is_tcp and not is_udp:
                return None

            protocol = "TCP" if is_tcp else "UDP"
            transport_layer = getattr(packet, "tcp") if is_tcp else getattr(packet, "udp")

            # FIXED: PyShark uses srcport/dstport but may also expose sport/dport
            src_port = self._extract_port(transport_layer, "srcport", "sport")
            dst_port = self._extract_port(transport_layer, "dstport", "dport")
            if src_port is None or dst_port is None:
                return None

            # packet.length is the frame length; safe fallback to ip layer length
            packet_size = self._extract_size(packet)
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

    # ------------------------------------------------------------------

    def _extract_timestamp(self, packet: object) -> float | None:
        """Extract packet timestamp — tries multiple PyShark attribute names."""
        for attr in ("sniff_timestamp", "frame_info.time_epoch", "sniff_time"):
            try:
                raw = getattr(packet, attr, None)
                if raw is not None:
                    return float(str(raw))
            except Exception:
                continue
        # Last resort: frame layer
        try:
            frame = getattr(packet, "frame_info", None) or getattr(packet, "frame", None)
            if frame is not None:
                epoch = getattr(frame, "time_epoch", None)
                if epoch is not None:
                    return float(str(epoch))
        except Exception:
            pass
        return None

    def _get_ip_layer(self, packet: object) -> object | None:
        """Return the IP or IPv6 layer, or None if neither is present."""
        if hasattr(packet, "ip"):
            return getattr(packet, "ip")
        if hasattr(packet, "ipv6"):
            return getattr(packet, "ipv6")
        return None

    def _extract_port(self, layer: object, *attrs: str) -> int | None:
        for attr in attrs:
            try:
                val = getattr(layer, attr, None)
                if val is not None:
                    return int(str(val))
            except Exception:
                continue
        return None

    def _extract_size(self, packet: object) -> int:
        try:
            return int(str(getattr(packet, "length")))
        except Exception:
            pass
        try:
            ip = self._get_ip_layer(packet)
            if ip is not None:
                return int(str(getattr(ip, "len", 0)))
        except Exception:
            pass
        return 0

    def _extract_tcp_flags(self, packet: object) -> dict[str, bool]:
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

            # PyShark commonly exposes flags as hex string e.g. "0x00000018"
            # But sometimes as plain decimal. Try hex first, then decimal.
            raw = str(flags_value).strip()
            try:
                flags_int = int(raw, 16)
            except ValueError:
                flags_int = int(raw, 0)

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
        try:
            header_len = int(str(header_len_raw), 0)
            if header_len <= 15:
                return header_len * 4
            return header_len
        except Exception:
            return 20

    def _extract_transport_header_length(self, packet: object, protocol: str) -> int:
        if protocol == "UDP":
            return 8
        try:
            tcp_layer = getattr(packet, "tcp")
            header_len_raw = getattr(tcp_layer, "hdr_len", None)
            if header_len_raw is None:
                return 20
            header_len = int(str(header_len_raw), 0)
            if header_len <= 15:
                return header_len * 4
            return header_len
        except Exception:
            return 20