
"""Packet filtering logic for selecting TLS-relevant traffic."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


class PacketFilter:
    """Filter packet dictionaries to keep only relevant TLS transport traffic."""

    def __init__(self) -> None:
        """Load filter configuration and initialize running filter statistics."""
        project_root = Path(__file__).resolve().parents[2]
        config_path = project_root / "configs" / "default.yaml"
        config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        network_config = config.get("network", {})

        self.tls_tcp_ports: set[int] = {
            int(port) for port in network_config.get("tls_tcp_ports", [])
        }
        self.tls_udp_ports: set[int] = {
            int(port) for port in network_config.get("tls_udp_ports", [])
        }

        self._kept: int = 0
        self._discarded: int = 0
        self._total: int = 0

        logger.info(
            "PacketFilter monitoring TLS ports: tcp=%s udp=%s",
            sorted(self.tls_tcp_ports),
            sorted(self.tls_udp_ports),
        )

    def should_keep(self, packet_dict: dict[str, Any]) -> bool:
        """Return True when a packet matches the configured TLS transport filters."""
        try:
            protocol = str(packet_dict["protocol"]).upper()
            if protocol == "ARP":
                return self._discard("protocol ARP")
            if protocol == "ICMP":
                return self._discard("protocol ICMP")
            if protocol not in {"TCP", "UDP"}:
                return self._discard(f"unsupported protocol {protocol}")

            src_port = int(packet_dict["src_port"])
            dst_port = int(packet_dict["dst_port"])

            if protocol == "TCP":
                payload_size = int(packet_dict.get("payload_size", 0))
                if self._is_tcp_ack_only(packet_dict.get("tcp_flags")) and payload_size == 0:
                    return self._discard("TCP ACK-only with zero payload")
                if src_port in self.tls_tcp_ports or dst_port in self.tls_tcp_ports:
                    return self._keep()
                return self._discard("TCP port not in configured TLS port list")

            if src_port in self.tls_udp_ports or dst_port in self.tls_udp_ports:
                return self._keep()
            return self._discard("UDP port not in configured TLS port list")
        except (KeyError, TypeError, ValueError) as exc:
            return self._discard(f"packet parsing error: {exc}")

    def get_stats(self) -> dict[str, int]:
        """Return running packet filter counters for kept/discarded/total packets."""
        return {"kept": self._kept, "discarded": self._discarded, "total": self._total}

    def _keep(self) -> bool:
        self._total += 1
        self._kept += 1
        return True

    def _discard(self, reason: str) -> bool:
        self._total += 1
        self._discarded += 1
        logger.debug("Discarding packet: %s", reason)
        return False

    def _is_tcp_ack_only(self, tcp_flags: Any) -> bool:
        if tcp_flags is None:
            return False

        if isinstance(tcp_flags, dict):
            normalized = {str(key).upper(): int(value) for key, value in tcp_flags.items()}
            ack_value = normalized.get("ACK", 0)
            other_flags = [
                flag
                for flag in ("SYN", "FIN", "RST", "PSH", "URG", "ECE", "CWR")
                if normalized.get(flag, 0) > 0
            ]
            return ack_value > 0 and not other_flags

        if isinstance(tcp_flags, str):
            flag_text = tcp_flags.strip().upper()
            if flag_text in {"ACK", "A"}:
                return True
            if "," in flag_text:
                flags = {flag.strip() for flag in flag_text.split(",")}
                return flags == {"ACK"} or flags == {"A"}
            return False

        return False
