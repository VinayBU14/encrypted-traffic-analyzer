
"""PCAP reader for streaming normalized and filtered packet dictionaries."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Generator

import pyshark

from src.ingestion.packet_filter import PacketFilter
from src.ingestion.packet_normalizer import PacketNormalizer

logger = logging.getLogger(__name__)


class PCAPReader:
    """Read packets from a PCAP file and stream normalized TLS-relevant packets."""

    def __init__(self, pcap_path: str) -> None:
        """Initialize reader with path validation and ingestion helpers."""
        self.pcap_path = Path(pcap_path).resolve()
        if not self.pcap_path.is_file():
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")

        self.packet_filter = PacketFilter()
        self.packet_normalizer = PacketNormalizer()

        file_size = self.pcap_path.stat().st_size
        logger.info("Initialized PCAPReader: path=%s size_bytes=%d", self.pcap_path, file_size)

    def read_packets(self) -> Generator[dict[str, Any], None, None]:
        """Yield normalized packets that pass filtering rules, one at a time."""
        capture: pyshark.FileCapture | None = None
        logger.info("Starting PCAP ingestion: %s", self.pcap_path)
        try:
            capture = pyshark.FileCapture(input_file=str(self.pcap_path), keep_packets=False)
            for packet in capture:
                try:
                    normalized_packet = self.packet_normalizer.normalize(packet)
                    if normalized_packet is None:
                        continue
                    if not self.packet_filter.should_keep(normalized_packet):
                        continue
                    yield normalized_packet
                except Exception as exc:
                    logger.debug("Error processing packet during ingestion: %s", exc)
                    continue
        except Exception as exc:
            logger.exception("PyShark ingestion error for %s: %s", self.pcap_path, exc)
        finally:
            if capture is not None:
                capture.close()
            stats = self.packet_filter.get_stats()
            logger.info(
                "Ingestion complete: %d/%d packets kept",
                stats["kept"],
                stats["total"],
            )

    def get_packet_count(self) -> int:
        """Count total packets in the PCAP by single-pass streaming iteration."""
        capture: pyshark.FileCapture | None = None
        count = 0
        try:
            capture = pyshark.FileCapture(input_file=str(self.pcap_path), keep_packets=False)
            for _ in capture:
                count += 1
        except Exception as exc:
            logger.exception("Failed to count packets for %s: %s", self.pcap_path, exc)
        finally:
            if capture is not None:
                capture.close()
        return count
