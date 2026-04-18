"""Live network ingestion using PyShark with shared normalization and filtering logic."""

from __future__ import annotations

import asyncio
import logging
import subprocess
import sys
from typing import Any, Generator

import pyshark

from src.ingestion.packet_filter import PacketFilter
from src.ingestion.packet_normalizer import PacketNormalizer


class LiveCaptureReader:
    """Capture live packets from a network interface and stream normalized TLS-relevant packets."""

    def __init__(
        self,
        interface: str = "",
        packet_limit: int = 0,
        bpf_filter: str = "tcp",
    ) -> None:
        """Initialize live capture settings and shared packet processing helpers."""
        self._interface = interface or self._pick_default_interface()
        self._packet_limit = packet_limit
        self._bpf_filter = bpf_filter
        self._packet_filter = PacketFilter()
        self._packet_normalizer = PacketNormalizer()
        self._running = False
        self._logger = logging.getLogger(__name__)

    @staticmethod
    def _pick_default_interface() -> str:
        """
        Try to pick the best default interface automatically.
        Prefers non-loopback interfaces. Falls back to 'eth0'.
        """
        interfaces = LiveCaptureReader.get_available_interfaces()
        for iface in interfaces:
            lower = iface.lower()
            if "loopback" in lower or lower in ("lo", "any"):
                continue
            return iface
        return interfaces[0] if interfaces else "eth0"

    def start_capture(self) -> Generator[dict[str, Any], None, None]:
        """Start live capture and yield normalized+filtered packets until stopped or limit reached."""
        # Ensure an event loop exists — pyshark requires one
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                raise RuntimeError("loop closed")
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        capture = None
        captured_count = 0
        self._running = True
        self._logger.info("Live capture started on %s", self._interface)

        try:
            capture_kwargs: dict[str, Any] = {"interface": self._interface}
            if self._bpf_filter.strip():
                capture_kwargs["bpf_filter"] = self._bpf_filter
            capture = pyshark.LiveCapture(**capture_kwargs, eventloop=loop)
            packet_counter = 0
            for packet in capture.sniff_continuously(packet_count=0):
                if not self._running:
                    break
                packet_counter += 1
                captured_count += 1
                normalized = self._packet_normalizer.normalize(packet)
                if normalized is None:
                    continue
                if not self._packet_filter.should_keep(normalized):
                    continue
                yield normalized
                if self._packet_limit > 0 and packet_counter >= self._packet_limit:
                    break
        except Exception as exc:
            if "tshark" in str(exc).lower() or "TShark" in str(exc):
                raise RuntimeError(
                    "TShark not found. Install Wireshark and ensure tshark is on PATH."
                ) from exc
            raise
        finally:
            self._running = False
            if capture is not None:
                try:
                    capture.close()
                except Exception:
                    pass
            self._logger.info(
                "Live capture stopped — %d packets captured", captured_count
            )

    def stop(self) -> None:
        """Signal the live capture loop to stop at the next packet boundary."""
        self._running = False

    @staticmethod
    def get_available_interfaces() -> list[str]:
        """
        Return available interface names via tshark -D.
        Parses both formats:
          1. \Device\NPF_{GUID} (Ethernet)   ← Windows
          2. eth0                             ← Linux
        """
        try:
            result = subprocess.run(
                ["tshark", "-D"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            interfaces: list[str] = []
            for line in result.stdout.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                # Strip leading "N. " index
                if ". " in line:
                    line = line.split(". ", 1)[1]
                # Extract the device name before the human-readable label in parens
                # e.g.  \Device\NPF_{1234} (Ethernet)  → \Device\NPF_{1234}
                if "(" in line:
                    iface_name = line.split("(")[0].strip()
                else:
                    iface_name = line.strip()
                if iface_name:
                    interfaces.append(iface_name)
            return interfaces if interfaces else ["eth0", "wlan0"]
        except FileNotFoundError:
            logging.getLogger(__name__).warning(
                "tshark not found — install Wireshark and add it to PATH"
            )
            return ["eth0", "wlan0"]
        except Exception as exc:
            logging.getLogger(__name__).warning(
                "Failed to list interfaces via tshark -D: %s", exc
            )
            return ["eth0", "wlan0"]