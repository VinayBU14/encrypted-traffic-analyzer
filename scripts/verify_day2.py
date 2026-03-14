"""Day 2 ingestion pipeline verification script for Spectra."""

from __future__ import annotations

import inspect
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ingestion.packet_filter import PacketFilter
from src.ingestion.packet_normalizer import PacketNormalizer
from src.ingestion.pcap_reader import PCAPReader


def _pass(message: str) -> None:
    print(f"PASS: {message}")


def _fail(message: str) -> None:
    print(f"FAIL: {message}")


def main() -> int:
    failed = False
    kept_packets: list[dict[str, Any]] = []

    # Check 1
    try:
        packet_filter = PacketFilter()
        assert 443 in packet_filter.tls_tcp_ports
        assert 443 in packet_filter.tls_udp_ports
        _pass("Check 1 - PacketFilter loaded TLS port config correctly")
    except Exception as exc:
        failed = True
        _fail(f"Check 1 - PacketFilter config load failed ({exc})")
        packet_filter = None

    # Check 2
    try:
        assert hasattr(PacketNormalizer, "normalize")
        normalize_fn = getattr(PacketNormalizer, "normalize")
        signature = inspect.signature(normalize_fn)
        assert len(signature.parameters) == 2
        _pass("Check 2 - PacketNormalizer imported and normalize() signature verified")
    except Exception as exc:
        failed = True
        _fail(f"Check 2 - PacketNormalizer structure check failed ({exc})")

    # Check 3
    try:
        pcap_path = PROJECT_ROOT / "data" / "raw" / "pcap" / "test_sample.pcap"
        reader = PCAPReader(str(pcap_path))
        required_keys = {
            "timestamp",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "packet_size",
            "tcp_flags",
            "has_tls_layer",
        }

        for packet in reader.read_packets():
            kept_packets.append(packet)
            if len(kept_packets) >= 50:
                break

        assert len(kept_packets) >= 1
        for packet in kept_packets:
            assert required_keys.issubset(packet.keys())
            assert isinstance(packet["timestamp"], float) and packet["timestamp"] > 0
            assert isinstance(packet["src_ip"], str) and packet["src_ip"].strip()
            assert isinstance(packet["dst_ip"], str) and packet["dst_ip"].strip()
            assert packet["protocol"] in {"TCP", "UDP"}

        _pass(f"Check 3 - PCAPReader kept {len(kept_packets)} packet(s) with valid schema")
    except Exception as exc:
        failed = True
        _fail(f"Check 3 - PCAPReader ingestion/schema check failed ({exc})")
        reader = None

    # Check 4
    try:
        if reader is None:
            raise RuntimeError("PCAPReader not available")
        stats = reader.packet_filter.get_stats()
        assert {"kept", "discarded", "total"}.issubset(stats.keys())
        assert stats["total"] == stats["kept"] + stats["discarded"]
        _pass(
            "Check 4 - Filter stats tracked correctly "
            f"(kept={stats['kept']}, discarded={stats['discarded']}, total={stats['total']})"
        )
    except Exception as exc:
        failed = True
        _fail(f"Check 4 - Filter stats check failed ({exc})")

    # Check 5
    try:
        tls_count = sum(1 for packet in kept_packets if bool(packet.get("has_tls_layer")))
        assert tls_count >= 1
        _pass(f"Check 5 - TLS packet detection verified ({tls_count} TLS packet(s) found)")
    except Exception as exc:
        failed = True
        _fail(f"Check 5 - TLS packet detection failed ({exc})")
        tls_count = 0

    for packet in kept_packets[:3]:
        tls_text = "yes" if packet.get("has_tls_layer") else "no"
        print(
            f"SAMPLE: {packet['src_ip']} -> {packet['dst_ip']} : {packet['dst_port']} | "
            f"{packet['protocol']} | {packet['packet_size']} | TLS: {tls_text}"
        )

    if failed:
        print("✗ Day 2 verification FAILED — see errors above")
        return 1

    print("✓ Day 2 verification passed — ingestion pipeline is ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
