"""Day 3 flow reconstruction verification script for Spectra."""

from __future__ import annotations

import sys
from pathlib import Path
from pprint import pformat
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.pipeline.orchestrator import PipelineOrchestrator
from src.storage.database import get_db
from src.storage.repositories.flow_repository import get_recent_flows


def _pass(message: str) -> None:
    print(f"PASS: {message}")


def _fail(message: str) -> None:
    print(f"FAIL: {message}")


def main() -> int:
    failed = False
    summary: dict[str, Any] = {}
    conn = get_db().get_connection()

    conn.execute("DELETE FROM tls_sessions")
    conn.execute("DELETE FROM alerts")
    conn.execute("DELETE FROM flows")
    conn.commit()

    # Check 1
    try:
        pcap_path = PROJECT_ROOT / "data" / "raw" / "pcap" / "test_sample.pcap"
        orchestrator = PipelineOrchestrator(str(pcap_path))
        summary = orchestrator.run()
        required_keys = {
            "pcap_path",
            "packets_processed",
            "flows_completed",
            "flows_saved",
            "ingestion_stats",
            "flow_stats",
        }
        assert required_keys.issubset(summary.keys())
        _pass("Check 1 - PipelineOrchestrator completed with valid summary")
        print("SUMMARY:")
        print(pformat(summary))
    except Exception as exc:
        failed = True
        _fail(f"Check 1 - pipeline execution failed ({exc})")

    flows = []

    # Check 2
    try:
        conn = get_db().get_connection()
        flows = get_recent_flows(conn, limit=1000)
        assert len(flows) >= 1
        _pass(f"Check 2 - flows saved to database (count={len(flows)})")
    except Exception as exc:
        failed = True
        _fail(f"Check 2 - flow retrieval failed ({exc})")

    # Check 3
    try:
        for flow in flows:
            assert isinstance(flow.flow_id, str) and flow.flow_id.strip()
            assert isinstance(flow.src_ip, str) and flow.src_ip.strip()
            assert isinstance(flow.dst_ip, str) and flow.dst_ip.strip()
            assert flow.packet_count > 0
            assert flow.bytes_total > 0
            assert flow.start_time > 0
            assert flow.duration_ms is not None and flow.duration_ms >= 0
            assert isinstance(flow.packet_sizes, list)
            assert isinstance(flow.inter_arrival_ms, list)
        _pass("Check 3 - flow record integrity verified")
    except Exception as exc:
        failed = True
        _fail(f"Check 3 - flow integrity check failed ({exc})")

    # Check 4
    try:
        assert any((flow.upload_bytes + flow.download_bytes) == flow.bytes_total for flow in flows)
        _pass("Check 4 - directional byte accounting verified")
    except Exception as exc:
        failed = True
        _fail(f"Check 4 - directional accounting check failed ({exc})")

    # Check 5
    try:
        unique_dst_ports = {flow.dst_port for flow in flows}
        assert len(unique_dst_ports) >= 2
        assert any(flow.packet_count > 1 for flow in flows)
        _pass(
            f"Check 5 - flow diversity verified "
            f"({len(unique_dst_ports)} unique destination ports)"
        )
        top_flows = sorted(flows, key=lambda item: item.packet_count, reverse=True)[:5]
        for flow in top_flows:
            duration_ms = flow.duration_ms if flow.duration_ms is not None else 0.0
            print(
                f"TOP: {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} | "
                f"{flow.packet_count} packets | {flow.bytes_total} bytes | {duration_ms:.3f} ms"
            )
    except Exception as exc:
        failed = True
        _fail(f"Check 5 - port diversity check failed ({exc})")

    if failed:
        print("✗ Day 3 verification FAILED — see errors above")
        return 1

    print("✓ Day 3 verification passed — flow reconstruction is ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
