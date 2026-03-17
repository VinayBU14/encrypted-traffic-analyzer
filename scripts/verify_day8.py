"""Day 8 — Beacon detection verification script for Spectra."""

from __future__ import annotations

import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.analysis.beacon.analyzer import BeaconAnalyzer
from src.analysis.beacon.metrics import (
    compute_regularity_score,
    compute_jitter_score,
    compute_payload_consistency_score,
    compute_time_independence_score,
)
from src.storage.database import get_db
from src.storage.models import FlowRecord
from src.storage.repositories.flow_repository import get_recent_flows


def _pass(msg: str) -> None:
    print(f"PASS: {msg}")


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}")


def _make_flows(
    count: int,
    interval_seconds: float,
    jitter: float = 0.0,
    bytes_total: int = 500,
    start_offset: float = 0.0,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "1.2.3.4",
) -> list[FlowRecord]:
    """Helper to create synthetic FlowRecords for testing."""
    base = time.time() - (count * interval_seconds) + start_offset
    flows = []
    for i in range(count):
        ts = base + i * interval_seconds + (jitter * (i % 3 - 1))
        flows.append(FlowRecord(
            flow_id=f"test-{i}",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=50000,
            dst_port=443,
            protocol="TCP",
            start_time=ts,
            packet_count=5,
            bytes_total=bytes_total,
            upload_bytes=bytes_total // 2,
            download_bytes=bytes_total // 2,
            packet_sizes=[100.0] * 5,
            inter_arrival_ms=[10.0] * 4,
            tcp_flags={"SYN": 1, "ACK": 4, "FIN": 1},
            created_at=ts,
            end_time=ts + 0.5,
            duration_ms=500.0,
        ))
    return flows


def main() -> int:
    failed = False
    analyzer = BeaconAnalyzer()

    # Check 1 — Too few flows returns score 0.0
    try:
        flows = _make_flows(count=3, interval_seconds=60)
        result = analyzer.score(flows)
        assert float(result["beacon_score"]) == 0.0
        _pass(f"Check 1 - Insufficient flows (<5) returns score=0.0 (got flow_count={result['flow_count']})")
    except Exception as exc:
        failed = True
        _fail(f"Check 1 - Insufficient flow handling failed ({exc})")

    # Check 2 — Perfect beacon (10 flows, exactly 60s apart) scores high
    try:
        flows = _make_flows(count=10, interval_seconds=60, jitter=0.0, bytes_total=512)
        result = analyzer.score(flows)
        score = float(result["beacon_score"])
        assert score >= 0.50, f"Expected >=0.50 for perfect beacon, got {score}"
        _pass(
            f"Check 2 - Perfect beacon scored high: score={score} "
            f"reg={result['regularity_score']} jitter={result['jitter_score']}"
        )
    except Exception as exc:
        failed = True
        _fail(f"Check 2 - Perfect beacon scoring failed ({exc})")

    # Check 3 — Random intervals score low
    try:
        import random
        random.seed(42)
        base = time.time() - 3600
        flows = []
        for i in range(10):
            ts = base + random.uniform(0, 3600)
            flows.append(FlowRecord(
                flow_id=f"rand-{i}", src_ip="10.0.0.2", dst_ip="5.6.7.8",
                src_port=50000, dst_port=443, protocol="TCP",
                start_time=ts, packet_count=3, bytes_total=random.randint(100, 5000),
                upload_bytes=200, download_bytes=200,
                packet_sizes=[200.0, 200.0, 200.0], inter_arrival_ms=[10.0, 10.0],
                tcp_flags={"SYN": 1, "ACK": 2, "FIN": 1},
                created_at=ts, end_time=ts + 1.0, duration_ms=1000.0,
            ))
        result = analyzer.score(flows)
        score = float(result["beacon_score"])
        assert score < 0.70, f"Expected <0.70 for random traffic, got {score}"
        _pass(f"Check 3 - Random traffic scored low: score={score}")
    except Exception as exc:
        failed = True
        _fail(f"Check 3 - Random traffic scoring failed ({exc})")

    # Check 4 — Individual metrics work correctly
    try:
        perfect_times = [time.time() + i * 60 for i in range(10)]
        reg = compute_regularity_score(perfect_times)
        jitter = compute_jitter_score(perfect_times)
        assert reg >= 0.90, f"Perfect regularity should be >=0.90, got {reg}"
        assert jitter >= 0.90, f"Perfect jitter should be >=0.90, got {jitter}"

        flows = _make_flows(10, 60, bytes_total=512)
        payload = compute_payload_consistency_score(flows)
        assert payload >= 0.90, f"Identical payloads should score >=0.90, got {payload}"

        _pass(f"Check 4 - Individual metrics: regularity={reg} jitter={jitter} payload={payload}")
    except Exception as exc:
        failed = True
        _fail(f"Check 4 - Individual metric checks failed ({exc})")

    # Check 5 — Score is always in [0.0, 1.0]
    try:
        for interval in [1, 10, 60, 300, 3600]:
            flows = _make_flows(count=10, interval_seconds=interval)
            result = analyzer.score(flows)
            score = float(result["beacon_score"])
            assert 0.0 <= score <= 1.0, f"Score out of range: {score}"
        _pass("Check 5 - Score always clamped to [0.0, 1.0] across various intervals")
    except Exception as exc:
        failed = True
        _fail(f"Check 5 - Score range check failed ({exc})")

    # Check 6 — Score real flows from database grouped by src/dst
    try:
        conn = get_db().get_connection()
        flows = get_recent_flows(conn, limit=500)

        # Group by src_ip -> dst_ip
        groups: dict[tuple[str, str], list[FlowRecord]] = {}
        for flow in flows:
            key = (flow.src_ip, flow.dst_ip)
            groups.setdefault(key, []).append(flow)

        scored_pairs = 0
        for (src, dst), group_flows in groups.items():
            result = analyzer.score(group_flows)
            scored_pairs += 1
            if result["finding"]:
                print(f"  BEACON: {src} → {dst} score={result['beacon_score']} flows={result['flow_count']} finding='{result['finding']}'")

        _pass(f"Check 6 - Scored {scored_pairs} src/dst pairs from database")
    except Exception as exc:
        failed = True
        _fail(f"Check 6 - Real flow scoring failed ({exc})")

    if failed:
        print("✗ Day 8 verification FAILED — see errors above")
        return 1

    print("✓ Day 8 verification passed — Beacon detection is ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())