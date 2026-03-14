"""Day 1 setup verification script for Spectra."""

from __future__ import annotations

import sys
import time
from decimal import Decimal
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.storage.database import get_db
from src.storage.models import SCHEMA_VERSION, FlowRecord
from src.storage.repositories.flow_repository import get_flow_by_id, insert_flow


def _print_pass(message: str) -> None:
    print(f"PASS: {message}")


def _print_fail(message: str) -> None:
    print(f"FAIL: {message}")


def main() -> int:
    failed = False
    conn = None

    # Check 1
    try:
        config_path = PROJECT_ROOT / "configs" / "default.yaml"
        config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        weights = config["scoring"]["weights"]
        ja3 = Decimal(str(weights["ja3"]))
        beacon = Decimal(str(weights["beacon"]))
        cert = Decimal(str(weights["cert"]))
        graph = Decimal(str(weights["graph"]))
        total = ja3 + beacon + cert + graph
        assert total == Decimal("1.0")
        _print_pass(
            f"Check 1 - loaded config and weights sum to 1.0: "
            f"ja3={ja3}, beacon={beacon}, cert={cert}, graph={graph}"
        )
    except Exception as exc:
        failed = True
        _print_fail(f"Check 1 - config/weights validation failed ({exc})")

    # Check 2
    try:
        db = get_db()
        conn = db.get_connection()
        _print_pass("Check 2 - DatabaseManager initialized and connection opened")
    except Exception as exc:
        failed = True
        _print_fail(f"Check 2 - database initialization failed ({exc})")
        conn = None

    # Check 3
    try:
        if conn is None:
            raise RuntimeError("No active database connection")
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
        tables = {row["name"] for row in rows}
        expected = {"flows", "tls_sessions", "alerts", "graph_entities"}
        missing = expected - tables
        assert not missing
        _print_pass("Check 3 - required tables exist")
    except Exception as exc:
        failed = True
        _print_fail(f"Check 3 - table verification failed ({exc})")

    # Check 4
    try:
        if conn is None:
            raise RuntimeError("No active database connection")
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index'"
        ).fetchall()
        indexes = {row["name"] for row in rows}
        assert len(indexes) >= 8
        _print_pass(f"Check 4 - index verification passed (found {len(indexes)} indexes)")
    except Exception as exc:
        failed = True
        _print_fail(f"Check 4 - index verification failed ({exc})")

    # Check 5
    test_flow_id = f"verify-day1-{int(time.time())}"
    try:
        if conn is None:
            raise RuntimeError("No active database connection")
        flow = FlowRecord(
            flow_id=test_flow_id,
            src_ip="10.0.0.1",
            dst_ip="1.1.1.1",
            src_port=50000,
            dst_port=443,
            protocol="TCP",
            start_time=float(time.time()),
            packet_count=3,
            bytes_total=1500,
            upload_bytes=900,
            download_bytes=600,
            packet_sizes=[500.0, 500.0, 500.0],
            inter_arrival_ms=[10.0, 20.0],
            tcp_flags={"SYN": 1, "ACK": 2},
            created_at=float(time.time()),
        )
        insert_flow(conn, flow)
        retrieved = get_flow_by_id(conn, test_flow_id)
        assert retrieved is not None
        assert retrieved.flow_id == flow.flow_id
        assert retrieved.src_ip == flow.src_ip
        assert retrieved.dst_ip == flow.dst_ip
        assert retrieved.packet_sizes == flow.packet_sizes
        assert retrieved.tcp_flags == flow.tcp_flags
        _print_pass("Check 5 - insert/retrieve flow verification passed")
    except Exception as exc:
        failed = True
        _print_fail(f"Check 5 - flow insert/retrieve failed ({exc})")
    finally:
        if conn is not None:
            conn.execute("DELETE FROM flows WHERE flow_id = ?", (test_flow_id,))
            conn.commit()

    # Check 6
    try:
        config_path = PROJECT_ROOT / "configs" / "default.yaml"
        config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        config_schema_version = str(config["project"]["schema_version"])
        assert SCHEMA_VERSION == config_schema_version
        _print_pass("Check 6 - schema version consistency verified")
    except Exception as exc:
        failed = True
        _print_fail(f"Check 6 - schema version mismatch ({exc})")

    if failed:
        print("✗ Day 1 verification FAILED — see errors above")
        return 1

    print("✓ Day 1 verification passed — Spectra foundation is ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
