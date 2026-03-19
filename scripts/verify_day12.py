"""Day 12 — Pipeline runner verification script for Spectra."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.pipeline.runner import run_pipeline
from src.storage.database import get_db
from src.storage.repositories import alert_repository


def _pass(msg: str) -> None:
    print(f"PASS: {msg}")


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}")


def main() -> int:
    failed = False

    # Clean slate
    conn = get_db().get_connection()
    conn.execute("DELETE FROM alerts")
    conn.execute("DELETE FROM tls_sessions")
    conn.execute("DELETE FROM flows")
    conn.commit()

    pcap_path = str(PROJECT_ROOT / "data" / "raw" / "pcap" / "test_sample.pcap")

    # Check 1 — Pipeline runs without error
    try:
        summary = run_pipeline(pcap_path, retrain=True)
        assert "alerts_created" in summary
        assert "flows_scored" in summary
        assert summary["elapsed_seconds"] > 0
        _pass(
            f"Check 1 - Pipeline completed in {summary['elapsed_seconds']}s: "
            f"flows={summary['flows_completed']} scored={summary['flows_scored']} "
            f"alerts={summary['alerts_created']}"
        )
    except Exception as exc:
        failed = True
        _fail(f"Check 1 - Pipeline run failed ({exc})")
        return 1

    # Check 2 — Alerts written to database
    try:
        alerts = alert_repository.get_recent_alerts(conn, limit=100)
        _pass(f"Check 2 - Alerts in database: {len(alerts)} alerts created")
        for alert in alerts[:5]:
            print(
                f"  ALERT: severity={alert.severity} score={alert.composite_score} "
                f"src={alert.src_ip} dst={alert.dst_domain or alert.dst_ip} "
                f"findings={len(alert.findings)}"
            )
    except Exception as exc:
        failed = True
        _fail(f"Check 2 - Alert retrieval failed ({exc})")

    # Check 3 — Alert fields are valid
    try:
        alerts = alert_repository.get_recent_alerts(conn, limit=100)
        for alert in alerts:
            assert alert.alert_id is not None
            assert alert.severity in ("CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL")
            assert 0.0 <= alert.composite_score <= 1.0
            assert isinstance(alert.findings, list)
            assert alert.src_ip is not None
        _pass(f"Check 3 - All {len(alerts)} alert records have valid fields")
    except Exception as exc:
        failed = True
        _fail(f"Check 3 - Alert field validation failed ({exc})")

    # Check 4 — Severity counts
    try:
        counts = alert_repository.get_alert_counts_by_severity(conn)
        _pass(f"Check 4 - Alert severity breakdown: {counts}")
    except Exception as exc:
        failed = True
        _fail(f"Check 4 - Severity count query failed ({exc})")

    # Check 5 — Graph stats in summary
    try:
        assert summary["graph_nodes"] >= 0
        assert summary["graph_edges"] >= 0
        _pass(
            f"Check 5 - Graph stats: {summary['graph_nodes']} nodes, "
            f"{summary['graph_edges']} edges"
        )
    except Exception as exc:
        failed = True
        _fail(f"Check 5 - Graph stats check failed ({exc})")

    if failed:
        print("✗ Day 12 verification FAILED — see errors above")
        return 1

    print("✓ Day 12 verification passed — Pipeline runner is ready")
    print(f"\nYou can now run the full pipeline with:")
    print(f"  python -m src.pipeline.runner --pcap data/raw/pcap/test_sample.pcap")
    print(f"  python -m src.pipeline.runner --pcap data/raw/pcap/test_sample.pcap --retrain")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())