"""Day 5 feature engineering verification script for Spectra."""

from __future__ import annotations

import math
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.features.feature_validator import validate_row
from src.features.schema import ALL_FEATURE_COLUMNS
from src.pipeline.orchestrator import PipelineOrchestrator
from src.storage.database import get_db


def _pass(message: str) -> None:
    print(f"PASS: {message}")


def _fail(message: str) -> None:
    print(f"FAIL: {message}")


def main() -> int:
    failed = False
    conn = get_db().get_connection()

    conn.execute("DELETE FROM tls_sessions")
    conn.execute("DELETE FROM alerts")
    conn.execute("DELETE FROM flows")
    conn.commit()

    feature_rows: list[dict[str, Any]] = []

    # Check 1
    try:
        pcap_path = PROJECT_ROOT / "data" / "raw" / "pcap" / "test_sample.pcap"
        orchestrator = PipelineOrchestrator(str(pcap_path))
        summary = orchestrator.run()
        assert "feature_rows_computed" in summary
        assert int(summary["feature_rows_computed"]) > 0
        feature_rows = list(getattr(orchestrator, "_feature_rows", []))
        assert len(feature_rows) > 0
        _pass(f"Check 1 - feature engineering ran (feature_rows_computed={summary['feature_rows_computed']})")
    except Exception as exc:
        failed = True
        _fail(f"Check 1 - pipeline/feature stage failed ({exc})")

    # Check 2
    try:
        sample_rows = feature_rows[:5]
        assert sample_rows
        for row in sample_rows:
            for column in ALL_FEATURE_COLUMNS:
                assert column in row
                value = row[column]
                assert value is not None
                numeric = float(value)
                assert not math.isnan(numeric)
                assert not math.isinf(numeric)
        _pass(f"Check 2 - schema completeness verified ({len(ALL_FEATURE_COLUMNS)} feature columns)")
    except Exception as exc:
        failed = True
        _fail(f"Check 2 - feature schema completeness failed ({exc})")

    # Check 3
    try:
        for row in feature_rows:
            assert float(row["duration_ms"]) >= 0.0
            assert float(row["total_packets"]) > 0.0
            assert float(row["total_bytes"]) > 0.0
            assert float(row["packet_rate_per_sec"]) >= 0.0
            assert float(row["avg_packet_size"]) > 0.0
        _pass("Check 3 - flow feature sanity checks passed")
    except Exception as exc:
        failed = True
        _fail(f"Check 3 - flow feature sanity failed ({exc})")

    # Check 4
    try:
        tls_rows = [row for row in feature_rows if float(row["tls_seen"]) == 1.0]
        for row in tls_rows:
            assert float(row["tls_version_code"]) > 0.0
            assert float(row["tls_cipher_suite_count"]) > 0.0
        _pass(f"Check 4 - TLS feature values verified ({len(tls_rows)} rows with tls_seen=1.0)")
    except Exception as exc:
        failed = True
        _fail(f"Check 4 - TLS feature verification failed ({exc})")

    # Check 5
    try:
        cert_rows = [row for row in feature_rows if float(row["tls_cert_present"]) == 1.0]
        for row in cert_rows:
            risk = float(row["cert_risk_score"])
            assert 0.0 <= risk <= 1.0
            assert float(row["tls_cert_validity_days"]) > 0.0

        bucket_zero = 0
        bucket_low = 0
        bucket_high = 0
        for row in cert_rows:
            risk = float(row["cert_risk_score"])
            if risk == 0.0:
                bucket_zero += 1
            elif 0.01 <= risk <= 0.25:
                bucket_low += 1
            else:
                bucket_high += 1

        _pass("Check 5 - certificate scoring values verified")
        print(f"0.0: {bucket_zero} flows")
        print(f"0.01-0.25: {bucket_low} flows")
        print(f"0.25+: {bucket_high} flows")
    except Exception as exc:
        failed = True
        _fail(f"Check 5 - certificate scoring verification failed ({exc})")

    # Check 6
    try:
        broken = dict(feature_rows[0])
        broken.pop(ALL_FEATURE_COLUMNS[0], None)
        try:
            validate_row(broken)
            raise AssertionError("validate_row did not raise for malformed row")
        except ValueError:
            _pass("PASS: validator correctly rejects malformed rows")
    except Exception as exc:
        failed = True
        _fail(f"Check 6 - validator rejection check failed ({exc})")

    if failed:
        print("✗ Day 5 verification FAILED — see errors above")
        return 1

    print("✓ Day 5 verification passed — feature engineering is ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
