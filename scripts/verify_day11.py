"""Day 11 — Scoring engine verification script for Spectra."""

from __future__ import annotations

import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.scoring.engine import ScoringEngine
from src.scoring.severity import get_severity, get_recommended_action
from src.scoring.alert_builder import AlertBuilder
from src.scoring.deduplicator import Deduplicator
from src.scoring.whitelist import Whitelist


def _pass(msg: str) -> None:
    print(f"PASS: {msg}")


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}")


def main() -> int:
    failed = False
    engine = ScoringEngine()
    builder = AlertBuilder()
    dedup = Deduplicator(suppress_seconds=5)
    whitelist = Whitelist()

    # Check 1 — Severity tiers map correctly
    try:
        assert get_severity(0.10) == "CLEAN"
        assert get_severity(0.30) == "LOW"
        assert get_severity(0.60) == "MEDIUM"
        assert get_severity(0.75) == "HIGH"
        assert get_severity(0.95) == "CRITICAL"
        _pass("Check 1 - Severity tiers map correctly: CLEAN/LOW/MEDIUM/HIGH/CRITICAL")
    except Exception as exc:
        failed = True
        _fail(f"Check 1 - Severity mapping failed ({exc})")

    # Check 2 — Composite formula is correct
    try:
        result = engine.compute(ja3_score=1.0, cert_score=0.0, beacon_score=0.0, graph_score=0.0)
        expected = round(0.35 * 1.0, 4)
        assert abs(float(result["composite_score"]) - expected) < 0.001
        _pass(f"Check 2 - Composite formula correct: ja3=1.0 only → score={result['composite_score']} (expected {expected})")
    except Exception as exc:
        failed = True
        _fail(f"Check 2 - Composite formula failed ({exc})")

    # Check 3 — All clean scores give CLEAN severity
    try:
        result = engine.compute(0.0, 0.0, 0.0, 0.0, 0.0)
        assert result["severity"] == "CLEAN"
        assert float(result["composite_score"]) == 0.0
        _pass("Check 3 - All zero scores → CLEAN severity")
    except Exception as exc:
        failed = True
        _fail(f"Check 3 - Zero score handling failed ({exc})")

    # Check 4 — Anomaly uplift fires correctly
    try:
        # anomaly=0.8 > 0.7, composite=0.3 < 0.5 → should uplift
        result = engine.compute(
            ja3_score=0.10, cert_score=0.10, beacon_score=0.10, graph_score=0.10,
            anomaly_score=0.80,
        )
        assert result["uplift_applied"] is True
        assert float(result["composite_score"]) > float(result["pre_uplift_score"])
        _pass(
            f"Check 4 - Anomaly uplift fires: "
            f"pre={result['pre_uplift_score']} → post={result['composite_score']} "
            f"severity={result['severity']}"
        )
    except Exception as exc:
        failed = True
        _fail(f"Check 4 - Anomaly uplift failed ({exc})")

    # Check 5 — Anomaly uplift does NOT fire when composite already high
    try:
        result = engine.compute(
            ja3_score=0.95, cert_score=0.50, beacon_score=0.50, graph_score=0.50,
            anomaly_score=0.80,
        )
        assert result["uplift_applied"] is False
        _pass(f"Check 5 - Uplift correctly skipped when composite already high: score={result['composite_score']}")
    except Exception as exc:
        failed = True
        _fail(f"Check 5 - Uplift suppression failed ({exc})")

    # Check 6 — AlertBuilder produces valid AlertRecord
    try:
        score_result = engine.compute(
            ja3_score=0.95, cert_score=0.35, beacon_score=0.60, graph_score=0.45
        )
        alert = builder.build(
            flow_id="test-flow-001",
            src_ip="192.168.1.10",
            dst_ip="185.220.101.1",
            dst_domain="evil.example.com",
            composite_score=score_result["composite_score"],
            severity=score_result["severity"],
            recommended_action=score_result["recommended_action"],
            ja3_score=0.95,
            cert_score=0.35,
            beacon_score=0.60,
            graph_score=0.45,
            findings=["JA3 hash matches Emotet malware", "Self-signed certificate", "Beacon detected"],
        )
        assert alert.alert_id is not None
        assert alert.severity in ("CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert 0.0 <= alert.composite_score <= 1.0
        assert len(alert.findings) <= 10
        _pass(
            f"Check 6 - AlertRecord built: severity={alert.severity} "
            f"score={alert.composite_score} findings={len(alert.findings)}"
        )
    except Exception as exc:
        failed = True
        _fail(f"Check 6 - AlertBuilder failed ({exc})")

    # Check 7 — Deduplicator suppresses within window, allows after
    try:
        dedup.clear()
        assert not dedup.is_duplicate("10.0.0.1", "1.2.3.4")
        dedup.register("10.0.0.1", "1.2.3.4")
        assert dedup.is_duplicate("10.0.0.1", "1.2.3.4")

        # Different pair should not be suppressed
        assert not dedup.is_duplicate("10.0.0.2", "1.2.3.4")

        # After window expires, should allow again
        time.sleep(6)
        assert not dedup.is_duplicate("10.0.0.1", "1.2.3.4")
        _pass("Check 7 - Deduplicator suppresses within window, allows after expiry")
    except Exception as exc:
        failed = True
        _fail(f"Check 7 - Deduplicator failed ({exc})")

    # Check 8 — Whitelist works for IPs and domains
    try:
        assert whitelist.is_whitelisted("8.8.8.8")
        assert whitelist.is_whitelisted("1.1.1.1")
        assert whitelist.is_whitelisted("99.99.99.99", "google.com")
        assert whitelist.is_whitelisted("99.99.99.99", "api.google.com")
        assert not whitelist.is_whitelisted("185.220.101.1", "evil.com")
        _pass("Check 8 - Whitelist correctly filters safe IPs and domains")
    except Exception as exc:
        failed = True
        _fail(f"Check 8 - Whitelist check failed ({exc})")

    # Check 9 — Full end-to-end score → alert pipeline
    try:
        cases = [
            {"ja3": 0.95, "cert": 0.35, "beacon": 0.85, "graph": 0.45, "anomaly": 0.0},
            {"ja3": 0.10, "cert": 0.00, "beacon": 0.00, "graph": 0.00, "anomaly": 0.0},
            {"ja3": 0.10, "cert": 0.10, "beacon": 0.10, "graph": 0.10, "anomaly": 0.90},
        ]
        for case in cases:
            r = engine.compute(
                ja3_score=case["ja3"], cert_score=case["cert"],
                beacon_score=case["beacon"], graph_score=case["graph"],
                anomaly_score=case["anomaly"],
            )
            print(f"  CASE: ja3={case['ja3']} beacon={case['beacon']} → composite={r['composite_score']} severity={r['severity']} uplift={r['uplift_applied']}")
            assert r["severity"] in ("CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL")
        _pass("Check 9 - End-to-end scoring pipeline works for all test cases")
    except Exception as exc:
        failed = True
        _fail(f"Check 9 - End-to-end pipeline failed ({exc})")

    if failed:
        print("✗ Day 11 verification FAILED — see errors above")
        return 1

    print("✓ Day 11 verification passed — Scoring engine is ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())