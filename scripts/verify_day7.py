"""Day 7 — Certificate analysis verification script for Spectra."""

from __future__ import annotations

import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.analysis.certificate.analyzer import CertificateAnalyzer
from src.storage.database import get_db
from src.storage.models import TLSSessionRecord
from src.storage.repositories.session_repository import get_recent_sessions


def _pass(msg: str) -> None:
    print(f"PASS: {msg}")


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}")


def main() -> int:
    failed = False
    analyzer = CertificateAnalyzer()

    # Check 1 — None session returns 0.0 safely
    try:
        result = analyzer.score(None)
        assert float(result["cert_score"]) == 0.0
        assert result["findings"] == []
        _pass("Check 1 - None session handled gracefully: score=0.0")
    except Exception as exc:
        failed = True
        _fail(f"Check 1 - None session handling failed ({exc})")

    # Check 2 — Self-signed cert scores >= 0.35
    try:
        session = TLSSessionRecord(
            session_id="test-self-signed",
            flow_id="flow-001",
            cipher_suites=[],
            extensions=[],
            elliptic_curves=[],
            cert_san_list=[],
            cert_is_self_signed=True,
            created_at=time.time(),
            cert_not_before=time.time() - 86400 * 200,
            cert_not_after=time.time() + 86400 * 165,
        )
        result = analyzer.score(session)
        assert float(result["cert_score"]) >= 0.35, f"Expected >=0.35, got {result['cert_score']}"
        assert any("self-signed" in f.lower() for f in result["findings"])
        _pass(f"Check 2 - Self-signed cert scored: score={result['cert_score']}, findings={result['findings']}")
    except Exception as exc:
        failed = True
        _fail(f"Check 2 - Self-signed cert scoring failed ({exc})")

    # Check 3 — Very new cert scores >= 0.25
    try:
        session = TLSSessionRecord(
            session_id="test-new-cert",
            flow_id="flow-002",
            cipher_suites=[],
            extensions=[],
            elliptic_curves=[],
            cert_san_list=[],
            cert_is_self_signed=False,
            created_at=time.time(),
            cert_not_before=time.time() - 86400 * 2,  # 2 days old
            cert_not_after=time.time() + 86400 * 88,
        )
        result = analyzer.score(session)
        assert float(result["cert_score"]) >= 0.25
        assert any("very new" in f.lower() or "very young" in f.lower() or "new" in f.lower() for f in result["findings"])
        _pass(f"Check 3 - Very new cert scored: score={result['cert_score']}, age={result['cert_age_days']}d")
    except Exception as exc:
        failed = True
        _fail(f"Check 3 - Very new cert scoring failed ({exc})")

    # Check 4 — High SAN count scores >= 0.25
    try:
        session = TLSSessionRecord(
            session_id="test-san-cluster",
            flow_id="flow-003",
            cipher_suites=[],
            extensions=[],
            elliptic_curves=[],
            cert_san_list=["a.com", "b.com", "c.com", "d.com", "e.com"],
            cert_is_self_signed=False,
            created_at=time.time(),
            cert_not_before=time.time() - 86400 * 100,
            cert_not_after=time.time() + 86400 * 265,
        )
        result = analyzer.score(session)
        assert float(result["cert_score"]) >= 0.25
        assert any("san" in f.lower() for f in result["findings"])
        _pass(f"Check 4 - SAN cluster scored: score={result['cert_score']}, findings={result['findings']}")
    except Exception as exc:
        failed = True
        _fail(f"Check 4 - SAN cluster scoring failed ({exc})")

    # Check 5 — Score is always clamped between 0.0 and 1.0
    try:
        # Worst case: self-signed + very new + high SANs + free CA
        session = TLSSessionRecord(
            session_id="test-worst-case",
            flow_id="flow-004",
            cipher_suites=[],
            extensions=[],
            elliptic_curves=[],
            cert_san_list=["a.com", "b.com", "c.com", "d.com", "e.com"],
            cert_is_self_signed=True,
            cert_issuer="Let's Encrypt Authority X3",
            created_at=time.time(),
            cert_not_before=time.time() - 86400 * 1,
            cert_not_after=time.time() + 86400 * 89,
        )
        result = analyzer.score(session)
        score = float(result["cert_score"])
        assert 0.0 <= score <= 1.0, f"Score out of range: {score}"
        _pass(f"Check 5 - Worst-case score clamped correctly: score={score}, findings={len(result['findings'])} signals")
    except Exception as exc:
        failed = True
        _fail(f"Check 5 - Score clamping failed ({exc})")

    # Check 6 — Score real sessions from database
    try:
        conn = get_db().get_connection()
        sessions = get_recent_sessions(conn, limit=100)
        scored = 0
        flagged = 0
        for session in sessions:
            result = analyzer.score(session)
            score = float(result["cert_score"])
            assert 0.0 <= score <= 1.0
            scored += 1
            if score > 0.0:
                flagged += 1
        _pass(f"Check 6 - Scored {scored} real sessions ({flagged} with cert risk > 0)")

        # Print flagged ones
        for session in sessions:
            result = analyzer.score(session)
            if float(result["cert_score"]) > 0.0:
                print(f"  FLAGGED: sni={session.sni_domain} score={result['cert_score']} findings={result['findings']}")
    except Exception as exc:
        failed = True
        _fail(f"Check 6 - Real session scoring failed ({exc})")

    if failed:
        print("✗ Day 7 verification FAILED — see errors above")
        return 1

    print("✓ Day 7 verification passed — Certificate analysis is ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())