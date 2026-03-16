"""Day 6 — JA3 analysis verification script for Spectra."""
 
from __future__ import annotations
 
import sys
from pathlib import Path
 
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
 
from src.analysis.ja3.database import get_ja3_database
from src.analysis.ja3.analyzer import JA3Analyzer
from src.storage.database import get_db
from src.storage.repositories.session_repository import get_recent_sessions
 
 
def _pass(msg: str) -> None:
    print(f"PASS: {msg}")
 
 
def _fail(msg: str) -> None:
    print(f"FAIL: {msg}")
 
 
def main() -> int:
    failed = False
 
    # Check 1 — JA3 database loads
    try:
        db = get_ja3_database()
        stats = db.get_stats()
        assert stats["malicious_count"] > 0, "No malicious hashes loaded"
        assert stats["benign_count"] > 0, "No benign hashes loaded"
        _pass(f"Check 1 - JA3 database loaded (malicious={stats['malicious_count']}, benign={stats['benign_count']})")
    except Exception as exc:
        failed = True
        _fail(f"Check 1 - JA3 database load failed ({exc})")
 
    # Check 2 — Known malicious hash returns 0.95
    try:
        analyzer = JA3Analyzer()
        result = analyzer.score_from_hash("e7d705a3286e19ea42f587b344ee6865")
        assert float(result["ja3_score"]) == 0.95, f"Expected 0.95, got {result['ja3_score']}"
        assert result["finding"] is not None
        _pass(f"Check 2 - Malicious hash scored correctly: score={result['ja3_score']}, finding='{result['finding']}'")
    except Exception as exc:
        failed = True
        _fail(f"Check 2 - Malicious hash scoring failed ({exc})")
 
    # Check 3 — Unknown hash returns 0.10
    try:
        result = analyzer.score_from_hash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        assert float(result["ja3_score"]) == 0.10, f"Expected 0.10, got {result['ja3_score']}"
        assert result["finding"] is None
        _pass(f"Check 3 - Unknown hash scored correctly: score={result['ja3_score']}")
    except Exception as exc:
        failed = True
        _fail(f"Check 3 - Unknown hash scoring failed ({exc})")
 
    # Check 4 — None input returns 0.0
    try:
        result = analyzer.score(None)
        assert float(result["ja3_score"]) == 0.0
        _pass("Check 4 - None session handled gracefully: score=0.0")
    except Exception as exc:
        failed = True
        _fail(f"Check 4 - None session handling failed ({exc})")
 
    # Check 5 — Score real sessions from the database
    try:
        conn = get_db().get_connection()
        sessions = get_recent_sessions(conn, limit=100)
        scored = 0
        for session in sessions:
            result = analyzer.score(session)
            score = float(result["ja3_score"])
            assert 0.0 <= score <= 1.0, f"Score out of range: {score}"
            scored += 1
        _pass(f"Check 5 - Scored {scored} real TLS sessions from database")
 
        # Print sample results
        for session in sessions[:3]:
            result = analyzer.score(session)
            print(f"  SAMPLE: ja3={session.ja3_hash} score={result['ja3_score']} finding={result['finding']}")
    except Exception as exc:
        failed = True
        _fail(f"Check 5 - Real session scoring failed ({exc})")
 
    if failed:
        print("✗ Day 6 verification FAILED — see errors above")
        return 1
 
    print("✓ Day 6 verification passed — JA3 analysis is ready")
    return 0
 
 
if __name__ == "__main__":
    raise SystemExit(main())
 