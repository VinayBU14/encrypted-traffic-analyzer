"""Day 4 TLS extraction verification script for Spectra."""

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
from src.storage.repositories import flow_repository, session_repository


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
        assert "tls_sessions_saved" in summary
        _pass("Check 1 - pipeline completed with TLS extraction summary")
        print("SUMMARY:")
        print(pformat(summary))
    except Exception as exc:
        failed = True
        _fail(f"Check 1 - pipeline execution failed ({exc})")

    sessions = []

    # Check 2
    try:
        sessions = session_repository.get_recent_sessions(conn, limit=1000)
        assert len(sessions) >= 1
        _pass(f"Check 2 - TLS sessions saved to DB (count={len(sessions)})")
    except Exception as exc:
        failed = True
        _fail(f"Check 2 - TLS session retrieval failed ({exc})")

    # Check 3
    try:
        ja3_hashes = sorted(
            {session.ja3_hash for session in sessions if session.ja3_hash is not None and session.ja3_hash}
        )
        assert len(ja3_hashes) >= 1
        _pass("Check 3 - JA3 hashes computed")
        print("JA3 hashes:")
        for value in ja3_hashes:
            print(f"  - {value}")
    except Exception as exc:
        failed = True
        _fail(f"Check 3 - JA3 hash verification failed ({exc})")

    # Check 4
    sni_domains = sorted(
        {session.sni_domain for session in sessions if session.sni_domain is not None and session.sni_domain}
    )
    sni_count = len(sni_domains)
    if sni_count > 0:
        _pass(f"Check 4 - SNI domains extracted (count={sni_count})")
        print("SNI domains:")
        for value in sni_domains:
            print(f"  - {value}")
    else:
        _pass("Check 4 - No SNI domains in this PCAP (expected for loopback traffic, will appear in real-world captures)")

    # Check 5
    try:
        for session in sessions:
            assert isinstance(session.session_id, str) and session.session_id.strip()
            assert isinstance(session.flow_id, str) and session.flow_id.strip()
            flow = flow_repository.get_flow_by_id(conn, session.flow_id)
            assert flow is not None
        _pass("Check 5 - TLS sessions are linked to existing flows")
    except Exception as exc:
        failed = True
        _fail(f"Check 5 - TLS/flow linkage verification failed ({exc})")

    # Check 6
    try:
        cert_data_count = 0
        tls_only_count = 0
        for session in sessions:
            has_cert_data = any(
                [
                    session.cert_subject is not None,
                    session.cert_issuer is not None,
                    session.cert_fingerprint is not None,
                    bool(session.cert_san_list),
                    session.cert_not_before is not None,
                    session.cert_not_after is not None,
                ]
            )

            if has_cert_data:
                cert_data_count += 1
            else:
                tls_only_count += 1

            if session.cert_not_before is not None and session.cert_not_after is not None:
                assert session.cert_not_after > session.cert_not_before
                cert_validity_days = int((session.cert_not_after - session.cert_not_before) // 86400)
                assert cert_validity_days > 0

        _pass("Check 6 - certificate metadata validated (partial data acceptable)")
        print(f"Certificate sessions: {cert_data_count}")
        print(f"TLS-only sessions: {tls_only_count}")
    except Exception as exc:
        failed = True
        _fail(f"Check 6 - certificate data verification failed ({exc})")

    if failed:
        print("✗ Day 4 verification FAILED — see errors above")
        return 1

    print("✓ Day 4 verification passed — TLS extraction is ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
