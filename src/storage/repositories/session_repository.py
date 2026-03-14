
"""Repository functions for tls_sessions table operations."""

from __future__ import annotations

import json
import logging
import sqlite3

from src.storage.models import TLSSessionRecord

logger = logging.getLogger(__name__)


def _row_to_session(row: sqlite3.Row) -> TLSSessionRecord:
    cipher_suites = json.loads(row["cipher_suites"]) if row["cipher_suites"] else []
    extensions = json.loads(row["extensions"]) if row["extensions"] else []
    elliptic_curves = json.loads(row["elliptic_curves"]) if row["elliptic_curves"] else []
    cert_san_list = json.loads(row["cert_san_list"]) if row["cert_san_list"] else []

    return TLSSessionRecord(
        session_id=row["session_id"],
        flow_id=row["flow_id"],
        cipher_suites=cipher_suites,
        extensions=extensions,
        elliptic_curves=elliptic_curves,
        cert_san_list=cert_san_list,
        cert_is_self_signed=bool(row["cert_is_self_signed"]),
        created_at=row["created_at"],
        sni_domain=row["sni_domain"],
        ja3_hash=row["ja3_hash"],
        tls_version=row["tls_version"],
        cert_subject=row["cert_subject"],
        cert_issuer=row["cert_issuer"],
        cert_not_before=row["cert_not_before"],
        cert_not_after=row["cert_not_after"],
        cert_fingerprint=row["cert_fingerprint"],
    )


def insert_tls_session(conn: sqlite3.Connection, session: TLSSessionRecord) -> None:
    """Insert a TLS session row into tls_sessions table."""
    conn.execute(
        """
        INSERT INTO tls_sessions (
            session_id, flow_id, sni_domain, ja3_hash, tls_version,
            cipher_suites, extensions, elliptic_curves, cert_subject,
            cert_issuer, cert_not_before, cert_not_after, cert_fingerprint,
            cert_san_list, cert_is_self_signed, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session.session_id,
            session.flow_id,
            session.sni_domain,
            session.ja3_hash,
            session.tls_version,
            json.dumps(session.cipher_suites),
            json.dumps(session.extensions),
            json.dumps(session.elliptic_curves),
            session.cert_subject,
            session.cert_issuer,
            session.cert_not_before,
            session.cert_not_after,
            session.cert_fingerprint,
            json.dumps(session.cert_san_list),
            int(session.cert_is_self_signed),
            session.created_at,
        ),
    )
    conn.commit()
    logger.info("Inserted TLS session: %s", session.session_id)


def get_session_by_flow_id(conn: sqlite3.Connection, flow_id: str) -> TLSSessionRecord | None:
    """Fetch a TLS session by associated flow_id."""
    row = conn.execute("SELECT * FROM tls_sessions WHERE flow_id = ?", (flow_id,)).fetchone()
    if row is None:
        return None
    return _row_to_session(row)


def get_sessions_by_ja3(conn: sqlite3.Connection, ja3_hash: str) -> list[TLSSessionRecord]:
    """Return TLS sessions for a given JA3 hash."""
    rows = conn.execute(
        "SELECT * FROM tls_sessions WHERE ja3_hash = ? ORDER BY created_at DESC",
        (ja3_hash,),
    ).fetchall()
    return [_row_to_session(row) for row in rows]


def get_sessions_by_domain(conn: sqlite3.Connection, domain: str) -> list[TLSSessionRecord]:
    """Return TLS sessions for a given SNI domain."""
    rows = conn.execute(
        "SELECT * FROM tls_sessions WHERE sni_domain = ? ORDER BY created_at DESC",
        (domain,),
    ).fetchall()
    return [_row_to_session(row) for row in rows]


def get_recent_sessions(conn: sqlite3.Connection, limit: int = 100) -> list[TLSSessionRecord]:
    """Return recent TLS sessions ordered by created_at descending."""
    rows = conn.execute(
        "SELECT * FROM tls_sessions ORDER BY created_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [_row_to_session(row) for row in rows]
