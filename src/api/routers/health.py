"""Health check router."""

from __future__ import annotations

import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends

from src.api.dependencies import get_db_conn

router = APIRouter(prefix="/health", tags=["health"])

DBConn = Annotated[sqlite3.Connection, Depends(get_db_conn)]


@router.get("")
def health_check(conn: DBConn = None) -> dict:
    """Return API health status and database connectivity."""
    try:
        conn.execute("SELECT 1").fetchone()
        db_status = "ok"
    except Exception as exc:
        db_status = f"error: {exc}"

    return {
        "status": "ok",
        "database": db_status,
        "service": "Spectra Encrypted Traffic Analyzer",
    }