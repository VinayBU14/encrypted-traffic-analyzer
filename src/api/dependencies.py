"""Shared FastAPI dependencies — per-request database connection."""

from __future__ import annotations

import sqlite3
from collections.abc import Generator
from pathlib import Path

import yaml

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_CONFIG_PATH = _PROJECT_ROOT / "configs" / "default.yaml"
_CONFIG = yaml.safe_load(_CONFIG_PATH.read_text(encoding="utf-8")) or {}
_DB_PATH = str(
    (_PROJECT_ROOT / _CONFIG.get("storage", {}).get("db_path", "data/spectra.db")).resolve()
)


def get_db_conn() -> Generator[sqlite3.Connection, None, None]:
    """FastAPI dependency — creates a fresh SQLite connection per request.

    SQLite connections are not thread-safe and cannot be shared across
    threads. FastAPI runs each request in its own thread, so we open
    a new connection for every request and let FastAPI close it.
    """
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    try:
        yield conn
    finally:
        conn.close()