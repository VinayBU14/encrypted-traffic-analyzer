
"""Database connection and schema initialization management for Spectra."""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from types import TracebackType
from typing import Any

import yaml

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manage SQLite connection lifecycle and schema initialization."""

    def __init__(self, db_path: str) -> None:
        """Initialize the database manager with a database path."""
        self.db_path = db_path
        self.connection: sqlite3.Connection | None = None

    def connect(self) -> None:
        """Open a SQLite connection and configure required PRAGMA settings."""
        self.connection = sqlite3.connect(self.db_path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL;")
        self.connection.execute("PRAGMA foreign_keys=ON;")
        logger.info("Database connection opened and WAL mode enabled: %s", self.db_path)

    def disconnect(self) -> None:
        """Close the active SQLite connection if one exists."""
        if self.connection is not None:
            self.connection.close()
            self.connection = None
            logger.info("Database connection closed")

    def get_connection(self) -> sqlite3.Connection:
        """Return the active SQLite connection."""
        if self.connection is None:
            raise RuntimeError(
                "Database connection is not initialized. Call connect() before requesting a connection."
            )
        return self.connection

    def initialize_schema(self) -> None:
        """Create database schema from the SQL migration file."""
        project_root = Path(__file__).resolve().parents[2]
        migration_path = project_root / "src" / "storage" / "migrations" / "v1_init.sql"
        sql_script = migration_path.read_text(encoding="utf-8")
        connection = self.get_connection()
        connection.executescript(sql_script)
        connection.commit()
        logger.info("Database schema initialized from %s", migration_path)

    def __enter__(self) -> DatabaseManager:
        """Enter context manager scope and return this database manager."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Exit context manager scope and close any active connection."""
        self.disconnect()


_db_instance: DatabaseManager | None = None


def _resolve_db_path_from_config() -> str:
    project_root = Path(__file__).resolve().parents[2]
    config_path = project_root / "configs" / "default.yaml"
    config_data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}

    storage_config = config_data.get("storage", {})
    db_path = storage_config.get("db_path")
    if not isinstance(db_path, str) or not db_path.strip():
        raise RuntimeError("Missing or invalid storage.db_path in configs/default.yaml")

    return str((project_root / db_path).resolve())


def get_db() -> DatabaseManager:
    """Return a singleton database manager, initializing it on first use."""
    global _db_instance
    if _db_instance is not None:
        logger.info("Returning existing DB connection")
        return _db_instance

    resolved_db_path = _resolve_db_path_from_config()
    Path(resolved_db_path).parent.mkdir(parents=True, exist_ok=True)

    _db_instance = DatabaseManager(db_path=resolved_db_path)
    _db_instance.connect()
    _db_instance.initialize_schema()
    return _db_instance
