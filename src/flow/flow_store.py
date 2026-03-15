
"""Flow persistence batching bridge between flow reconstruction and storage."""

from __future__ import annotations

import logging

from src.storage.database import get_db
from src.storage.models import FlowRecord
from src.storage.repositories import flow_repository


class FlowStore:
    """Batch and persist completed flows into SQLite storage."""

    def __init__(self, batch_size: int = 50) -> None:
        """Initialize pending flow buffer and persistence counters."""
        self._pending: list[FlowRecord] = []
        self._batch_size = batch_size
        self._total_saved = 0
        self._logger = logging.getLogger(__name__)

    def add(self, flow: FlowRecord) -> None:
        """Add a flow to the pending batch and flush when batch size is reached."""
        self._pending.append(flow)
        if len(self._pending) >= self._batch_size:
            self.flush()

    def flush(self) -> int:
        """Persist pending flows to storage and return count written on success."""
        if not self._pending:
            return 0

        try:
            conn = get_db().get_connection()
            for flow in self._pending:
                flow_repository.insert_flow(conn, flow)
            written = len(self._pending)
            self._pending.clear()
            self._total_saved += written
            self._logger.info("Flushed %d flows to database", written)
            return written
        except Exception as exc:
            self._logger.error("Failed to flush flows to database: %s", exc)
            return 0

    def flush_all(self) -> int:
        """Flush all pending flows regardless of configured batch size."""
        total_flushed = 0
        while self._pending:
            flushed = self.flush()
            if flushed == 0:
                break
            total_flushed += flushed
        return total_flushed

    def get_stats(self) -> dict[str, int]:
        """Return pending queue size and cumulative saved flow count."""
        return {"pending": len(self._pending), "total_saved": self._total_saved}
