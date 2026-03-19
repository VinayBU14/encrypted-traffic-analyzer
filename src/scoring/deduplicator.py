"""Alert deduplicator — suppresses repeated alerts for the same src/dst within a time window."""

from __future__ import annotations

import logging
import time
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_CONFIG_PATH = _PROJECT_ROOT / "configs" / "default.yaml"
_CONFIG = yaml.safe_load(_CONFIG_PATH.read_text(encoding="utf-8")) or {}
_SUPPRESS_SECONDS: float = float(
    _CONFIG.get("alerts", {}).get("suppress_seconds", 300)
)


class Deduplicator:
    """Track recently raised alerts and suppress duplicates within a time window."""

    def __init__(self, suppress_seconds: float = _SUPPRESS_SECONDS) -> None:
        """Initialize deduplicator with configurable suppression window."""
        self._suppress_seconds = suppress_seconds
        # key: (src_ip, dst_ip) → last alert timestamp
        self._seen: dict[tuple[str, str], float] = {}
        logger.info(
            "Deduplicator initialized — suppress_seconds=%.0f", suppress_seconds
        )

    def is_duplicate(self, src_ip: str, dst_ip: str) -> bool:
        """Return True if this src/dst pair was already alerted within the suppress window."""
        key = (src_ip, dst_ip)
        last_seen = self._seen.get(key)
        if last_seen is None:
            return False
        age = time.time() - last_seen
        if age < self._suppress_seconds:
            logger.debug(
                "Suppressing duplicate alert: %s → %s (last seen %.0fs ago)",
                src_ip, dst_ip, age,
            )
            return True
        return False

    def register(self, src_ip: str, dst_ip: str) -> None:
        """Register that an alert was raised for this src/dst pair right now."""
        self._seen[(src_ip, dst_ip)] = time.time()
        logger.debug("Registered alert: %s → %s", src_ip, dst_ip)

    def clear(self) -> None:
        """Clear all suppression state (useful for testing)."""
        self._seen.clear()

    def get_stats(self) -> dict[str, int]:
        """Return count of currently tracked src/dst pairs."""
        return {"tracked_pairs": len(self._seen)}
