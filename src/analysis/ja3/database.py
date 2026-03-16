"""JA3 threat intelligence database loader."""
 
from __future__ import annotations
 
import json
import logging
from pathlib import Path
 
logger = logging.getLogger(__name__)
 
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_MALICIOUS_PATH = _PROJECT_ROOT / "data" / "threat_intel" / "ja3_malicious.json"
_BENIGN_PATH = _PROJECT_ROOT / "data" / "threat_intel" / "ja3_benign.json"
 
 
class JA3Database:
    """Load and query JA3 hash threat intelligence lists."""
 
    def __init__(self) -> None:
        """Load malicious and benign JA3 hash lists from threat intel files."""
        self._malicious: dict[str, str] = {}
        self._benign: dict[str, str] = {}
        self._load()
 
    def _load(self) -> None:
        """Load both JA3 JSON files into memory."""
        try:
            raw = _MALICIOUS_PATH.read_text(encoding="utf-8").strip()
            self._malicious = json.loads(raw) if raw else {}
            logger.info("Loaded %d malicious JA3 hashes", len(self._malicious))
        except Exception as exc:
            logger.warning("Failed to load malicious JA3 list: %s", exc)
            self._malicious = {}
 
        try:
            raw = _BENIGN_PATH.read_text(encoding="utf-8").strip()
            self._benign = json.loads(raw) if raw else {}
            logger.info("Loaded %d benign JA3 hashes", len(self._benign))
        except Exception as exc:
            logger.warning("Failed to load benign JA3 list: %s", exc)
            self._benign = {}
 
    def is_malicious(self, ja3_hash: str) -> bool:
        """Return True if the hash is in the malicious list."""
        return ja3_hash.lower() in self._malicious
 
    def is_benign(self, ja3_hash: str) -> bool:
        """Return True if the hash is in the benign list."""
        return ja3_hash.lower() in self._benign
 
    def get_malicious_label(self, ja3_hash: str) -> str | None:
        """Return the malware family name for a known malicious hash."""
        return self._malicious.get(ja3_hash.lower())
 
    def get_stats(self) -> dict[str, int]:
        """Return count of loaded malicious and benign hashes."""
        return {
            "malicious_count": len(self._malicious),
            "benign_count": len(self._benign),
        }
 
 
_db_instance: JA3Database | None = None
 
 
def get_ja3_database() -> JA3Database:
    """Return the singleton JA3Database instance."""
    global _db_instance
    if _db_instance is None:
        _db_instance = JA3Database()
    return _db_instance
