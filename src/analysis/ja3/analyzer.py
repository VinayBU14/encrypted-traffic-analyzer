
"""JA3 fingerprint analyzer — scores a TLS session based on its JA3 hash."""
 
from __future__ import annotations
 
import logging
from pathlib import Path
 
import yaml
 
from src.analysis.ja3.database import get_ja3_database
from src.storage.models import TLSSessionRecord
 
logger = logging.getLogger(__name__)
 
_CONFIG_PATH = Path(__file__).resolve().parents[3] / "configs" / "default.yaml"
_CONFIG = yaml.safe_load(_CONFIG_PATH.read_text(encoding="utf-8")) or {}
_JA3_CFG = _CONFIG.get("ja3", {})
 
SCORE_MALICIOUS: float = float(_JA3_CFG.get("score_malicious", 0.95))
SCORE_BENIGN: float = float(_JA3_CFG.get("score_benign", 0.00))
SCORE_UNKNOWN: float = float(_JA3_CFG.get("score_unknown", 0.10))
 
 
class JA3Analyzer:
    """Score a TLS session based on JA3 hash threat intel lookup."""
 
    def __init__(self) -> None:
        """Initialize JA3 analyzer with threat intel database."""
        self._db = get_ja3_database()
        logger.info(
            "JA3Analyzer initialized — malicious=%d benign=%d",
            self._db.get_stats()["malicious_count"],
            self._db.get_stats()["benign_count"],
        )
 
    def score(self, session: TLSSessionRecord | None) -> dict[str, object]:
        """Score a TLS session and return score + findings.
 
        Returns a dict with:
            ja3_score (float): 0.0 to 1.0
            ja3_hash (str | None): the hash that was looked up
            finding (str | None): human-readable finding if suspicious
        """
        if session is None or session.ja3_hash is None:
            logger.debug("JA3 score: 0.0 (no session or no JA3 hash)")
            return {
                "ja3_score": 0.0,
                "ja3_hash": None,
                "finding": None,
            }
 
        ja3_hash = session.ja3_hash.strip().lower()
 
        if self._db.is_malicious(ja3_hash):
            label = self._db.get_malicious_label(ja3_hash) or "known malicious"
            finding = f"JA3 hash {ja3_hash[:8]}... matches {label}"
            logger.warning("Malicious JA3 detected: %s (%s)", ja3_hash, label)
            return {
                "ja3_score": SCORE_MALICIOUS,
                "ja3_hash": ja3_hash,
                "finding": finding,
            }
 
        if self._db.is_benign(ja3_hash):
            logger.debug("Benign JA3 hash: %s", ja3_hash)
            return {
                "ja3_score": SCORE_BENIGN,
                "ja3_hash": ja3_hash,
                "finding": None,
            }
 
        # Unknown hash — small non-zero suspicion score
        logger.debug("Unknown JA3 hash: %s (score=%.2f)", ja3_hash, SCORE_UNKNOWN)
        return {
            "ja3_score": SCORE_UNKNOWN,
            "ja3_hash": ja3_hash,
            "finding": None,
        }
 
    def score_from_hash(self, ja3_hash: str | None) -> dict[str, object]:
        """Score directly from a raw JA3 hash string without a session object."""
        if ja3_hash is None:
            return {"ja3_score": 0.0, "ja3_hash": None, "finding": None}
 
        fake_session = TLSSessionRecord(
            session_id="",
            flow_id="",
            cipher_suites=[],
            extensions=[],
            elliptic_curves=[],
            cert_san_list=[],
            cert_is_self_signed=False,
            created_at=0.0,
            ja3_hash=ja3_hash,
        )
        return self.score(fake_session)
 