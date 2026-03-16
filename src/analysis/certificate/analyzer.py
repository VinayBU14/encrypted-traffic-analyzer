"""Certificate lifecycle risk analyzer for TLS session metadata."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import yaml

from src.storage.models import TLSSessionRecord

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_CONFIG_PATH = _PROJECT_ROOT / "configs" / "default.yaml"
_CONFIG = yaml.safe_load(_CONFIG_PATH.read_text(encoding="utf-8")) or {}
_CERT_CFG = _CONFIG.get("certificate", {})
_SCORES = _CERT_CFG.get("scores", {})

# Thresholds (days)
VERY_YOUNG_DAYS: float = float(_CERT_CFG.get("very_young_days", 7))
YOUNG_DAYS: float = float(_CERT_CFG.get("young_days", 30))
SHORT_VALIDITY_DAYS: float = float(_CERT_CFG.get("short_validity_days", 7))

# Score values from config
SCORE_VERY_YOUNG: float = float(_SCORES.get("very_young", 0.25))
SCORE_YOUNG: float = float(_SCORES.get("young", 0.15))
SCORE_SELF_SIGNED: float = float(_SCORES.get("self_signed", 0.35))
SCORE_LETSENCRYPT_NEW: float = float(_SCORES.get("letsencrypt_new_domain", 0.20))
SCORE_SAN_CLUSTER: float = float(_SCORES.get("san_cluster", 0.25))
SCORE_BAD_FINGERPRINT: float = float(_SCORES.get("fingerprint_in_bad_db", 0.40))

# Free/automated CAs — new domains on these are slightly suspicious
_FREE_CA_NAMES = ("let's encrypt", "letsencrypt", "zerossl", "buypass")

# Known bad certificate fingerprints (SHA-256)
# In production these would come from a threat intel feed
_BAD_FINGERPRINTS: set[str] = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
}


class CertificateAnalyzer:
    """Analyze TLS certificate metadata and return a risk score with findings."""

    def __init__(self) -> None:
        """Initialize certificate analyzer and logger."""
        self._logger = logging.getLogger(__name__)
        self._logger.info(
            "CertificateAnalyzer initialized — thresholds: very_young=%dd young=%dd",
            VERY_YOUNG_DAYS,
            YOUNG_DAYS,
        )

    def score(self, session: TLSSessionRecord | None) -> dict[str, object]:
        """Score certificate risk for a TLS session.

        Returns a dict with:
            cert_score (float): 0.0 to 1.0 composite risk score
            findings (list[str]): human-readable risk signals found
            cert_age_days (float): age of cert in days (0 if unknown)
            cert_validity_days (float): total validity window in days
        """
        if session is None:
            return {
                "cert_score": 0.0,
                "findings": [],
                "cert_age_days": 0.0,
                "cert_validity_days": 0.0,
            }

        findings: list[str] = []
        composite: float = 0.0
        now = time.time()

        # --- Cert age check ---
        cert_age_days = 0.0
        if session.cert_not_before is not None:
            cert_age_days = max(0.0, (now - float(session.cert_not_before)) / 86400.0)
            if cert_age_days < VERY_YOUNG_DAYS:
                composite += SCORE_VERY_YOUNG
                findings.append(
                    f"Certificate is very new ({cert_age_days:.1f} days old — threshold: {VERY_YOUNG_DAYS}d)"
                )
                self._logger.debug("Cert very young: %.1f days", cert_age_days)
            elif cert_age_days < YOUNG_DAYS:
                composite += SCORE_YOUNG
                findings.append(
                    f"Certificate is recently issued ({cert_age_days:.1f} days old)"
                )

        # --- Validity window check ---
        cert_validity_days = 0.0
        if session.cert_not_before is not None and session.cert_not_after is not None:
            cert_validity_days = max(
                0.0,
                (float(session.cert_not_after) - float(session.cert_not_before)) / 86400.0,
            )
            if 0 < cert_validity_days <= SHORT_VALIDITY_DAYS:
                findings.append(
                    f"Certificate has unusually short validity window ({cert_validity_days:.0f} days)"
                )

        # --- Self-signed check ---
        if session.cert_is_self_signed:
            composite += SCORE_SELF_SIGNED
            findings.append("Certificate is self-signed")
            self._logger.debug("Self-signed certificate detected")

        # --- Free CA + new domain check ---
        if self._is_free_ca(session.cert_issuer):
            if cert_age_days < YOUNG_DAYS:
                composite += SCORE_LETSENCRYPT_NEW
                issuer_short = self._short_issuer(session.cert_issuer)
                findings.append(
                    f"Free CA ({issuer_short}) issued cert for a recently registered domain"
                )
            else:
                # Free CA alone is not suspicious — just note it
                self._logger.debug("Free CA cert but not new: %s", session.cert_issuer)

        # --- SAN cluster check ---
        san_count = len(session.cert_san_list) if session.cert_san_list else 0
        if san_count >= 4:
            composite += SCORE_SAN_CLUSTER
            findings.append(
                f"Certificate covers {san_count} SANs (possible domain clustering)"
            )
        elif san_count >= 2:
            composite += 0.10
            findings.append(f"Certificate covers {san_count} SANs")

        # --- Bad fingerprint check ---
        if session.cert_fingerprint is not None:
            fp = session.cert_fingerprint.lower().strip()
            if fp in _BAD_FINGERPRINTS:
                composite += SCORE_BAD_FINGERPRINT
                findings.append(
                    f"Certificate fingerprint {fp[:16]}... is in known-bad database"
                )
                self._logger.warning("Bad cert fingerprint detected: %s", fp)

        # Clamp composite to [0.0, 1.0]
        cert_score = min(1.0, max(0.0, composite))

        if cert_score > 0.0:
            self._logger.debug(
                "Cert risk score=%.2f findings=%d for session %s",
                cert_score,
                len(findings),
                session.session_id,
            )

        return {
            "cert_score": cert_score,
            "findings": findings,
            "cert_age_days": round(cert_age_days, 2),
            "cert_validity_days": round(cert_validity_days, 2),
        }

    def _is_free_ca(self, issuer: str | None) -> bool:
        """Return True when the issuer is a known free/automated CA."""
        if issuer is None:
            return False
        issuer_lc = issuer.lower()
        return any(name in issuer_lc for name in _FREE_CA_NAMES)

    def _short_issuer(self, issuer: str | None) -> str:
        """Return a short display name for the issuer."""
        if issuer is None:
            return "unknown CA"
        if "encrypt" in issuer.lower():
            return "Let's Encrypt"
        if "zerossl" in issuer.lower():
            return "ZeroSSL"
        if "buypass" in issuer.lower():
            return "Buypass"
        return issuer[:40]
