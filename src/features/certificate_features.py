
"""Certificate risk feature scoring for Module B certificate analysis."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

import yaml

from src.storage.models import TLSSessionRecord


class CertificateFeatureScorer:
    """Compute normalized certificate risk scores from TLS session metadata."""

    def __init__(self) -> None:
        """Load certificate scoring thresholds and initialize logger."""
        config_path = Path(__file__).resolve().parents[2] / "configs" / "default.yaml"
        config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        cert_config = config.get("certificate", {})

        self.very_young_days: float = float(cert_config.get("very_young_days", 7))
        self.young_days: float = float(cert_config.get("young_days", 30))
        self.cert_scores: dict[str, float] = {
            key: float(value) for key, value in (cert_config.get("scores", {}) or {}).items()
        }
        self._logger = logging.getLogger(__name__)

    def score(self, session: TLSSessionRecord | None) -> dict[str, float]:
        """Score certificate risk features, returning zeros when session data is unavailable."""
        if session is None:
            return {
                "cert_age_score": 0.0,
                "self_signed_score": 0.0,
                "san_cluster_score": 0.0,
                "issuer_free_ca_score": 0.0,
                "cert_risk_score": 0.0,
            }

        cert_age_days = 0.0
        if session.cert_not_before is not None:
            cert_age_days = max(0.0, (time.time() - float(session.cert_not_before)) / 86400.0)

        if cert_age_days < self.very_young_days:
            cert_age_score = self._clamp_score(self.cert_scores.get("very_young", 0.25))
        elif cert_age_days < self.young_days:
            cert_age_score = self._clamp_score(self.cert_scores.get("young", 0.15))
        else:
            cert_age_score = 0.0

        self_signed_score = (
            self._clamp_score(self.cert_scores.get("self_signed", 0.35))
            if bool(session.cert_is_self_signed)
            else 0.0
        )

        san_count = len(session.cert_san_list)
        if san_count >= 4:
            san_cluster_score = self._clamp_score(self.cert_scores.get("san_cluster", 0.25))
        elif san_count >= 2:
            san_cluster_score = 0.10
        else:
            san_cluster_score = 0.0

        if self._is_free_ca(session.cert_issuer):
            if cert_age_score > 0.0:
                issuer_free_ca_score = self._clamp_score(
                    self.cert_scores.get("letsencrypt_new_domain", 0.20)
                )
            else:
                issuer_free_ca_score = 0.05
        else:
            issuer_free_ca_score = 0.0

        cert_risk_score = self._clamp_score(
            cert_age_score + self_signed_score + san_cluster_score + issuer_free_ca_score
        )

        result = {
            "cert_age_score": cert_age_score,
            "self_signed_score": self_signed_score,
            "san_cluster_score": san_cluster_score,
            "issuer_free_ca_score": issuer_free_ca_score,
            "cert_risk_score": cert_risk_score,
        }
        self._logger.debug("Computed certificate risk score for session_id=%s", session.session_id)
        return result

    def _is_free_ca(self, issuer: str | None) -> bool:
        """Return True when issuer name indicates a free/automated certificate authority."""
        if issuer is None:
            return False
        issuer_lc = issuer.lower()
        return any(name in issuer_lc for name in ("let's encrypt", "zerossl", "buypass"))

    def _clamp_score(self, value: Any) -> float:
        try:
            parsed = float(value)
        except Exception:
            return 0.0
        if parsed < 0.0:
            return 0.0
        if parsed > 1.0:
            return 1.0
        return parsed
