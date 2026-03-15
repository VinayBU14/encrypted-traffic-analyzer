
"""TLS-derived feature extraction from TLSSessionRecord objects."""

from __future__ import annotations

import logging
import time
from pathlib import Path

import yaml

from src.features.schema import TLS_FEATURE_COLUMNS
from src.storage.models import TLSSessionRecord


class TLSFeatureExtractor:
    """Compute normalized TLS feature values used by downstream analysis stages."""

    def __init__(self) -> None:
        """Load certificate threshold config and initialize extractor logger."""
        config_path = Path(__file__).resolve().parents[2] / "configs" / "default.yaml"
        config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        cert_cfg = config.get("certificate", {})
        self.very_young_days: float = float(cert_cfg.get("very_young_days", 7))
        self.young_days: float = float(cert_cfg.get("young_days", 30))
        self.short_validity_days: float = float(cert_cfg.get("short_validity_days", 7))
        self._logger = logging.getLogger(__name__)

    def extract(self, session: TLSSessionRecord | None) -> dict[str, float]:
        """Extract TLS feature columns as float values, returning zeros for missing session."""
        if session is None:
            return {column: 0.0 for column in TLS_FEATURE_COLUMNS}

        cert_validity_days = 0.0
        if session.cert_not_before is not None and session.cert_not_after is not None:
            cert_validity_days = self._safe_float(
                (session.cert_not_after - session.cert_not_before) / 86400.0
            )
            if cert_validity_days < 0.0:
                cert_validity_days = 0.0

        cert_age_days = 0.0
        if session.cert_not_before is not None:
            cert_age_days = self._safe_float((time.time() - session.cert_not_before) / 86400.0)
            if cert_age_days < 0.0:
                cert_age_days = 0.0

        features: dict[str, float] = {
            "tls_seen": 1.0,
            "tls_version_code": self._safe_float(session.tls_version if session.tls_version is not None else 0.0),
            "tls_cipher_suite_count": self._safe_float(len(session.cipher_suites)),
            "tls_extension_count": self._safe_float(len(session.extensions)),
            "tls_sni_present": 1.0 if session.sni_domain is not None else 0.0,
            "tls_cert_present": 1.0 if session.cert_fingerprint is not None else 0.0,
            "tls_cert_validity_days": cert_validity_days,
            "tls_cert_self_signed": 1.0 if session.cert_is_self_signed else 0.0,
            "tls_cert_san_count": self._safe_float(len(session.cert_san_list)),
            "tls_cert_age_days": cert_age_days,
        }

        for column in TLS_FEATURE_COLUMNS:
            if column not in features:
                features[column] = 0.0

        self._logger.debug("Extracted TLS features for session_id=%s", session.session_id)
        return {column: self._safe_float(features[column]) for column in TLS_FEATURE_COLUMNS}

    def _safe_float(self, value: object) -> float:
        try:
            parsed = float(value)
            if parsed != parsed or parsed in (float("inf"), float("-inf")):
                return 0.0
            return parsed
        except Exception:
            return 0.0
