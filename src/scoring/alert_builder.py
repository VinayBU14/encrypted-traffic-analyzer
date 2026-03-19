"""Alert builder — assembles AlertRecord from all module outputs."""

from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path
from typing import Any

import yaml

from src.storage.models import AlertRecord

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_CONFIG_PATH = _PROJECT_ROOT / "configs" / "default.yaml"
_CONFIG = yaml.safe_load(_CONFIG_PATH.read_text(encoding="utf-8")) or {}
_MAX_FINDINGS: int = int(
    _CONFIG.get("alerts", {}).get("max_findings_per_alert", 10)
)


class AlertBuilder:
    """Build AlertRecord objects from scoring engine and module outputs."""

    def __init__(self) -> None:
        """Initialize alert builder with config-driven limits."""
        logger.info(
            "AlertBuilder initialized — max_findings=%d", _MAX_FINDINGS
        )

    def build(
        self,
        flow_id: str,
        src_ip: str,
        dst_ip: str,
        dst_domain: str | None,
        composite_score: float,
        severity: str,
        recommended_action: str,
        ja3_score: float = 0.0,
        cert_score: float = 0.0,
        beacon_score: float = 0.0,
        graph_score: float = 0.0,
        anomaly_score: float = 0.0,
        findings: list[str] | None = None,
    ) -> AlertRecord:
        """Build and return a complete AlertRecord.

        Args:
            flow_id: The flow this alert is associated with.
            src_ip: Source (internal device) IP.
            dst_ip: Destination IP.
            dst_domain: SNI domain name if available.
            composite_score: Final weighted score from ScoringEngine.
            severity: Severity tier string (CLEAN/LOW/MEDIUM/HIGH/CRITICAL).
            recommended_action: Human readable action string.
            ja3_score: Individual JA3 module score.
            cert_score: Individual certificate module score.
            beacon_score: Individual beacon module score.
            graph_score: Individual graph module score.
            anomaly_score: Isolation forest anomaly score.
            findings: List of human-readable finding strings.

        Returns:
            A populated AlertRecord ready to be inserted into the database.
        """
        all_findings = list(findings or [])

        # Truncate findings to configured max
        if len(all_findings) > _MAX_FINDINGS:
            logger.debug(
                "Truncating findings from %d to %d", len(all_findings), _MAX_FINDINGS
            )
            all_findings = all_findings[:_MAX_FINDINGS]

        alert = AlertRecord(
            alert_id=str(uuid.uuid4()),
            flow_id=flow_id,
            timestamp=time.time(),
            severity=severity,
            composite_score=round(float(composite_score), 4),
            ja3_score=round(float(ja3_score), 4),
            beacon_score=round(float(beacon_score), 4),
            cert_score=round(float(cert_score), 4),
            graph_score=round(float(graph_score), 4),
            anomaly_score=round(float(anomaly_score), 4),
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_domain=dst_domain,
            findings=all_findings,
            recommended_action=recommended_action,
            is_suppressed=False,
            created_at=time.time(),
        )

        logger.info(
            "Alert built: id=%s severity=%s score=%.4f src=%s dst=%s findings=%d",
            alert.alert_id, severity, composite_score,
            src_ip, dst_domain or dst_ip, len(all_findings),
        )
        return alert
