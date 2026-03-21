"""Rule-based explanation generator for suspicious encrypted traffic flows."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

BASELINE_STATS: dict[str, dict[str, float]] = {
    "duration_ms": {"mean": 1200.0, "std": 800.0},
    "packet_rate_per_sec": {"mean": 12.0, "std": 8.0},
    "avg_packet_size": {"mean": 512.0, "std": 200.0},
    "std_packet_size": {"mean": 45.0, "std": 30.0},
    "mean_iat_ms": {"mean": 85.0, "std": 60.0},
    "std_iat_ms": {"mean": 40.0, "std": 25.0},
    "bytes_total": {"mean": 15000.0, "std": 12000.0},
    "tls_cert_age_days": {"mean": 400.0, "std": 300.0},
}

DEVIATION_THRESHOLD: float = 2.0

FEATURE_LABELS: dict[str, str] = {
    "duration_ms": "Flow duration",
    "packet_rate_per_sec": "Packet rate",
    "avg_packet_size": "Avg packet size",
    "std_packet_size": "Packet size variance",
    "mean_iat_ms": "Avg inter-arrival time",
    "std_iat_ms": "IAT variance",
    "bytes_total": "Total bytes",
    "tls_cert_age_days": "Certificate age",
}


class RuleExplainer:
    """Generate structured, human-readable explanation payloads from module outputs."""

    def explain(
        self,
        feature_row: dict[str, Any],
        alert: dict[str, Any],
        ja3_result: dict[str, Any],
        cert_result: dict[str, Any],
        beacon_result: dict[str, Any],
        graph_result: dict[str, Any],
    ) -> dict[str, Any]:
        """Build a normalized explanation dictionary for a flagged flow."""
        severity = str(alert.get("severity", "LOW")).upper()
        composite_score = float(alert.get("composite_score", alert.get("risk_score", 0.0)))

        module_scores: dict[str, float] = {
            "JA3": float(ja3_result.get("ja3_score", 0.0)),
            "Certificate": float(cert_result.get("cert_score", 0.0)),
            "Beacon": float(beacon_result.get("beacon_score", 0.0)),
            "Graph": float(graph_result.get("graph_score", 0.0)),
        }

        technical_findings: list[str] = []
        ja3_finding = ja3_result.get("finding")
        if isinstance(ja3_finding, str) and ja3_finding:
            technical_findings.append(ja3_finding)

        cert_findings = cert_result.get("findings", [])
        if isinstance(cert_findings, list):
            technical_findings.extend(str(item) for item in cert_findings if item)

        beacon_finding = beacon_result.get("finding")
        if isinstance(beacon_finding, str) and beacon_finding:
            technical_findings.append(beacon_finding)

        graph_findings = graph_result.get("findings", [])
        if isinstance(graph_findings, list):
            technical_findings.extend(str(item) for item in graph_findings if item)

        alert_findings = alert.get("findings", [])
        if isinstance(alert_findings, list):
            technical_findings.extend(str(item) for item in alert_findings if item)

        technical_findings = list(dict.fromkeys(technical_findings))

        deviations: list[dict[str, Any]] = []
        for feature in BASELINE_STATS:
            if feature not in feature_row:
                continue
            try:
                deviation = self._compute_deviation(feature, float(feature_row[feature]))
            except (TypeError, ValueError):
                logger.debug("Skipping non-numeric feature for deviation: %s", feature)
                continue
            if float(deviation["z_score"]) > DEVIATION_THRESHOLD:
                deviations.append(deviation)

        risk_factors: list[str] = []
        if isinstance(cert_findings, list):
            for finding in cert_findings:
                if not finding:
                    continue
                short = str(finding).strip().split(".")[0]
                if short:
                    risk_factors.append(short)

        if float(beacon_result.get("beacon_score", 0.0)) > 0.5:
            risk_factors.append("Periodic beaconing pattern detected")
        if float(ja3_result.get("ja3_score", 0.0)) > 0.5:
            risk_factors.append("Known malicious TLS fingerprint")
        if float(beacon_result.get("time_score", 0.0)) > 0.6:
            risk_factors.append("Traffic during anomalous hours (midnight–6am)")

        for deviation in deviations:
            if float(deviation.get("z_score", 0.0)) > 4.0:
                label = str(deviation.get("label", deviation.get("feature", "Feature")))
                risk_factors.append(f"{label} far outside normal range")

        risk_factors = list(dict.fromkeys(risk_factors))

        recommended_action = str(alert.get("recommended_action", "")).strip()
        if not recommended_action:
            if severity in {"CRITICAL", "HIGH"}:
                recommended_action = "Isolate endpoint and block destination pending investigation."
            elif severity == "MEDIUM":
                recommended_action = "Escalate for analyst review and monitor for recurrence."
            else:
                recommended_action = "Monitor traffic and enrich with additional telemetry."

        headline = self._build_headline(
            severity=severity,
            composite_score=composite_score,
            beacon_result=beacon_result,
            ja3_result=ja3_result,
            cert_result=cert_result,
        )

        return {
            "headline": headline,
            "severity": severity,
            "composite_score": composite_score,
            "src_ip": str(feature_row.get("src_ip", alert.get("src_ip", ""))),
            "dst_ip": str(feature_row.get("dst_ip", alert.get("dst_ip", ""))),
            "technical_findings": technical_findings,
            "deviations": deviations,
            "risk_factors": risk_factors,
            "module_scores": module_scores,
            "recommended_action": recommended_action,
        }

    def _compute_deviation(self, feature: str, value: float) -> dict[str, Any]:
        baseline = BASELINE_STATS.get(feature, {"mean": 0.0, "std": 0.0})
        mean = float(baseline.get("mean", 0.0))
        std = float(baseline.get("std", 0.0))
        z_score = abs(value - mean) / std if std > 0 else 0.0
        direction = "above" if value >= mean else "below"
        verdict = f"⚠ {z_score:.1f}× {direction} normal"
        return {
            "feature": feature,
            "label": FEATURE_LABELS.get(feature, feature),
            "observed": float(value),
            "baseline_mean": mean,
            "baseline_std": std,
            "z_score": float(z_score),
            "verdict": verdict,
            "is_anomalous": bool(z_score > DEVIATION_THRESHOLD),
        }

    def _build_headline(
        self,
        severity: str,
        composite_score: float,
        beacon_result: dict[str, Any],
        ja3_result: dict[str, Any],
        cert_result: dict[str, Any],
    ) -> str:
        _ = composite_score
        ja3_score = float(ja3_result.get("ja3_score", 0.0))
        ja3_finding = str(ja3_result.get("finding", "")).strip()
        if ja3_score > 0.9 and ja3_finding:
            reason = ja3_finding
        elif float(beacon_result.get("beacon_score", 0.0)) > 0.6:
            mean_interval = float(beacon_result.get("mean_interval", 0.0))
            reason = f"C2 beacon detected ({mean_interval:.0f}s interval)"
        elif float(cert_result.get("cert_score", 0.0)) > 0.5:
            reason = "Suspicious certificate infrastructure"
        else:
            reason = "Anomalous encrypted traffic pattern"
        return f"{severity} — {reason}"
