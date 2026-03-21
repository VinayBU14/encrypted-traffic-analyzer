"""AI-assisted explanation wrapper for Spectra alert narratives."""

from __future__ import annotations

import logging
import os
from typing import Any

try:
    import anthropic

    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False

logger = logging.getLogger(__name__)


class AIExplainer:
    """Generate plain-English SOC summaries from structured rule explanations."""

    def __init__(self) -> None:
        """Initialize Anthropic client availability and API connectivity state."""
        self._available: bool = False
        self._client: Any | None = None
        try:
            if not _ANTHROPIC_AVAILABLE:
                logger.warning("anthropic package not installed — running in rule-based mode")
                self._available = False
                return

            key = os.getenv("SPECTRA_ANTHROPIC_KEY")
            if key is None or key.strip() == "":
                logger.info("SPECTRA_ANTHROPIC_KEY not set — running in rule-based mode")
                self._available = False
                return

            self._client = anthropic.Anthropic(api_key=key)
            self._available = True
            logger.info("AIExplainer ready — Claude API connected")
        except Exception as exc:
            logger.error("AIExplainer initialization failed: %s", exc)
            self._available = False
            self._client = None

    def explain(self, rule_explanation: dict[str, Any]) -> dict[str, Any]:
        """Return rule explanation enriched with AI-generated plain-English summary."""
        result: dict[str, Any] = dict(rule_explanation)
        if not self._available or self._client is None:
            result["plain_english"] = self._fallback_summary(rule_explanation)
            return result

        try:
            severity = str(rule_explanation.get("severity", "LOW"))
            composite_score = float(rule_explanation.get("composite_score", 0.0))
            headline = str(rule_explanation.get("headline", ""))
            technical_findings = rule_explanation.get("technical_findings", [])
            deviations = rule_explanation.get("deviations", [])

            findings_bullet_list = "\n".join(f"• {f}" for f in technical_findings[:5]) or "• None reported"
            deviations_text = (
                "\n".join(
                    f"• {d['label']}: {d['observed']:.1f} vs normal {d['baseline_mean']:.1f} ± {d['baseline_std']:.1f} (z={d['z_score']:.1f})"
                    for d in deviations[:4]
                )
                or "• None reported"
            )

            system_message = (
                "You are a cybersecurity analyst assistant for a network threat detection system "
                "called Spectra. Be concise, technical, and direct. Maximum 3 sentences."
            )

            user_message = (
                "Explain this security alert in plain English for a SOC analyst:\n\n"
                f"Severity: {severity}\n"
                f"Risk Score: {composite_score:.2f}\n"
                f"Headline: {headline}\n\n"
                f"Technical findings:\n{findings_bullet_list}\n\n"
                f"Statistical deviations from baseline:\n{deviations_text}\n\n"
                "Be specific about what the numbers mean and what the analyst should do next."
            )

            response = self._client.messages.create(
                model="claude-haiku-4-5",
                max_tokens=200,
                messages=[{"role": "user", "content": user_message}],
                system=system_message,
            )
            result["plain_english"] = response.content[0].text.strip()
            return result
        except Exception as exc:
            logger.error("Claude explanation failed: %s", exc)
            result["plain_english"] = self._fallback_summary(rule_explanation)
            return result

    def _fallback_summary(self, explanation: dict[str, Any]) -> str:
        severity = str(explanation.get("severity", "LOW"))
        src_ip = str(explanation.get("src_ip", "unknown"))
        dst_ip = str(explanation.get("dst_ip", "unknown"))
        dst_domain = explanation.get("dst_domain")
        technical_findings = explanation.get("technical_findings", [])
        recommended_action = str(explanation.get("recommended_action", "")).strip()
        target = str(dst_domain) if dst_domain else dst_ip

        top_signals = ", ".join(technical_findings[:2]) if technical_findings else "anomalous traffic pattern"
        return (
            f"This {severity} alert from {src_ip} to {target} detected {len(technical_findings)} suspicious signal(s). "
            f"Top signals: {top_signals}. "
            f"{recommended_action}"
        )
