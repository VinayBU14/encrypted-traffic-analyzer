"""Severity tier mapping from composite score to human-readable level."""

from __future__ import annotations

from pathlib import Path

import yaml

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_CONFIG_PATH = _PROJECT_ROOT / "configs" / "default.yaml"
_CONFIG = yaml.safe_load(_CONFIG_PATH.read_text(encoding="utf-8")) or {}
_THRESHOLDS = _CONFIG.get("scoring", {}).get("thresholds", {})

THRESHOLD_CLEAN: float = float(_THRESHOLDS.get("clean", 0.30))
THRESHOLD_LOW: float = float(_THRESHOLDS.get("low", 0.60))
THRESHOLD_MEDIUM: float = float(_THRESHOLDS.get("medium", 0.75))
THRESHOLD_HIGH: float = float(_THRESHOLDS.get("high", 0.90))


def get_severity(composite_score: float) -> str:
    """Map a composite score float to a severity tier string.

    Tiers (from config/default.yaml):
        CLEAN    < 0.30
        LOW      < 0.60
        MEDIUM   < 0.75
        HIGH     < 0.90
        CRITICAL >= 0.90
    """
    score = float(composite_score)
    if score < THRESHOLD_CLEAN:
        return "CLEAN"
    if score < THRESHOLD_LOW:
        return "LOW"
    if score < THRESHOLD_MEDIUM:
        return "MEDIUM"
    if score < THRESHOLD_HIGH:
        return "HIGH"
    return "CRITICAL"


def get_recommended_action(severity: str) -> str:
    """Return a recommended action string based on severity tier."""
    actions = {
        "CLEAN": "No action required.",
        "LOW": "Monitor this host for further suspicious activity.",
        "MEDIUM": "Investigate this connection — review flow history and destination reputation.",
        "HIGH": "Isolate or block this host pending investigation.",
        "CRITICAL": "Immediate containment recommended — likely active threat.",
    }
    return actions.get(severity, "Review manually.")
