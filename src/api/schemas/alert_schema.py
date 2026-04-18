"""Pydantic schemas for alert API responses."""

from __future__ import annotations
from typing import Any
from pydantic import BaseModel, field_validator
import json


class AlertResponse(BaseModel):
    alert_id:           str
    flow_id:            str | None = None
    timestamp:          float = 0.0
    severity:           str = ""
    composite_score:    float = 0.0
    ja3_score:          float | None = None
    beacon_score:       float | None = None
    cert_score:         float | None = None
    graph_score:        float | None = None
    anomaly_score:      float | None = None
    src_ip:             str = ""
    src_port:           int = 0
    dst_ip:             str | None = None
    dst_port:           int = 0
    dst_domain:         str | None = None
    findings:           list[str] = []
    recommended_action: str | None = None
    is_suppressed:      bool = False
    is_live:            int = 0
    is_beacon:          int = 0
    groq_summary:       str = ""
    groq_explanation:   str = ""
    groq_action:        str = ""
    groq_threat_type:   str = ""
    groq_confidence:    str = ""

    model_config = {"from_attributes": True}

    @field_validator("findings", mode="before")
    @classmethod
    def parse_findings(cls, v: Any) -> list:
        """Accept JSON string or list — always return a list."""
        if v is None:
            return []
        if isinstance(v, list):
            return v
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                return parsed if isinstance(parsed, list) else [v] if v else []
            except Exception:
                return [v] if v else []
        return []


class SuppressRequest(BaseModel):
    alert_id: str