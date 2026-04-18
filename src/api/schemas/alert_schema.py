"""Pydantic schemas for alert API responses."""

from __future__ import annotations
from typing import Any, Optional
from pydantic import BaseModel, field_validator
import json


class AlertResponse(BaseModel):
    alert_id:           str
    flow_id:            Optional[str] = None
    timestamp:          float = 0.0
    severity:           str = ""
    composite_score:    float = 0.0
    ja3_score:          Optional[float] = None
    beacon_score:       Optional[float] = None
    cert_score:         Optional[float] = None
    graph_score:        Optional[float] = None
    anomaly_score:      Optional[float] = None
    src_ip:             str = ""
    src_port:           int = 0
    dst_ip:             Optional[str] = None
    dst_port:           int = 0
    dst_domain:         Optional[str] = None
    findings:           list[str] = []
    recommended_action: Optional[str] = None
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

    # Coerce None → "" for all string fields that may be NULL in the DB
    @field_validator(
        "alert_id", "severity", "src_ip",
        "groq_summary", "groq_explanation", "groq_action",
        "groq_threat_type", "groq_confidence",
        mode="before",
    )
    @classmethod
    def str_none_to_empty(cls, v: Any) -> Any:
        return "" if v is None else v

    # Coerce None → 0.0 for float fields
    @field_validator("timestamp", "composite_score", mode="before")
    @classmethod
    def float_none_to_zero(cls, v: Any) -> Any:
        return 0.0 if v is None else v

    # Coerce None → 0 for int fields
    @field_validator("src_port", "dst_port", "is_live", "is_beacon", mode="before")
    @classmethod
    def int_none_to_zero(cls, v: Any) -> Any:
        return 0 if v is None else v

    # Coerce None → False for bool fields
    @field_validator("is_suppressed", mode="before")
    @classmethod
    def bool_none_to_false(cls, v: Any) -> Any:
        return False if v is None else v


class SuppressRequest(BaseModel):
    alert_id: str