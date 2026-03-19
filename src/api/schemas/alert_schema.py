"""Pydantic schemas for alert API responses."""

from __future__ import annotations
from pydantic import BaseModel


class AlertResponse(BaseModel):
    alert_id: str
    flow_id: str | None
    timestamp: float
    severity: str
    composite_score: float
    ja3_score: float | None
    beacon_score: float | None
    cert_score: float | None
    graph_score: float | None
    anomaly_score: float | None
    src_ip: str
    dst_ip: str | None
    dst_domain: str | None
    findings: list[str]
    recommended_action: str | None
    is_suppressed: bool

    model_config = {"from_attributes": True}


class SuppressRequest(BaseModel):
    alert_id: str
