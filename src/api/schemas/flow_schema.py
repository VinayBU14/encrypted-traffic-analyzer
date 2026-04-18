"""Pydantic schemas for flow API responses."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, field_validator


class FlowResponse(BaseModel):
    flow_id:          str
    src_ip:           str
    dst_ip:           str
    src_port:         int
    dst_port:         int
    protocol:         str
    start_time:       float
    end_time:         float | None = None
    duration_ms:      float | None = None
    packet_count:     int = 0
    bytes_total:      int = 0
    upload_bytes:     int = 0
    download_bytes:   int = 0
    status:           str = "CLOSED"
    tcp_flags:        dict[str, Any] = {}
    # FIX: Added fields that the dashboard relies on for filtering + scoring display
    is_live:          int = 0
    severity:         str = "CLEAN"
    composite_score:  float = 0.0
    anomaly_score:    float = 0.0
    ja3_score:        float = 0.0
    beacon_score:     float = 0.0
    cert_score:       float = 0.0
    graph_score:      float = 0.0
    verdict:          str = "BENIGN"
    source:           str = "pcap"

    model_config = {"from_attributes": True}

    @field_validator("tcp_flags", mode="before")
    @classmethod
    def parse_tcp_flags(cls, v: Any) -> dict:
        """Accept a JSON string or dict — always return a dict."""
        if v is None:
            return {}
        if isinstance(v, dict):
            return v
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                return parsed if isinstance(parsed, dict) else {}
            except (json.JSONDecodeError, ValueError):
                return {}
        return {}