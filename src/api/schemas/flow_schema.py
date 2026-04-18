"""Pydantic schemas for flow API responses."""

from __future__ import annotations

import json
from typing import Any, Optional

from pydantic import BaseModel, field_validator


class FlowResponse(BaseModel):
    flow_id:          str
    src_ip:           str
    dst_ip:           str
    src_port:         int
    dst_port:         int
    protocol:         str
    start_time:       float
    end_time:         Optional[float] = None
    duration_ms:      Optional[float] = None
    packet_count:     int = 0
    bytes_total:      int = 0
    upload_bytes:     int = 0
    download_bytes:   int = 0
    status:           str = "CLOSED"
    tcp_flags:        dict[str, Any] = {}
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

    # Coerce None → "" for every string field that the DB may store as NULL
    @field_validator(
        "flow_id", "src_ip", "dst_ip", "protocol",
        "status", "severity", "verdict", "source",
        mode="before",
    )
    @classmethod
    def str_none_to_empty(cls, v: Any) -> Any:
        return "" if v is None else v

    # Coerce None → 0.0 for float fields
    @field_validator(
        "start_time", "composite_score", "anomaly_score",
        "ja3_score", "beacon_score", "cert_score", "graph_score",
        mode="before",
    )
    @classmethod
    def float_none_to_zero(cls, v: Any) -> Any:
        return 0.0 if v is None else v

    # Coerce None → 0 for int fields
    @field_validator(
        "src_port", "dst_port", "packet_count", "bytes_total",
        "upload_bytes", "download_bytes", "is_live",
        mode="before",
    )
    @classmethod
    def int_none_to_zero(cls, v: Any) -> Any:
        return 0 if v is None else v