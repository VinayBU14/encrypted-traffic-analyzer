"""Pydantic schemas for flow API responses."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, field_validator


class FlowResponse(BaseModel):
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    end_time: float | None = None
    duration_ms: float | None = None
    packet_count: int
    bytes_total: int
    upload_bytes: int
    download_bytes: int
    status: str
    tcp_flags: dict[str, Any] = {}

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