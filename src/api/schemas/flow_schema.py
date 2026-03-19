"""Pydantic schemas for flow API responses."""

from __future__ import annotations
from typing import Any
from pydantic import BaseModel


class FlowResponse(BaseModel):
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    end_time: float | None
    duration_ms: float | None
    packet_count: int
    bytes_total: int
    upload_bytes: int
    download_bytes: int
    status: str
    tcp_flags: dict[str, Any]

    model_config = {"from_attributes": True}
