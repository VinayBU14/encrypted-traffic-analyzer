"""Pydantic schemas for graph entity API responses."""

from __future__ import annotations
from typing import Any
from pydantic import BaseModel


class EntityNode(BaseModel):
    id: str
    node_type: str
    value: str
    risk_score: float
    is_malicious: bool
    metadata: dict[str, Any] = {}


class GraphResponse(BaseModel):
    node_count: int
    edge_count: int
    nodes: list[EntityNode]
    edges: list[dict[str, Any]]
