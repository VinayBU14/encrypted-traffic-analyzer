"""Entities router — graph node queries for the infrastructure view."""

from __future__ import annotations

import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from src.api.dependencies import get_db_conn
from src.api.schemas.entity_schema import GraphResponse
from src.graph.builder import GraphBuilder
from src.graph.serializer import GraphSerializer
from src.storage.repositories import flow_repository, session_repository

router = APIRouter(prefix="/entities", tags=["entities"])

DBConn = Annotated[sqlite3.Connection, Depends(get_db_conn)]


@router.get("/graph", response_model=GraphResponse)
def get_graph(
    limit: int = Query(default=1000, le=5000),
    conn: DBConn = None,
) -> dict:
    """Return the full infrastructure graph as nodes and edges."""
    flows = flow_repository.get_recent_flows(conn, limit=limit)
    sessions = session_repository.get_recent_sessions(conn, limit=limit)
    builder = GraphBuilder()
    serializer = GraphSerializer()
    graph = builder.build(flows, sessions)
    return serializer.to_dict(graph)


@router.get("/high-risk")
def get_high_risk_nodes(
    threshold: float = Query(default=0.30, ge=0.0, le=1.0),
    limit: int = Query(default=1000, le=5000),
    conn: DBConn = None,
) -> list[dict]:
    """Return graph nodes with risk score above the given threshold."""
    flows = flow_repository.get_recent_flows(conn, limit=limit)
    sessions = session_repository.get_recent_sessions(conn, limit=limit)
    builder = GraphBuilder()
    serializer = GraphSerializer()
    graph = builder.build(flows, sessions)
    return serializer.get_high_risk_nodes(graph, threshold=threshold)