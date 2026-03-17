"""Graph serializer — converts NetworkX graph to JSON-serializable dicts."""

from __future__ import annotations

import logging

import networkx as nx

logger = logging.getLogger(__name__)


class GraphSerializer:
    """Serialize a NetworkX DiGraph to JSON-compatible structures for the API."""

    def to_dict(self, graph: nx.DiGraph) -> dict:
        """Convert graph to a dict with nodes and edges lists."""
        nodes = []
        for node_id, data in graph.nodes(data=True):
            nodes.append({
                "id": node_id,
                "node_type": data.get("node_type", "unknown"),
                "value": data.get("value", node_id),
                "risk_score": round(float(data.get("risk_score", 0.0)), 4),
                "is_malicious": bool(data.get("is_malicious", False)),
                "metadata": {
                    k: v for k, v in data.items()
                    if k not in ("node_type", "value", "risk_score", "is_malicious")
                },
            })

        edges = []
        for src, dst, data in graph.edges(data=True):
            edges.append({
                "source": src,
                "target": dst,
                "edge_type": data.get("edge_type", "unknown"),
                "weight": float(data.get("weight", 1.0)),
                "metadata": {
                    k: v for k, v in data.items()
                    if k not in ("edge_type", "weight")
                },
            })

        return {
            "node_count": graph.number_of_nodes(),
            "edge_count": graph.number_of_edges(),
            "nodes": nodes,
            "edges": edges,
        }

    def get_high_risk_nodes(self, graph: nx.DiGraph, threshold: float = 0.30) -> list[dict]:
        """Return nodes with risk_score above threshold, sorted descending."""
        risky = []
        for node_id, data in graph.nodes(data=True):
            score = float(data.get("risk_score", 0.0))
            if score >= threshold:
                risky.append({
                    "id": node_id,
                    "node_type": data.get("node_type", "unknown"),
                    "value": data.get("value", node_id),
                    "risk_score": round(score, 4),
                    "is_malicious": bool(data.get("is_malicious", False)),
                })
        return sorted(risky, key=lambda x: x["risk_score"], reverse=True)
