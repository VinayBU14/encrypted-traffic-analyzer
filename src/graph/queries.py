"""Graph query functions for detecting suspicious infrastructure patterns."""

from __future__ import annotations

import logging
from pathlib import Path

import networkx as nx
import yaml

from src.graph.entities import EdgeType, NodeType

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_CONFIG_PATH = _PROJECT_ROOT / "configs" / "default.yaml"
_CONFIG = yaml.safe_load(_CONFIG_PATH.read_text(encoding="utf-8")) or {}
_GRAPH_CFG = _CONFIG.get("graph", {})
_SCORES = _GRAPH_CFG.get("scores", {})
_THRESHOLDS = _GRAPH_CFG.get("thresholds", {})

SCORE_CERT_FANOUT: float = float(_SCORES.get("cert_fanout", 0.35))
SCORE_MALICIOUS_IP: float = float(_SCORES.get("malicious_ip", 0.45))
SCORE_MULTI_DEVICE: float = float(_SCORES.get("multi_device", 0.50))
SCORE_KNOWN_CAMPAIGN: float = float(_SCORES.get("known_campaign", 0.60))

CERT_FANOUT_MIN_DOMAINS: int = int(_THRESHOLDS.get("cert_fanout_min_domains", 3))
MULTI_DEVICE_MIN_COUNT: int = int(_THRESHOLDS.get("multi_device_min_count", 2))


def query_cert_fanout(graph: nx.DiGraph, target_ip: str) -> dict[str, object]:
    """Detect if the certificate used by target_ip covers many unrelated domains.

    High SAN count on a new cert is a common malware infrastructure technique.
    Returns score > 0 if the cert node attached to this IP has >= min_domains SANs.
    """
    ip_id = f"ip:{target_ip}"
    if ip_id not in graph:
        return {"graph_score": 0.0, "finding": None}

    # Walk: ip ← domain → cert, or ip → cert directly
    cert_nodes = []
    for neighbor in graph.predecessors(ip_id):
        node_data = graph.nodes.get(neighbor, {})
        if node_data.get("node_type") == NodeType.DOMAIN.value:
            for cert_neighbor in graph.successors(neighbor):
                cert_data = graph.nodes.get(cert_neighbor, {})
                if cert_data.get("node_type") == NodeType.CERTIFICATE.value:
                    cert_nodes.append((cert_neighbor, cert_data))
        elif node_data.get("node_type") == NodeType.CERTIFICATE.value:
            cert_nodes.append((neighbor, node_data))

    for cert_id, cert_data in cert_nodes:
        san_count = int(cert_data.get("san_count", 0))
        if san_count >= CERT_FANOUT_MIN_DOMAINS:
            finding = (
                f"Certificate fanout: cert covers {san_count} domains "
                f"(threshold: {CERT_FANOUT_MIN_DOMAINS})"
            )
            logger.debug("Cert fanout detected for %s: %s", target_ip, finding)
            return {"graph_score": SCORE_CERT_FANOUT, "finding": finding}

    return {"graph_score": 0.0, "finding": None}


def query_malicious_ip(graph: nx.DiGraph, target_ip: str) -> dict[str, object]:
    """Check if target_ip or any neighbor is flagged as malicious in threat intel."""
    ip_id = f"ip:{target_ip}"
    if ip_id not in graph:
        return {"graph_score": 0.0, "finding": None}

    # Direct check on the target IP node
    node_data = graph.nodes.get(ip_id, {})
    if node_data.get("is_malicious", False):
        finding = f"Destination IP {target_ip} is in threat intelligence feed"
        logger.warning("Malicious IP in graph: %s", target_ip)
        return {"graph_score": SCORE_MALICIOUS_IP, "finding": finding}

    # Check malicious neighbors (1-hop)
    for neighbor in list(graph.predecessors(ip_id)) + list(graph.successors(ip_id)):
        neighbor_data = graph.nodes.get(neighbor, {})
        if neighbor_data.get("is_malicious", False):
            finding = (
                f"IP {target_ip} is 1 hop from known-malicious node "
                f"{neighbor_data.get('value', neighbor)}"
            )
            return {"graph_score": SCORE_MALICIOUS_IP * 0.5, "finding": finding}

    return {"graph_score": 0.0, "finding": None}


def query_multi_device(graph: nx.DiGraph, target_ip: str) -> dict[str, object]:
    """Detect if multiple internal devices are all connecting to the same destination.

    Multiple compromised hosts beaconing to the same C2 is a strong signal.
    """
    ip_id = f"ip:{target_ip}"
    if ip_id not in graph:
        return {"graph_score": 0.0, "finding": None}

    # Count unique device nodes pointing at this IP (directly or via domain)
    device_nodes: set[str] = set()
    for predecessor in graph.predecessors(ip_id):
        pred_data = graph.nodes.get(predecessor, {})
        if pred_data.get("node_type") == NodeType.DEVICE.value:
            device_nodes.add(predecessor)
        elif pred_data.get("node_type") == NodeType.DOMAIN.value:
            for domain_pred in graph.predecessors(predecessor):
                dp_data = graph.nodes.get(domain_pred, {})
                if dp_data.get("node_type") == NodeType.DEVICE.value:
                    device_nodes.add(domain_pred)

    if len(device_nodes) >= MULTI_DEVICE_MIN_COUNT:
        finding = (
            f"Multi-device convergence: {len(device_nodes)} devices "
            f"all contacting {target_ip}"
        )
        logger.debug("Multi-device convergence: %s", finding)
        return {"graph_score": SCORE_MULTI_DEVICE, "finding": finding}

    return {"graph_score": 0.0, "finding": None}


def query_malicious_neighbor_proximity(
    graph: nx.DiGraph, target_ip: str
) -> dict[str, object]:
    """Check if target_ip shares infrastructure with known-malicious campaigns.

    If a certificate used by target_ip is also used by a known-malicious domain,
    that's strong evidence of shared malicious infrastructure.
    """
    ip_id = f"ip:{target_ip}"
    if ip_id not in graph:
        return {"graph_score": 0.0, "finding": None}

    # Find all certs reachable from this IP
    reachable_certs: set[str] = set()
    for predecessor in graph.predecessors(ip_id):
        pred_data = graph.nodes.get(predecessor, {})
        if pred_data.get("node_type") in (NodeType.DOMAIN.value, NodeType.IP.value):
            for node in graph.successors(predecessor):
                node_data = graph.nodes.get(node, {})
                if node_data.get("node_type") == NodeType.CERTIFICATE.value:
                    reachable_certs.add(node)

    # Check if any of those certs connect to malicious nodes
    for cert_id in reachable_certs:
        for cert_neighbor in list(graph.predecessors(cert_id)) + list(graph.successors(cert_id)):
            neighbor_data = graph.nodes.get(cert_neighbor, {})
            if neighbor_data.get("is_malicious", False):
                finding = (
                    f"Shared malicious infrastructure: cert used by {target_ip} "
                    f"also linked to malicious node {neighbor_data.get('value', cert_neighbor)}"
                )
                return {"graph_score": SCORE_KNOWN_CAMPAIGN, "finding": finding}

    return {"graph_score": 0.0, "finding": None}


def run_all_queries(graph: nx.DiGraph, target_ip: str) -> dict[str, object]:
    """Run all 4 graph queries for a target IP and return combined results."""
    fanout = query_cert_fanout(graph, target_ip)
    malicious = query_malicious_ip(graph, target_ip)
    multi = query_multi_device(graph, target_ip)
    proximity = query_malicious_neighbor_proximity(graph, target_ip)

    # Take the max score from all queries (most severe signal wins)
    all_scores = [
        float(fanout["graph_score"]),
        float(malicious["graph_score"]),
        float(multi["graph_score"]),
        float(proximity["graph_score"]),
    ]
    graph_score = min(1.0, max(all_scores))

    findings = [
        r["finding"]
        for r in [fanout, malicious, multi, proximity]
        if r["finding"] is not None
    ]

    return {
        "graph_score": round(graph_score, 4),
        "findings": findings,
        "cert_fanout_score": fanout["graph_score"],
        "malicious_ip_score": malicious["graph_score"],
        "multi_device_score": multi["graph_score"],
        "proximity_score": proximity["graph_score"],
    }
