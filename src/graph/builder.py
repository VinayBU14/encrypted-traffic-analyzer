"""Infrastructure graph builder — constructs NetworkX graph from flows and TLS sessions."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import networkx as nx

from src.graph.entities import EdgeType, GraphEdge, GraphNode, NodeType
from src.storage.models import FlowRecord, TLSSessionRecord

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_IP_REPUTATION_PATH = _PROJECT_ROOT / "data" / "threat_intel" / "ip_reputation.json"


def _load_malicious_ips() -> set[str]:
    """Load known malicious IPs from threat intel file."""
    try:
        raw = _IP_REPUTATION_PATH.read_text(encoding="utf-8").strip()
        if not raw:
            return set()
        data = json.loads(raw)
        malicious = set(data.get("malicious_ips", []))
        malicious.update(data.get("tor_exit_nodes", []))
        malicious.update(data.get("known_c2_servers", []))
        return malicious
    except Exception as exc:
        logger.warning("Could not load IP reputation data: %s", exc)
        return set()


_MALICIOUS_IPS: set[str] = _load_malicious_ips()


class GraphBuilder:
    """Build a directed NetworkX graph from flow and TLS session records."""

    def __init__(self) -> None:
        """Initialize an empty graph."""
        self._graph: nx.DiGraph = nx.DiGraph()
        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []
        logger.info("GraphBuilder initialized (malicious_ips loaded: %d)", len(_MALICIOUS_IPS))

    def build(
        self,
        flows: list[FlowRecord],
        sessions: list[TLSSessionRecord],
    ) -> nx.DiGraph:
        """Build the full infrastructure graph from flows and TLS sessions.

        Args:
            flows: All FlowRecords to include.
            sessions: All TLSSessionRecords to include.

        Returns:
            A populated NetworkX DiGraph.
        """
        self._graph.clear()
        self._nodes.clear()
        self._edges.clear()

        # Map flow_id → flow for quick lookup
        flow_map: dict[str, FlowRecord] = {f.flow_id: f for f in flows}

        # Add flow-level nodes and edges
        for flow in flows:
            self._add_flow(flow)

        # Add TLS session nodes and edges
        for session in sessions:
            flow = flow_map.get(session.flow_id)
            self._add_tls_session(session, flow)

        logger.info(
            "Graph built: %d nodes, %d edges",
            self._graph.number_of_nodes(),
            self._graph.number_of_edges(),
        )
        return self._graph

    def get_graph(self) -> nx.DiGraph:
        """Return the current graph."""
        return self._graph

    def _add_flow(self, flow: FlowRecord) -> None:
        """Add device and IP nodes with a CONTACTED edge for a flow."""
        device_id = f"device:{flow.src_ip}"
        ip_id = f"ip:{flow.dst_ip}"

        # Device node (source)
        if device_id not in self._graph:
            self._graph.add_node(
                device_id,
                node_type=NodeType.DEVICE.value,
                value=flow.src_ip,
                risk_score=0.0,
                is_malicious=False,
            )

        # IP node (destination)
        is_malicious_ip = flow.dst_ip in _MALICIOUS_IPS
        if ip_id not in self._graph:
            self._graph.add_node(
                ip_id,
                node_type=NodeType.IP.value,
                value=flow.dst_ip,
                risk_score=0.90 if is_malicious_ip else 0.0,
                is_malicious=is_malicious_ip,
            )

        # CONTACTED edge — weight = number of flows (increments on repeated contact)
        if self._graph.has_edge(device_id, ip_id):
            self._graph[device_id][ip_id]["weight"] += 1
            self._graph[device_id][ip_id]["total_bytes"] = (
                self._graph[device_id][ip_id].get("total_bytes", 0) + flow.bytes_total
            )
        else:
            self._graph.add_edge(
                device_id, ip_id,
                edge_type=EdgeType.CONTACTED.value,
                weight=1,
                total_bytes=flow.bytes_total,
            )

    def _add_tls_session(
        self, session: TLSSessionRecord, flow: FlowRecord | None
    ) -> None:
        """Add domain and certificate nodes with edges from TLS session data."""
        if flow is None:
            return

        ip_id = f"ip:{flow.dst_ip}"

        # Domain node from SNI
        if session.sni_domain:
            domain_id = f"domain:{session.sni_domain}"
            if domain_id not in self._graph:
                self._graph.add_node(
                    domain_id,
                    node_type=NodeType.DOMAIN.value,
                    value=session.sni_domain,
                    risk_score=0.0,
                    is_malicious=False,
                )

            # domain → ip (RESOLVES_TO)
            if not self._graph.has_edge(domain_id, ip_id):
                self._graph.add_edge(
                    domain_id, ip_id,
                    edge_type=EdgeType.RESOLVES_TO.value,
                    weight=1,
                )

            # device → domain (CONTACTED, preferred over device → ip when SNI exists)
            device_id = f"device:{flow.src_ip}"
            if device_id in self._graph and not self._graph.has_edge(device_id, domain_id):
                self._graph.add_edge(
                    device_id, domain_id,
                    edge_type=EdgeType.CONTACTED.value,
                    weight=1,
                )

        # Certificate node
        if session.cert_fingerprint:
            cert_id = f"cert:{session.cert_fingerprint[:16]}"
            if cert_id not in self._graph:
                self._graph.add_node(
                    cert_id,
                    node_type=NodeType.CERTIFICATE.value,
                    value=session.cert_fingerprint,
                    risk_score=0.35 if session.cert_is_self_signed else 0.0,
                    is_malicious=False,
                    is_self_signed=session.cert_is_self_signed,
                    san_count=len(session.cert_san_list),
                )

            # domain → cert (USES_CERT) or ip → cert if no domain
            anchor = f"domain:{session.sni_domain}" if session.sni_domain else ip_id
            if anchor in self._graph and not self._graph.has_edge(anchor, cert_id):
                self._graph.add_edge(
                    anchor, cert_id,
                    edge_type=EdgeType.USES_CERT.value,
                    weight=1,
                )

            # SAN domains → cert (COVERED_BY)
            for san in session.cert_san_list:
                san_id = f"domain:{san}"
                if san_id not in self._graph:
                    self._graph.add_node(
                        san_id,
                        node_type=NodeType.DOMAIN.value,
                        value=san,
                        risk_score=0.0,
                        is_malicious=False,
                    )
                if not self._graph.has_edge(san_id, cert_id):
                    self._graph.add_edge(
                        san_id, cert_id,
                        edge_type=EdgeType.COVERED_BY.value,
                        weight=1,
                    )
