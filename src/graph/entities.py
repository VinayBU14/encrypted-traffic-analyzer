"""Graph entity and edge type definitions for the Spectra infrastructure graph."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class NodeType(str, Enum):
    """Types of nodes in the infrastructure graph."""
    DEVICE = "device"        # Source IP (internal device)
    IP = "ip"                # Destination IP
    DOMAIN = "domain"        # SNI domain name
    CERTIFICATE = "certificate"  # TLS certificate fingerprint
    ASN = "asn"              # Autonomous System Number (future use)


class EdgeType(str, Enum):
    """Types of directed edges in the infrastructure graph."""
    CONTACTED = "contacted"       # device → ip (made a connection)
    RESOLVES_TO = "resolves_to"   # domain → ip (DNS resolution implied by SNI+dst)
    USES_CERT = "uses_cert"       # domain → certificate
    COVERED_BY = "covered_by"     # domain → certificate (SAN coverage)


@dataclass
class GraphNode:
    """A node in the infrastructure graph."""
    node_id: str
    node_type: NodeType
    value: str
    risk_score: float = 0.0
    is_malicious: bool = False
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "value": self.value,
            "risk_score": self.risk_score,
            "is_malicious": self.is_malicious,
            "metadata": self.metadata,
        }


@dataclass
class GraphEdge:
    """A directed edge in the infrastructure graph."""
    src_id: str
    dst_id: str
    edge_type: EdgeType
    weight: float = 1.0
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "src_id": self.src_id,
            "dst_id": self.dst_id,
            "edge_type": self.edge_type.value,
            "weight": self.weight,
            "metadata": self.metadata,
        }
