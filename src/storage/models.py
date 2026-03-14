
"""Dataclass models mirroring Spectra storage schema."""

from dataclasses import dataclass

SCHEMA_VERSION: str = "v1.0.0"


@dataclass
class FlowRecord:
    """Flow row model.

    JSON serialization/deserialization for list and dict fields is handled by
    the repository layer, not here.
    """

    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    packet_count: int
    bytes_total: int
    upload_bytes: int
    download_bytes: int
    packet_sizes: list[float]
    inter_arrival_ms: list[float]
    tcp_flags: dict[str, int]
    created_at: float
    end_time: float | None = None
    duration_ms: float | None = None
    status: str = "ACTIVE"


@dataclass
class TLSSessionRecord:
    """TLS session row model."""

    session_id: str
    flow_id: str
    cipher_suites: list[int]
    extensions: list[int]
    elliptic_curves: list[int]
    cert_san_list: list[str]
    cert_is_self_signed: bool
    created_at: float
    sni_domain: str | None = None
    ja3_hash: str | None = None
    tls_version: int | None = None
    cert_subject: str | None = None
    cert_issuer: str | None = None
    cert_not_before: float | None = None
    cert_not_after: float | None = None
    cert_fingerprint: str | None = None


@dataclass
class AlertRecord:
    """Alert row model."""

    alert_id: str
    timestamp: float
    severity: str
    composite_score: float
    src_ip: str
    findings: list[str]
    is_suppressed: bool
    created_at: float
    flow_id: str | None = None
    ja3_score: float | None = None
    beacon_score: float | None = None
    cert_score: float | None = None
    graph_score: float | None = None
    anomaly_score: float | None = None
    dst_domain: str | None = None
    dst_ip: str | None = None
    recommended_action: str | None = None


@dataclass
class GraphEntityRecord:
    """Graph entity row model."""

    entity_id: str
    entity_type: str
    value: str
    risk_score: float
    is_malicious: bool
    metadata: dict[str, object]
    created_at: float
    updated_at: float
