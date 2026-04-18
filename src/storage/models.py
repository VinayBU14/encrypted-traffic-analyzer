"""Dataclass models mirroring Spectra storage schema."""

from dataclasses import dataclass, field

SCHEMA_VERSION: str = "v1.1.0"


@dataclass
class FlowRecord:
    """Flow row model.

    JSON serialization/deserialization for list and dict fields is handled by
    the repository layer, not here.
    """

    flow_id:          str
    src_ip:           str
    dst_ip:           str
    src_port:         int
    dst_port:         int
    protocol:         str
    start_time:       float
    packet_count:     int
    bytes_total:      int
    upload_bytes:     int
    download_bytes:   int
    packet_sizes:     list
    inter_arrival_ms: list
    tcp_flags:        dict
    created_at:       float
    end_time:         float | None = None
    duration_ms:      float | None = None
    status:           str = "ACTIVE"
    # FIX: Added scoring + source fields — previously missing, caused dashboard to
    # show 0 for all score columns when loading flows from the live capture pipeline.
    composite_score:      float = 0.0
    anomaly_score:        float = 0.0
    ja3_score:            float = 0.0
    beacon_score:         float = 0.0
    cert_score:           float = 0.0
    graph_score:          float = 0.0
    verdict:              str = "BENIGN"
    severity:             str = "CLEAN"
    source:               str = "pcap"
    is_live:              int = 0
    packet_rate_per_sec:  float = 0.0
    byte_rate_per_sec:    float = 0.0
    avg_packet_size:      float = 0.0
    syn_count:            int = 0
    rst_count:            int = 0
    fin_count:            int = 0
    ack_count:            int = 0
    psh_count:            int = 0


@dataclass
class TLSSessionRecord:
    """TLS session row model."""

    session_id:          str
    flow_id:             str
    cipher_suites:       list
    extensions:          list
    elliptic_curves:     list
    cert_san_list:       list
    cert_is_self_signed: bool
    created_at:          float
    sni_domain:          str | None = None
    ja3_hash:            str | None = None
    tls_version:         int | None = None
    cert_subject:        str | None = None
    cert_issuer:         str | None = None
    cert_not_before:     float | None = None
    cert_not_after:      float | None = None
    cert_fingerprint:    str | None = None


@dataclass
class AlertRecord:
    """Alert row model.

    FIX: Added src_port, dst_port, is_live, is_beacon, groq_* fields.
    Previously these were missing, so the alert detail page showed 0 for
    all risk factor bars (ja3/beacon/cert/graph) and live badge never showed.
    """

    alert_id:          str
    timestamp:         float
    severity:          str
    composite_score:   float
    src_ip:            str
    findings:          list
    is_suppressed:     bool
    created_at:        float
    flow_id:           str | None = None
    ja3_score:         float | None = None
    beacon_score:      float | None = None
    cert_score:        float | None = None
    graph_score:       float | None = None
    anomaly_score:     float | None = None
    dst_domain:        str | None = None
    dst_ip:            str | None = None
    recommended_action:str | None = None
    src_port:          int = 0
    dst_port:          int = 0
    is_live:           int = 0
    is_beacon:         int = 0
    groq_summary:      str = ""
    groq_explanation:  str = ""
    groq_action:       str = ""
    groq_threat_type:  str = ""
    groq_confidence:   str = ""


@dataclass
class GraphEntityRecord:
    """Graph entity row model."""

    entity_id:   str
    entity_type: str
    value:       str
    risk_score:  float
    is_malicious:bool
    metadata:    dict
    created_at:  float
    updated_at:  float