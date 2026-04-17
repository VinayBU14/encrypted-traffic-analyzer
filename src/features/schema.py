"""Canonical V1 feature schema definitions shared by training and inference stages."""

from typing import TypedDict

SCHEMA_VERSION: str = "v1.0.0"

FLOW_FEATURE_COLUMNS: list[str] = [
    "duration_ms",
    "total_packets",
    "total_bytes",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "packet_rate_per_sec",
    "byte_rate_per_sec",
    "avg_packet_size",
    "min_packet_size",
    "max_packet_size",
    "std_packet_size",
    "mean_iat_ms",
    "min_iat_ms",
    "max_iat_ms",
    "std_iat_ms",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
]

TLS_FEATURE_COLUMNS: list[str] = [
    "tls_seen",
    "tls_version_code",
    "tls_cipher_suite_count",
    "tls_extension_count",
    "tls_sni_present",
    "tls_cert_present",
    "tls_cert_validity_days",
    "tls_cert_self_signed",
    "tls_cert_san_count",
    "tls_cert_age_days",
]

ALL_FEATURE_COLUMNS: list[str] = FLOW_FEATURE_COLUMNS + TLS_FEATURE_COLUMNS

# FIXED: was referencing non-existent columns (regularity_score, payload_consistency, etc.)
# Now maps directly to columns that ARE produced by FlowFeatureExtractor + TLSFeatureExtractor.
# This is what the IsolationForest model trains and scores against.
SCORING_FEATURE_COLUMNS: list[str] = [
    # Flow features
    "duration_ms",
    "total_packets",
    "total_bytes",
    "fwd_bytes",
    "bwd_bytes",
    "packet_rate_per_sec",
    "byte_rate_per_sec",
    "avg_packet_size",
    "std_packet_size",
    "mean_iat_ms",
    "std_iat_ms",
    "syn_count",
    "rst_count",
    "psh_count",
    # TLS features
    "tls_seen",
    "tls_version_code",
    "tls_cipher_suite_count",
    "tls_extension_count",
    "tls_sni_present",
    "tls_cert_present",
    "tls_cert_validity_days",
    "tls_cert_self_signed",
    "tls_cert_san_count",
    "tls_cert_age_days",
]


class FeatureRow(TypedDict, total=False):
    """Full feature row contract including context fields and optional feature values."""

    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    schema_version: str
    duration_ms: float
    total_packets: float
    total_bytes: float
    fwd_packets: float
    bwd_packets: float
    fwd_bytes: float
    bwd_bytes: float
    packet_rate_per_sec: float
    byte_rate_per_sec: float
    avg_packet_size: float
    min_packet_size: float
    max_packet_size: float
    std_packet_size: float
    mean_iat_ms: float
    min_iat_ms: float
    max_iat_ms: float
    std_iat_ms: float
    syn_count: float
    ack_count: float
    fin_count: float
    rst_count: float
    psh_count: float
    tls_seen: float
    tls_version_code: float
    tls_cipher_suite_count: float
    tls_extension_count: float
    tls_sni_present: float
    tls_cert_present: float
    tls_cert_validity_days: float
    tls_cert_self_signed: float
    tls_cert_san_count: float
    tls_cert_age_days: float