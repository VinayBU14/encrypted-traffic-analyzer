"""Day 10 — Graph analysis verification script for Spectra."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.graph.builder import GraphBuilder
from src.graph.entities import NodeType, EdgeType
from src.graph.queries import run_all_queries, query_malicious_ip, query_multi_device
from src.graph.serializer import GraphSerializer
from src.storage.database import get_db
from src.storage.models import FlowRecord, TLSSessionRecord
from src.storage.repositories.flow_repository import get_recent_flows
from src.storage.repositories.session_repository import get_recent_sessions
import time


def _pass(msg: str) -> None:
    print(f"PASS: {msg}")


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}")


def _make_flow(flow_id: str, src: str, dst: str, port: int = 443, bytes_total: int = 1000) -> FlowRecord:
    ts = time.time()
    return FlowRecord(
        flow_id=flow_id, src_ip=src, dst_ip=dst,
        src_port=50000, dst_port=port, protocol="TCP",
        start_time=ts, packet_count=5, bytes_total=bytes_total,
        upload_bytes=500, download_bytes=500,
        packet_sizes=[200.0] * 5, inter_arrival_ms=[10.0] * 4,
        tcp_flags={"SYN": 1, "ACK": 3, "FIN": 1},
        created_at=ts, end_time=ts + 1.0, duration_ms=1000.0,
    )


def _make_session(session_id: str, flow_id: str, sni: str | None = None,
                  fingerprint: str | None = None, san_list: list | None = None,
                  self_signed: bool = False) -> TLSSessionRecord:
    return TLSSessionRecord(
        session_id=session_id, flow_id=flow_id,
        cipher_suites=[49195], extensions=[0, 23], elliptic_curves=[29],
        cert_san_list=san_list or [], cert_is_self_signed=self_signed,
        created_at=time.time(), sni_domain=sni,
        cert_fingerprint=fingerprint,
    )


def main() -> int:
    failed = False
    builder = GraphBuilder()
    serializer = GraphSerializer()

    # Check 1 — Empty graph builds without error
    try:
        graph = builder.build([], [])
        assert graph.number_of_nodes() == 0
        _pass("Check 1 - Empty graph builds cleanly")
    except Exception as exc:
        failed = True
        _fail(f"Check 1 - Empty graph failed ({exc})")

    # Check 2 — Basic flow adds device and IP nodes
    try:
        flows = [_make_flow("f1", "192.168.1.10", "8.8.8.8")]
        graph = builder.build(flows, [])
        assert graph.number_of_nodes() >= 2
        assert "device:192.168.1.10" in graph
        assert "ip:8.8.8.8" in graph
        assert graph.has_edge("device:192.168.1.10", "ip:8.8.8.8")
        _pass(f"Check 2 - Flow creates device+IP nodes and CONTACTED edge ({graph.number_of_nodes()} nodes)")
    except Exception as exc:
        failed = True
        _fail(f"Check 2 - Basic flow graph failed ({exc})")

    # Check 3 — TLS session adds domain and cert nodes
    try:
        flows = [_make_flow("f2", "10.0.0.1", "1.2.3.4")]
        sessions = [_make_session("s2", "f2", sni="evil.com", fingerprint="abc123fingerprint456", san_list=["evil.com", "also-evil.com"])]
        graph = builder.build(flows, sessions)
        assert "domain:evil.com" in graph
        _pass(f"Check 3 - TLS session adds domain/cert nodes ({graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges)")
    except Exception as exc:
        failed = True
        _fail(f"Check 3 - TLS session graph failed ({exc})")

    # Check 4 — Malicious IP query detects known-bad IP
    try:
        known_bad_ip = "185.220.101.1"
        flows = [_make_flow("f3", "10.0.0.1", known_bad_ip)]
        graph = builder.build(flows, [])
        result = query_malicious_ip(graph, known_bad_ip)
        assert float(result["graph_score"]) > 0.0, "Known malicious IP should score > 0"
        assert result["finding"] is not None
        _pass(f"Check 4 - Malicious IP detected: score={result['graph_score']} finding='{result['finding']}'")
    except Exception as exc:
        failed = True
        _fail(f"Check 4 - Malicious IP query failed ({exc})")

    # Check 5 — Multi-device query detects multiple devices → same destination
    try:
        flows = [
            _make_flow("f4a", "10.0.0.1", "9.9.9.9"),
            _make_flow("f4b", "10.0.0.2", "9.9.9.9"),
            _make_flow("f4c", "10.0.0.3", "9.9.9.9"),
        ]
        graph = builder.build(flows, [])
        result = query_multi_device(graph, "9.9.9.9")
        assert float(result["graph_score"]) > 0.0
        assert result["finding"] is not None
        _pass(f"Check 5 - Multi-device convergence detected: score={result['graph_score']} finding='{result['finding']}'")
    except Exception as exc:
        failed = True
        _fail(f"Check 5 - Multi-device query failed ({exc})")

    # Check 6 — run_all_queries returns all expected keys
    try:
        flows = [_make_flow("f5", "10.0.0.1", "5.5.5.5")]
        graph = builder.build(flows, [])
        result = run_all_queries(graph, "5.5.5.5")
        for key in ("graph_score", "findings", "cert_fanout_score", "malicious_ip_score", "multi_device_score", "proximity_score"):
            assert key in result, f"Missing key: {key}"
        assert 0.0 <= float(result["graph_score"]) <= 1.0
        _pass(f"Check 6 - run_all_queries returns complete result: score={result['graph_score']}")
    except Exception as exc:
        failed = True
        _fail(f"Check 6 - run_all_queries failed ({exc})")

    # Check 7 — Serialize graph to dict
    try:
        flows = [_make_flow("f6", "172.16.0.1", "203.0.113.5")]
        graph = builder.build(flows, [])
        data = serializer.to_dict(graph)
        assert "nodes" in data and "edges" in data
        assert data["node_count"] == graph.number_of_nodes()
        _pass(f"Check 7 - Graph serialized: {data['node_count']} nodes, {data['edge_count']} edges")
    except Exception as exc:
        failed = True
        _fail(f"Check 7 - Serialization failed ({exc})")

    # Check 8 — Build graph from real database flows and sessions
    try:
        conn = get_db().get_connection()
        flows = get_recent_flows(conn, limit=500)
        sessions = get_recent_sessions(conn, limit=500)
        graph = builder.build(flows, sessions)
        risky = serializer.get_high_risk_nodes(graph, threshold=0.30)
        _pass(
            f"Check 8 - Real graph built: {graph.number_of_nodes()} nodes, "
            f"{graph.number_of_edges()} edges, {len(risky)} high-risk nodes"
        )
        for node in risky[:5]:
            print(f"  HIGH RISK: {node['node_type']}={node['value']} score={node['risk_score']} malicious={node['is_malicious']}")
    except Exception as exc:
        failed = True
        _fail(f"Check 8 - Real graph build failed ({exc})")

    if failed:
        print("✗ Day 10 verification FAILED — see errors above")
        return 1

    print("✓ Day 10 verification passed — Graph analysis is ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())