"""Day 13 — FastAPI backend verification script for Spectra."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient
from src.api.main import app

client = TestClient(app)


def _pass(msg: str) -> None:
    print(f"PASS: {msg}")


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}")


def main() -> int:
    failed = False

    # Check 1 — Root endpoint
    try:
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "service" in data
        assert "endpoints" in data
        _pass(f"Check 1 - Root endpoint: {data['service']}")
    except Exception as exc:
        failed = True
        _fail(f"Check 1 - Root endpoint failed ({exc})")

    # Check 2 — Health check
    try:
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["database"] == "ok"
        _pass(f"Check 2 - Health check: status={data['status']} db={data['database']}")
    except Exception as exc:
        failed = True
        _fail(f"Check 2 - Health check failed ({exc})")

    # Check 3 — List flows
    try:
        response = client.get("/flows?limit=10")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        _pass(f"Check 3 - GET /flows returned {len(data)} flows")
        if data:
            flow = data[0]
            for key in ("flow_id", "src_ip", "dst_ip", "protocol", "packet_count"):
                assert key in flow, f"Missing key: {key}"
            _pass(f"Check 3b - Flow schema valid: {flow['src_ip']} → {flow['dst_ip']}")
    except Exception as exc:
        failed = True
        _fail(f"Check 3 - GET /flows failed ({exc})")

    # Check 4 — Get single flow
    try:
        flows_response = client.get("/flows?limit=1")
        flows = flows_response.json()
        if flows:
            flow_id = flows[0]["flow_id"]
            response = client.get(f"/flows/{flow_id}")
            assert response.status_code == 200
            assert response.json()["flow_id"] == flow_id
            _pass(f"Check 4 - GET /flows/{{id}} returned correct flow: {flow_id[:8]}...")
        else:
            _pass("Check 4 - Skipped (no flows in DB yet — run verify_day12 first)")
    except Exception as exc:
        failed = True
        _fail(f"Check 4 - GET /flows/{{id}} failed ({exc})")

    # Check 5 — 404 for unknown flow
    try:
        response = client.get("/flows/nonexistent-flow-id")
        assert response.status_code == 404
        _pass("Check 5 - GET /flows/unknown returns 404 correctly")
    except Exception as exc:
        failed = True
        _fail(f"Check 5 - 404 handling failed ({exc})")

    # Check 6 — List alerts
    try:
        response = client.get("/alerts?limit=10")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        _pass(f"Check 6 - GET /alerts returned {len(data)} alerts")
        if data:
            alert = data[0]
            for key in ("alert_id", "severity", "composite_score", "src_ip", "findings"):
                assert key in alert, f"Missing key: {key}"
            _pass(f"Check 6b - Alert schema valid: severity={alert['severity']} score={alert['composite_score']}")
    except Exception as exc:
        failed = True
        _fail(f"Check 6 - GET /alerts failed ({exc})")

    # Check 7 — Filter alerts by severity
    try:
        for severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            response = client.get(f"/alerts?severity={severity}")
            assert response.status_code == 200
            data = response.json()
            for alert in data:
                assert alert["severity"] == severity
        _pass("Check 7 - GET /alerts?severity=X filters correctly")
    except Exception as exc:
        failed = True
        _fail(f"Check 7 - Severity filter failed ({exc})")

    # Check 8 — Alert stats endpoint
    try:
        response = client.get("/alerts/stats")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict)
        _pass(f"Check 8 - GET /alerts/stats: {data}")
    except Exception as exc:
        failed = True
        _fail(f"Check 8 - Alert stats failed ({exc})")

    # Check 9 — Graph entities endpoint
    try:
        response = client.get("/entities/graph")
        assert response.status_code == 200
        data = response.json()
        assert "nodes" in data
        assert "edges" in data
        assert "node_count" in data
        _pass(f"Check 9 - GET /entities/graph: {data['node_count']} nodes, {data['edge_count']} edges")
    except Exception as exc:
        failed = True
        _fail(f"Check 9 - Graph entities failed ({exc})")

    # Check 10 — High risk nodes endpoint
    try:
        response = client.get("/entities/high-risk?threshold=0.30")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        _pass(f"Check 10 - GET /entities/high-risk: {len(data)} high-risk nodes")
        for node in data[:3]:
            print(f"  HIGH RISK: type={node['node_type']} value={node['value']} score={node['risk_score']}")
    except Exception as exc:
        failed = True
        _fail(f"Check 10 - High-risk nodes failed ({exc})")

    # Check 11 — Suppress alert endpoint
    try:
        alerts_response = client.get("/alerts?limit=1")
        alerts = alerts_response.json()
        if alerts:
            alert_id = alerts[0]["alert_id"]
            response = client.post(f"/alerts/{alert_id}/suppress")
            assert response.status_code == 200
            assert response.json()["status"] == "suppressed"
            _pass(f"Check 11 - POST /alerts/{{id}}/suppress works: {alert_id[:8]}...")
        else:
            _pass("Check 11 - Skipped (no alerts in DB — run verify_day12 first)")
    except Exception as exc:
        failed = True
        _fail(f"Check 11 - Suppress alert failed ({exc})")

    # Check 12 — OpenAPI docs accessible
    try:
        response = client.get("/docs")
        assert response.status_code == 200
        _pass("Check 12 - Swagger UI docs accessible at /docs")
    except Exception as exc:
        failed = True
        _fail(f"Check 12 - Docs endpoint failed ({exc})")

    if failed:
        print("✗ Day 13 verification FAILED — see errors above")
        return 1

    print("✓ Day 13 verification passed — FastAPI backend is ready")
    print("\nStart the API server with:")
    print("  uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload")
    print("\nThen open:")
    print("  http://localhost:8000/docs  ← Swagger UI")
    print("  http://localhost:8000/health")
    print("  http://localhost:8000/alerts")
    print("  http://localhost:8000/flows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())