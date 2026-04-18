from __future__ import annotations

import logging
from typing import Any
from pathlib import Path

import httpx
import yaml

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_CONFIG_PATH  = _PROJECT_ROOT / "configs" / "default.yaml"
_CONFIG       = yaml.safe_load(_CONFIG_PATH.read_text(encoding="utf-8")) or {}
_DASHBOARD_CFG = _CONFIG.get("dashboard", {})

BASE_URL: str  = _DASHBOARD_CFG.get("api_base_url", "http://localhost:8000").rstrip("/")
TIMEOUT: float = 10.0


def _get(path: str, params: dict[str, Any] | None = None) -> Any:
    url = f"{BASE_URL}{path}"
    try:
        with httpx.Client(timeout=TIMEOUT) as client:
            resp = client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()
    except httpx.ConnectError as exc:
        logger.error("Cannot connect to API at %s: %s", BASE_URL, exc)
        raise ConnectionError(
            f"Cannot reach Spectra API at {BASE_URL}.\n"
            "Start the server with:\n"
            "  uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload"
        ) from exc
    except httpx.HTTPStatusError as exc:
        logger.error("API %s %s — %s", exc.response.status_code, url, exc.response.text)
        raise
    except Exception as exc:
        logger.error("Unexpected error calling %s: %s", url, exc)
        raise


def _post(path: str) -> Any:
    url = f"{BASE_URL}{path}"
    try:
        with httpx.Client(timeout=TIMEOUT) as client:
            resp = client.post(url)
        resp.raise_for_status()
        return resp.json()
    except httpx.ConnectError as exc:
        raise ConnectionError(f"Cannot reach Spectra API at {BASE_URL}.") from exc
    except httpx.HTTPStatusError as exc:
        logger.error("API %s %s — %s", exc.response.status_code, url, exc.response.text)
        raise


def check_health() -> dict[str, Any]:
    return _get("/health")


def get_alerts(
    limit: int = 200,
    severity: str | None = None,
    source: str | None = None,   # "live" | "pcap" | None (= all)
) -> list[dict[str, Any]]:
    params: dict[str, Any] = {"limit": limit}
    if severity and severity != "ALL":
        params["severity"] = severity.upper()
    if source and source in ("live", "pcap"):
        params["source"] = source
    return _get("/alerts", params=params)


def get_alert(alert_id: str) -> dict[str, Any]:
    return _get(f"/alerts/{alert_id}")


def get_alert_stats(source: str | None = None) -> dict[str, int]:
    """source = 'live' | 'pcap' | None (all)"""
    params: dict[str, Any] = {}
    if source in ("live", "pcap"):
        params["source"] = source
    return _get("/alerts/stats", params=params)


def get_alerts_by_src_ip(src_ip: str) -> list[dict[str, Any]]:
    return _get(f"/alerts/src/{src_ip}")


def suppress_alert(alert_id: str) -> dict[str, Any]:
    return _post(f"/alerts/{alert_id}/suppress")


def get_flows(limit: int = 200, source: str | None = None) -> list[dict[str, Any]]:
    params: dict[str, Any] = {"limit": limit}
    if source in ("live", "pcap"):
        params["source"] = source
    return _get("/flows", params=params)


def get_flow(flow_id: str) -> dict[str, Any]:
    return _get(f"/flows/{flow_id}")


def get_flows_by_pair(src_ip: str, dst_ip: str) -> list[dict[str, Any]]:
    return _get(f"/flows/src/{src_ip}", params={"dst_ip": dst_ip})


def get_graph(limit: int = 1000) -> dict[str, Any]:
    return _get("/entities/graph", params={"limit": limit})


def get_high_risk_nodes(threshold: float = 0.30, limit: int = 1000) -> list[dict[str, Any]]:
    return _get("/entities/high-risk", params={"threshold": threshold, "limit": limit})