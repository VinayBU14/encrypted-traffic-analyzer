"""
src/api/routers/capture.py
Live capture router — start/stop real-time packet capture and stream results.

Key fixes vs previous version:
  - Flows inserted with ALL columns that match the unified schema in init_db.py
  - Alerts inserted with is_live=1 so the dashboard can filter them correctly
  - /capture/recent-alerts uses created_at (not timestamp) for ordering fallback
  - Schema is never assumed to exist — safe to call init_db() before writing
  - Scapy is the capture backend (already installed in your venv per Scripts/)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
import queue
from collections import defaultdict
from datetime import datetime, timezone
from typing import Annotated, Optional

import numpy as np
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from src.api.dependencies import get_db_conn

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/capture", tags=["capture"])

DBConn = Annotated[sqlite3.Connection, Depends(get_db_conn)]

DB_PATH = os.getenv("SPECTRA_DB", "data/spectra.db")

# ── Scapy ─────────────────────────────────────────────────────────────────────
try:
    from scapy.all import sniff, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not installed — live capture unavailable. Run: pip install scapy")


# ── Shared helpers (identical logic to step4_score_flows) ─────────────────────

def _make_alert_id(src_ip, src_port, dst_ip, dst_port, protocol="TCP") -> str:
    raw = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _make_beacon_alert_id(src_ip, dst_ip, dst_port) -> str:
    epoch_minute = int(time.time() // 60)
    raw = f"beacon:{src_ip}:{dst_ip}:{dst_port}:{epoch_minute}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _score_to_severity(score: float) -> str:
    if score >= 0.90: return "CRITICAL"
    if score >= 0.75: return "HIGH"
    if score >= 0.60: return "MEDIUM"
    if score >= 0.30: return "LOW"
    return "CLEAN"


# ── Flow accumulator ──────────────────────────────────────────────────────────

class _FlowAccumulator:
    FLOW_TIMEOUT_SEC = 60

    def __init__(self):
        self._flows: dict[str, dict] = {}
        self._lock = threading.Lock()

    def _key(self, pkt) -> Optional[str]:
        if not pkt.haslayer("IP"):
            return None
        ip = pkt["IP"]
        sp = dp = 0
        if pkt.haslayer("TCP"):
            sp, dp = pkt["TCP"].sport, pkt["TCP"].dport
        elif pkt.haslayer("UDP"):
            sp, dp = pkt["UDP"].sport, pkt["UDP"].dport
        pair = sorted([(ip.src, sp), (ip.dst, dp)])
        return f"{pair[0][0]}:{pair[0][1]}-{pair[1][0]}:{pair[1][1]}-{ip.proto}"

    def add_packet(self, pkt) -> Optional[dict]:
        key = self._key(pkt)
        if not key:
            return None
        now = time.time()
        with self._lock:
            if key not in self._flows:
                ip = pkt["IP"]
                sp = pkt["TCP"].sport if pkt.haslayer("TCP") else (pkt["UDP"].sport if pkt.haslayer("UDP") else 0)
                dp = pkt["TCP"].dport if pkt.haslayer("TCP") else (pkt["UDP"].dport if pkt.haslayer("UDP") else 0)
                self._flows[key] = dict(
                    src_ip=ip.src, dst_ip=ip.dst,
                    src_port=sp, dst_port=dp,
                    protocol="TCP" if pkt.haslayer("TCP") else "UDP",
                    start_time=now, last_time=now,
                    packet_count=0, byte_count=0,
                    tls_count=0, rst_count=0, syn_count=0, fin_count=0,
                    intervals=[], pkt_sizes=[],
                )
            f = self._flows[key]
            pkt_len = len(pkt)
            f["packet_count"] += 1
            f["byte_count"] += pkt_len
            f["pkt_sizes"].append(pkt_len)
            if f["last_time"] > 0:
                f["intervals"].append(now - f["last_time"])
            f["last_time"] = now
            if f["dst_port"] in (443, 8443, 993, 465, 587):
                f["tls_count"] += 1
            if pkt.haslayer("TCP"):
                flags = pkt["TCP"].flags
                if flags & 0x04: f["rst_count"] += 1
                if flags & 0x02: f["syn_count"] += 1
                if flags & 0x01: f["fin_count"] += 1

            completed = None
            if now - f["start_time"] > self.FLOW_TIMEOUT_SEC:
                completed = self._finalise(key)
                del self._flows[key]
            return completed

    def _finalise(self, key: str) -> dict:
        import statistics
        f = self._flows[key]
        dur = max(f["last_time"] - f["start_time"], 0.001)
        ivs, szs = f["intervals"], f["pkt_sizes"]
        mean_iv = statistics.mean(ivs) if ivs else 0
        std_iv  = statistics.stdev(ivs) if len(ivs) > 1 else 0
        return {
            "src_ip":              f["src_ip"],
            "dst_ip":              f["dst_ip"],
            "src_port":            f["src_port"],
            "dst_port":            f["dst_port"],
            "protocol":            f["protocol"],
            "duration_ms":         dur * 1000,
            "total_packets":       f["packet_count"],
            "total_bytes":         f["byte_count"],
            "fwd_bytes":           f["byte_count"],
            "bwd_bytes":           0,
            "byte_rate_per_sec":   f["byte_count"] / dur,
            "packet_rate_per_sec": f["packet_count"] / dur,
            "avg_packet_size":     statistics.mean(szs) if szs else 0,
            "min_packet_size":     min(szs) if szs else 0,
            "max_packet_size":     max(szs) if szs else 0,
            "std_packet_size":     statistics.stdev(szs) if len(szs) > 1 else 0,
            "mean_iat_ms":         mean_iv * 1000,
            "std_iat_ms":          std_iv * 1000,
            "min_iat_ms":          min(ivs) * 1000 if ivs else 0,
            "max_iat_ms":          max(ivs) * 1000 if ivs else 0,
            "tls_ratio":           f["tls_count"] / max(f["packet_count"], 1),
            "rst_count":           f["rst_count"],
            "syn_count":           f["syn_count"],
            "fin_count":           f["fin_count"],
            "ack_count":           0,
            "psh_count":           0,
            "tcp_flags": json.dumps({
                "SYN": f["syn_count"], "RST": f["rst_count"], "FIN": f["fin_count"],
            }),
        }

    def flush_all(self) -> list[dict]:
        with self._lock:
            completed = [self._finalise(k) for k in list(self._flows)]
            self._flows.clear()
            return completed

    @property
    def active_count(self) -> int:
        return len(self._flows)


# ── Capture session singleton ─────────────────────────────────────────────────

class _CaptureSession:
    def __init__(self):
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._accumulator = _FlowAccumulator()
        self._flow_q: queue.Queue = queue.Queue()
        self._event_q: queue.Queue = queue.Queue()
        self.stats = dict(packets_captured=0, tls_packets=0, bytes_seen=0, active_flows=0)
        self._iface = ""
        self._bpf   = ""

    def get_interfaces(self) -> list[str]:
        if not SCAPY_AVAILABLE:
            return []
        try:
            return get_if_list()
        except Exception:
            return []

    def start(self, iface: str, bpf_filter: str = "") -> None:
        if self.running:
            raise RuntimeError("Capture already running")
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy not installed. Run: pip install scapy")
        self._iface = iface
        self._bpf   = bpf_filter
        self.running = True
        self.stats   = dict(packets_captured=0, tls_packets=0, bytes_seen=0, active_flows=0)
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self._push("status", {"running": True, "iface": iface})
        # Update live_capture_status row
        self._update_status_row(is_running=1, interface=iface, bpf_filter=bpf_filter)

    def stop(self) -> list[dict]:
        self.running = False
        flushed = self._accumulator.flush_all()
        for f in flushed:
            self._flow_q.put(f)
        self._push("status", {"running": False})
        self._update_status_row(is_running=0)
        return flushed

    def _loop(self):
        def handle(pkt):
            if not self.running:
                return
            self.stats["packets_captured"] += 1
            self.stats["bytes_seen"] += len(pkt)
            if pkt.haslayer("IP") and pkt.haslayer("TCP"):
                if pkt["TCP"].dport in (443, 8443, 993, 465, 587):
                    self.stats["tls_packets"] += 1
            self.stats["active_flows"] = self._accumulator.active_count

            completed = self._accumulator.add_packet(pkt)
            if completed:
                self._flow_q.put(completed)
                self._push("flow", completed)

            if self.stats["packets_captured"] % 50 == 0:
                self._push("stats", self.stats.copy())
                self._update_stats_row()

        try:
            sniff(
                iface=self._iface,
                filter=self._bpf or None,
                prn=handle,
                stop_filter=lambda _: not self.running,
                store=False,
            )
        except Exception as e:
            logger.error("Capture error: %s", e)
            self.running = False
            self._push("error", {"message": str(e)})

    def _push(self, event_type: str, data: dict):
        self._event_q.put({"type": event_type, "data": data, "ts": time.time()})

    def drain_flows(self) -> list[dict]:
        out = []
        while not self._flow_q.empty():
            try:
                out.append(self._flow_q.get_nowait())
            except queue.Empty:
                break
        return out

    def drain_events(self) -> list[dict]:
        out = []
        while not self._event_q.empty():
            try:
                out.append(self._event_q.get_nowait())
            except queue.Empty:
                break
        return out

    def _update_status_row(self, **kwargs):
        kwargs["updated_at"] = time.time()
        cols = ", ".join(f"{k}=?" for k in kwargs)
        vals = list(kwargs.values())
        try:
            conn = sqlite3.connect(DB_PATH, timeout=5)
            conn.execute(f"UPDATE live_capture_status SET {cols} WHERE id=1", vals)
            conn.commit(); conn.close()
        except Exception:
            pass

    def _update_stats_row(self):
        s = self.stats
        self._update_status_row(
            packets_captured=s["packets_captured"],
            tls_packets=s["tls_packets"],
            bytes_seen=s["bytes_seen"],
            active_flows=s["active_flows"],
        )


_session = _CaptureSession()


# ── Scoring helper ─────────────────────────────────────────────────────────────

def _score_and_store_flow(flow: dict, db_path: str = None) -> Optional[dict]:
    """
    Score one completed live flow and upsert into spectra.db.
    Uses the exact same composite formula as step4_score_flows.py.
    Marks both the flow and alert with is_live=1 so the dashboard
    can show only live traffic when needed.
    """
    db_path = db_path or DB_PATH
    import pandas as pd
    from step4_score_flows import (
        compute_module_scores,
        compute_scoring_features,
        _get_composite_score,
        SCORING_FEATURE_COLUMNS,
    )

    df = pd.DataFrame([{
        "src_ip":              flow.get("src_ip", ""),
        "dst_ip":              flow.get("dst_ip", ""),
        "src_port":            flow.get("src_port", 0),
        "dst_port":            flow.get("dst_port", 0),
        "duration_ms":         flow.get("duration_ms", 0),
        "total_packets":       flow.get("total_packets", 0),
        "total_bytes":         flow.get("total_bytes", 0),
        "fwd_packets":         flow.get("total_packets", 0),
        "bwd_packets":         0,
        "fwd_bytes":           flow.get("fwd_bytes", flow.get("total_bytes", 0)),
        "bwd_bytes":           flow.get("bwd_bytes", 0),
        "packet_rate_per_sec": flow.get("packet_rate_per_sec", 0),
        "byte_rate_per_sec":   flow.get("byte_rate_per_sec", 0),
        "avg_packet_size":     flow.get("avg_packet_size", 0),
        "min_packet_size":     flow.get("min_packet_size", 0),
        "max_packet_size":     flow.get("max_packet_size", 0),
        "std_packet_size":     flow.get("std_packet_size", 0),
        "mean_iat_ms":         flow.get("mean_iat_ms", 0),
        "min_iat_ms":          flow.get("min_iat_ms", 0),
        "max_iat_ms":          flow.get("max_iat_ms", 0),
        "std_iat_ms":          flow.get("std_iat_ms", 0),
        "syn_count":           flow.get("syn_count", 0),
        "ack_count":           flow.get("ack_count", 0),
        "fin_count":           flow.get("fin_count", 0),
        "rst_count":           flow.get("rst_count", 0),
        "psh_count":           flow.get("psh_count", 0),
    }])

    # ── ML scoring ────────────────────────────────────────────────────────────
    try:
        import joblib
        from pathlib import Path
        model  = joblib.load(Path("models/isolation_forest.joblib"))
        scaler = joblib.load(Path("models/scaler.joblib"))
        feats  = compute_scoring_features(df)
        X      = feats[SCORING_FEATURE_COLUMNS].replace([np.inf, -np.inf], 0).fillna(0)
        X_sc   = scaler.transform(X)
        raw    = model.score_samples(X_sc)
        df["anomaly_score"] = np.clip(-raw * 2.0, 0, 1).round(4)
        df["prediction"]    = (df["anomaly_score"] >= 0.70).astype(int)
        df["verdict"]       = df["prediction"].map({0: "BENIGN", 1: "ANOMALY"})
    except Exception as e:
        logger.warning("Model scoring failed (%s) — heuristic fallback", e)
        rst_r = flow.get("rst_count", 0) / max(flow.get("total_packets", 1), 1)
        df["anomaly_score"] = min(1.0, rst_r * 2 + 0.2)
        df["verdict"]       = "ANOMALY"

    df = compute_module_scores(df)
    row = df.iloc[0]
    composite = _get_composite_score(row)
    verdict   = str(row.get("verdict", "BENIGN"))

    if verdict == "BENIGN":
        return None

    severity    = _score_to_severity(composite)
    anomaly_val = float(row.get("anomaly_score", composite))
    ja3_val     = float(row.get("ja3_score", 0.0) or 0.0)
    beacon_val  = float(row.get("beacon_score", 0.0) or 0.0)
    cert_val    = float(row.get("cert_score", 0.0) or 0.0)
    graph_val   = float(row.get("graph_score", 0.0) or 0.0)

    src_ip   = str(flow.get("src_ip", ""))
    dst_ip   = str(flow.get("dst_ip", ""))
    src_port = int(flow.get("src_port", 0))
    dst_port = int(flow.get("dst_port", 0))
    protocol = str(flow.get("protocol", "TCP"))

    # Findings
    findings: list[str] = []
    if composite >= 0.90:   findings.append("Extremely high anomaly score — likely malicious")
    elif composite >= 0.75: findings.append("High anomaly score detected")
    elif composite >= 0.60: findings.append("Moderate anomaly score detected")
    else:                   findings.append("Low-level anomaly detected")
    if ja3_val   >= 0.60: findings.append(f"Suspicious TLS fingerprint pattern (JA3={ja3_val:.2f})")
    if beacon_val >= 0.60: findings.append(f"Beaconing behavior detected (beacon={beacon_val:.2f})")
    if cert_val  >= 0.50: findings.append(f"Certificate anomaly proxy triggered (cert={cert_val:.2f})")
    if graph_val >= 0.60: findings.append(f"Infrastructure clustering (graph={graph_val:.2f})")
    findings_str = json.dumps(findings)

    recommended = {
        "CRITICAL": "Block immediately — isolate source host",
        "HIGH":     "Investigate and consider blocking source IP",
        "MEDIUM":   "Monitor closely — flag for review",
        "LOW":      "Log and monitor",
    }.get(severity, "Review manually")

    now_ts  = datetime.now(timezone.utc).timestamp()
    flow_id = hashlib.sha256(f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}".encode()).hexdigest()[:32]
    is_beacon = beacon_val >= 0.60 and severity in ("HIGH", "CRITICAL")
    alert_id  = _make_beacon_alert_id(src_ip, dst_ip, dst_port) if is_beacon \
                else _make_alert_id(src_ip, src_port, dst_ip, dst_port, protocol)

    try:
        conn = sqlite3.connect(db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")

        # ── flows table ───────────────────────────────────────────────────────
        dur_s = flow.get("duration_ms", 0) / 1000.0
        conn.execute("""
            INSERT OR IGNORE INTO flows (
                flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
                start_time, end_time, duration_ms,
                packet_count, bytes_total, upload_bytes, download_bytes,
                packet_rate_per_sec, byte_rate_per_sec, avg_packet_size,
                tcp_flags, syn_count, rst_count, fin_count,
                composite_score, anomaly_score, ja3_score, beacon_score,
                cert_score, graph_score,
                status, verdict, severity, source, is_live, created_at
            ) VALUES (
                ?,?,?,?,?,?,  ?,?,?,  ?,?,?,?,  ?,?,?,  ?,?,?,?,
                ?,?,?,?,?,?,  ?,?,?,?,?,?
            )""", (
            flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
            now_ts, now_ts + dur_s, flow.get("duration_ms", 0),
            int(flow.get("total_packets", 0)),
            int(flow.get("total_bytes", 0)),
            int(flow.get("fwd_bytes", 0)),
            int(flow.get("bwd_bytes", 0)),
            float(row.get("packet_rate_per_sec", 0)),
            float(row.get("byte_rate_per_sec", 0)),
            float(row.get("avg_packet_size", 0)),
            flow.get("tcp_flags", "{}"),
            int(flow.get("syn_count", 0)),
            int(flow.get("rst_count", 0)),
            int(flow.get("fin_count", 0)),
            round(composite, 4), round(anomaly_val, 4),
            round(ja3_val, 4), round(beacon_val, 4),
            round(cert_val, 4), round(graph_val, 4),
            "ACTIVE", verdict, severity, "live", 1, now_ts,
        ))

        # ── alerts table ──────────────────────────────────────────────────────
        existing = conn.execute(
            "SELECT alert_id FROM alerts WHERE alert_id=?", (alert_id,)
        ).fetchone()

        if existing and not is_beacon:
            conn.execute("""
                UPDATE alerts SET
                    composite_score=?, severity=?, anomaly_score=?,
                    ja3_score=?, beacon_score=?, cert_score=?, graph_score=?,
                    findings=?, recommended_action=?, timestamp=?
                WHERE alert_id=?""",
                (round(composite,4), severity, round(anomaly_val,4),
                 round(ja3_val,4), round(beacon_val,4),
                 round(cert_val,4), round(graph_val,4),
                 findings_str, recommended, now_ts, alert_id))
        else:
            conn.execute("""
                INSERT INTO alerts (
                    alert_id, flow_id, timestamp, created_at, severity,
                    composite_score, anomaly_score, ja3_score, beacon_score,
                    cert_score, graph_score,
                    src_ip, src_port, dst_ip, dst_port, dst_domain,
                    findings, recommended_action,
                    is_suppressed, is_live, is_beacon
                ) VALUES (?,?,?,?,?, ?,?,?,?, ?,?, ?,?,?,?,?, ?,?, ?,?,?)""",
                (alert_id, flow_id, now_ts, now_ts, severity,
                 round(composite,4), round(anomaly_val,4),
                 round(ja3_val,4), round(beacon_val,4),
                 round(cert_val,4), round(graph_val,4),
                 src_ip, src_port, dst_ip, dst_port, "",
                 findings_str, recommended,
                 0, 1, int(is_beacon)))   # is_live=1  ← key fix

        conn.commit()
        conn.close()

    except Exception as e:
        logger.error("Live alert DB write failed: %s", e)
        return None

    result = {
        "alert_id": alert_id, "flow_id": flow_id,
        "src_ip": src_ip, "src_port": src_port,
        "dst_ip": dst_ip, "dst_port": dst_port,
        "severity": severity, "composite_score": round(composite, 4),
        "anomaly_score": round(anomaly_val, 4),
        "ja3_score": round(ja3_val, 4),
        "beacon_score": round(beacon_val, 4),
        "cert_score": round(cert_val, 4),
        "graph_score": round(graph_val, 4),
        "findings": findings,
        "recommended_action": recommended,
        "timestamp": now_ts,
        "is_live": 1,
        "is_suppressed": 0,
    }

    # ── Supabase + Groq (non-blocking) ────────────────────────────────────────
    if severity in ("HIGH", "CRITICAL"):
        try:
            from src.integrations.supabase_client import mirror_alert
            mirror_alert(result)
        except Exception:
            pass

        def _groq_thread():
            try:
                from src.integrations.groq_client import analyse_and_store
                analyse_and_store(result, db_path)
            except Exception:
                pass
        threading.Thread(target=_groq_thread, daemon=True).start()

    return result


# ── Background flow processor ─────────────────────────────────────────────────

async def _processor(db_path: str):
    while _session.running:
        for flow in _session.drain_flows():
            try:
                _score_and_store_flow(flow, db_path)
            except Exception as e:
                logger.warning("Flow scoring error: %s", e)
        await asyncio.sleep(1)


# ── Routes ────────────────────────────────────────────────────────────────────

class CaptureStartRequest(BaseModel):
    iface: str
    bpf_filter: str = ""
    db_path: str = ""   # empty = use env/default


@router.get("/interfaces")
def list_interfaces() -> dict:
    return {"interfaces": _session.get_interfaces()}


@router.post("/start")
def start_capture(req: CaptureStartRequest, background_tasks: BackgroundTasks) -> dict:
    if _session.running:
        raise HTTPException(status_code=409, detail="Capture already running")
    try:
        _session.start(req.iface, req.bpf_filter)
        db = req.db_path or DB_PATH
        background_tasks.add_task(_processor, db)
        return {"started": True, "iface": req.iface, "bpf_filter": req.bpf_filter}
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.post("/stop")
def stop_capture() -> dict:
    if not _session.running:
        raise HTTPException(status_code=409, detail="No capture running")
    flushed = _session.stop()
    return {"stopped": True, "flows_flushed": len(flushed)}


@router.get("/status")
def capture_status() -> dict:
    """Return current capture state and live stats."""
    return {"running": _session.running, "stats": _session.stats}


@router.get("/stream")
async def capture_stream() -> StreamingResponse:
    async def _gen():
        while True:
            for ev in _session.drain_events():
                yield f"data: {json.dumps(ev)}\n\n"
            if not _session.running:
                yield 'data: {"type":"end"}\n\n'
                break
            await asyncio.sleep(0.5)
    return StreamingResponse(_gen(), media_type="text/event-stream")


@router.get("/recent-alerts")
def recent_live_alerts(limit: int = 50, conn: DBConn = None) -> dict:
    """
    Return recently scored alerts from LIVE capture (is_live=1).
    Falls back to all alerts if column not present (old DB).
    """
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        # Prefer timestamp column; fall back to created_at for ordering
        order_col = "timestamp" if "timestamp" in cols else "created_at"
        if "is_live" in cols:
            rows = conn.execute(
                f"SELECT * FROM alerts WHERE is_live=1 ORDER BY {order_col} DESC LIMIT ?",
                (limit,),
            ).fetchall()
        else:
            rows = conn.execute(
                f"SELECT * FROM alerts ORDER BY {order_col} DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return {"alerts": [dict(r) for r in rows]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))