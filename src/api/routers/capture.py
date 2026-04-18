"""
src/api/routers/capture.py
Live capture router — start/stop real-time packet capture and stream results.

Fixes in this version:
  - src_ip/src_port always = the CLIENT side (higher ephemeral port),
    dst_ip/dst_port always = the SERVER side (lower well-known port).
    Previously the 5-tuple was sorted lexicographically which swapped them,
    causing src_port=0 and wrong directions in all downstream views.
  - All five module scores (anomaly, ja3, beacon, cert, graph) are written to
    both the flows and alerts tables, so the alert detail risk-factor bars
    show real values instead of all-zero.
  - composite_score is capped correctly; anomaly=1 no longer forces it to 1.0
    while other modules are 0 — the weighted formula is used properly.
  - Windows: BPF filter is not passed to Scapy (Npcap BPF is unreliable);
    Python-level port filtering keeps only TCP/UDP traffic.
  - Interface list returns {friendly, npf_path} dicts with Wi-Fi sorted first.
  - Flow timeout 15 s / early-emit after 10 packets for fast feedback.
  - Supabase + Groq run in one background thread for HIGH/CRITICAL alerts.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import platform
import sqlite3
import statistics
import subprocess
import threading
import time
import queue
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Optional

import numpy as np
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from src.api.dependencies import get_db_conn

logger = logging.getLogger(__name__)

router  = APIRouter(prefix="/capture", tags=["capture"])
DBConn  = Annotated[sqlite3.Connection, Depends(get_db_conn)]

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
DB_PATH      = os.getenv("SPECTRA_DB", str(_PROJECT_ROOT / "data" / "spectra.db"))
_MODEL_PATH  = _PROJECT_ROOT / "models" / "isolation_forest.joblib"
_SCALER_PATH = _PROJECT_ROOT / "models" / "scaler.joblib"

IS_WINDOWS = platform.system() == "Windows"

# ── Scapy ─────────────────────────────────────────────────────────────────────
try:
    from scapy.all import sniff, get_if_list, conf as scapy_conf
    scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not installed — live capture unavailable.")

# ── ML model (loaded once) ────────────────────────────────────────────────────
_model  = None
_scaler = None

def _load_model() -> bool:
    global _model, _scaler
    if _model is not None:
        return True
    try:
        import joblib
        _model  = joblib.load(_MODEL_PATH)
        _scaler = joblib.load(_SCALER_PATH)
        logger.info("ML model loaded from %s", _MODEL_PATH.parent)
        return True
    except Exception as e:
        logger.warning("Could not load ML model: %s — heuristic fallback active", e)
        return False

_load_model()


# ── Windows interface helpers ─────────────────────────────────────────────────

def _guid_to_friendly(guid: str) -> str:
    try:
        import winreg
        clean    = guid.strip("{}")
        reg_path = (
            r"SYSTEM\CurrentControlSet\Control\Network"
            r"\{4D36E972-E325-11CE-BFC1-08002BE10318}"
            rf"\{{{clean}}}\Connection"
        )
        key  = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
        name, _ = winreg.QueryValueEx(key, "Name")
        winreg.CloseKey(key)
        return str(name)
    except Exception:
        return ""


def _get_all_interfaces() -> list[dict]:
    results: list[dict] = []
    seen: set[str] = set()

    raw: list[str] = []
    if SCAPY_AVAILABLE:
        try:
            raw = get_if_list()
        except Exception:
            pass

    if not raw:
        try:
            out = subprocess.run(
                ["tshark", "-D"], capture_output=True, text=True, timeout=8, check=False
            )
            for line in out.stdout.strip().splitlines():
                if ". " in line:
                    line = line.split(". ", 1)[1]
                name = line.split("(")[0].strip() if "(" in line else line.strip()
                if name:
                    raw.append(name)
        except Exception:
            raw = ["eth0", "wlan0"]

    for npf in raw:
        if IS_WINDOWS:
            guid = ""
            if "{" in npf and "}" in npf:
                guid = npf[npf.index("{"):npf.index("}") + 1]
            friendly = _guid_to_friendly(guid) if guid else npf
            if not friendly:
                friendly = guid or npf
        else:
            friendly = npf

        if friendly in seen:
            continue
        seen.add(friendly)
        results.append({"friendly": friendly, "npf_path": npf})

    def _sort(item: dict) -> tuple:
        fn = item["friendly"].lower()
        if "wi-fi" in fn or "wlan" in fn or "wireless" in fn: return (0, fn)
        if "ethernet" in fn or "local area" in fn:             return (1, fn)
        if "loopback" in fn or fn == "lo":                     return (9, fn)
        return (5, fn)

    results.sort(key=_sort)
    return results


# ── Scoring helpers (self-contained) ─────────────────────────────────────────

SCORING_FEATURE_COLUMNS = [
    "regularity_score", "payload_consistency", "cert_age_normalized",
    "tls_version_encoded", "bytes_per_second", "packet_rate",
]

def _scoring_features(flow: dict) -> dict:
    mean_iat    = flow.get("mean_iat_ms", 0) or 1e-9
    std_iat     = flow.get("std_iat_ms", 0) or 0
    total_bytes = flow.get("total_bytes", 0) or 1
    fwd_bytes   = flow.get("fwd_bytes", total_bytes) or 0
    ratio       = fwd_bytes / total_bytes
    return {
        "regularity_score":    float(max(0.0, 1.0 - min(std_iat / mean_iat, 1.0))),
        "payload_consistency": float(1.0 - abs(ratio - 0.5) * 2),
        "cert_age_normalized": 0.0,
        "tls_version_encoded": 0.0,
        "bytes_per_second":    float(flow.get("byte_rate_per_sec", 0) or 0),
        "packet_rate":         float(flow.get("packet_rate_per_sec", 0) or 0),
    }

def _module_scores(flow: dict) -> dict:
    dst_port    = int(flow.get("dst_port", 0))
    pkt_rate    = float(flow.get("packet_rate_per_sec", 0) or 0)
    mean_iat    = float(flow.get("mean_iat_ms", 0) or 1e-9)
    std_iat     = float(flow.get("std_iat_ms", 0) or 0)
    syn_count   = int(flow.get("syn_count", 0) or 0)
    rst_count   = int(flow.get("rst_count", 0) or 0)
    fin_count   = int(flow.get("fin_count", 0) or 0)
    total_pkts  = max(int(flow.get("total_packets", 1) or 1), 1)
    total_bytes = int(flow.get("total_bytes", 0) or 0)
    avg_pkt     = float(flow.get("avg_packet_size", 0) or 0)
    duration_ms = float(flow.get("duration_ms", 1) or 1)

    is_tls  = 1.0 if dst_port in (443, 8443, 993, 995, 465) else 0.0
    iat_cv  = min(std_iat / mean_iat, 5.0) / 5.0
    p_anom  = min((0.6 if 0 < pkt_rate < 1.0 else 0.0) + (0.8 if pkt_rate > 500 else 0.0), 1.0)
    ja3     = round(min(1.0, 0.4*p_anom + 0.4*is_tls*max(0.0, 1.0-iat_cv) + 0.2*is_tls*(1.0 if syn_count > 3 else 0.0)), 4)

    reg     = max(0.0, 1.0 - min(std_iat / mean_iat, 1.0))
    beacon  = round(min(1.0, 0.45*reg
                         + 0.25*(1.0 if avg_pkt < 200 else 0.0)
                         + 0.20*(1.0 if total_bytes < 5000 else 0.0)
                         + 0.10*min((total_pkts / max(duration_ms/1000.0, 0.001)) / 100.0, 1.0)), 4)

    rst_r   = min(rst_count / total_pkts, 1.0)
    fin_r   = min(fin_count / total_pkts, 1.0)
    cert    = round(min(1.0, 0.35*(0.5 if dst_port not in (443, 8443) else 0.0)
                         + 0.35*min((1.0 if duration_ms < 500 else 0.0) * rst_r, 1.0)
                         + 0.20*rst_r + 0.10*fin_r), 4)

    return {"ja3_score": ja3, "beacon_score": beacon, "cert_score": cert, "graph_score": 0.0}

def _composite(anomaly, ja3, beacon, cert, graph) -> float:
    return round(float(np.clip(0.40*anomaly + 0.20*beacon + 0.15*ja3 + 0.15*cert + 0.10*graph, 0.0, 1.0)), 4)

def _severity(score: float) -> str:
    if score >= 0.90: return "CRITICAL"
    if score >= 0.75: return "HIGH"
    if score >= 0.60: return "MEDIUM"
    if score >= 0.30: return "LOW"
    return "CLEAN"

def _alert_id(src_ip, src_port, dst_ip, dst_port, protocol="TCP") -> str:
    return hashlib.sha256(f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}".encode()).hexdigest()[:16]

def _beacon_alert_id(src_ip, dst_ip, dst_port) -> str:
    return hashlib.sha256(f"beacon:{src_ip}:{dst_ip}:{dst_port}:{int(time.time()//60)}".encode()).hexdigest()[:16]


# ── Flow accumulator ──────────────────────────────────────────────────────────

class _FlowAccumulator:
    FLOW_TIMEOUT_SEC   = 15
    EARLY_EMIT_PACKETS = 10

    def __init__(self):
        self._flows: dict[str, dict] = {}
        self._lock  = threading.Lock()

    @staticmethod
    def _orient(pkt) -> tuple[str, int, str, int]:
        """
        Always return (client_ip, client_port, server_ip, server_port).
        The client is the side that sent the SYN (higher ephemeral port);
        the server has the well-known port (443, 80, etc.).
        For UDP we use the same heuristic: lower port = server.
        Never swap src/dst — direction matters for the rest of the pipeline.
        """
        ip  = pkt["IP"]
        src_ip, dst_ip = ip.src, ip.dst
        if pkt.haslayer("TCP"):
            sp = pkt["TCP"].sport
            dp = pkt["TCP"].dport
        elif pkt.haslayer("UDP"):
            sp = pkt["UDP"].sport
            dp = pkt["UDP"].dport
        else:
            sp = dp = 0

        # Heuristic: well-known ports (≤1024 or common TLS ports) = server side
        WELL_KNOWN = {80, 443, 8080, 8443, 993, 465, 587, 53, 22, 21, 25, 110, 143}
        if dp in WELL_KNOWN or (dp <= 1024 and sp > 1024):
            return src_ip, sp, dst_ip, dp   # normal: src=client, dst=server
        if sp in WELL_KNOWN or (sp <= 1024 and dp > 1024):
            return dst_ip, dp, src_ip, sp   # reversed packet (response): flip back
        # Both ephemeral or both well-known — keep as-is
        return src_ip, sp, dst_ip, dp

    def _key(self, pkt) -> Optional[str]:
        if not pkt.haslayer("IP"):
            return None
        try:
            src_ip, sp, dst_ip, dp = self._orient(pkt)
            proto = "6" if pkt.haslayer("TCP") else "17"
            return f"{src_ip}:{sp}-{dst_ip}:{dp}-{proto}"
        except Exception:
            return None

    def add_packet(self, pkt) -> Optional[dict]:
        key = self._key(pkt)
        if not key:
            return None
        now = time.time()
        with self._lock:
            if key not in self._flows:
                try:
                    src_ip, sp, dst_ip, dp = self._orient(pkt)
                except Exception:
                    return None
                self._flows[key] = dict(
                    src_ip=src_ip, dst_ip=dst_ip,
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
            f["byte_count"]   += pkt_len
            f["pkt_sizes"].append(pkt_len)
            if f["packet_count"] > 1:
                f["intervals"].append(now - f["last_time"])
            f["last_time"] = now
            if f["dst_port"] in (443, 8443, 993, 465, 587):
                f["tls_count"] += 1
            if pkt.haslayer("TCP"):
                flags = int(pkt["TCP"].flags)
                if flags & 0x04: f["rst_count"] += 1
                if flags & 0x02: f["syn_count"] += 1
                if flags & 0x01: f["fin_count"] += 1

            elapsed = now - f["start_time"]
            if f["packet_count"] >= self.EARLY_EMIT_PACKETS or elapsed > self.FLOW_TIMEOUT_SEC:
                completed = self._finalise(key)
                del self._flows[key]
                return completed
        return None

    def _finalise(self, key: str) -> dict:
        f   = self._flows[key]
        dur = max(f["last_time"] - f["start_time"], 0.001)
        ivs, szs = f["intervals"], f["pkt_sizes"]
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
            "mean_iat_ms":         statistics.mean(ivs) * 1000 if ivs else 0,
            "std_iat_ms":          (statistics.stdev(ivs) * 1000 if len(ivs) > 1 else 0),
            "min_iat_ms":          min(ivs) * 1000 if ivs else 0,
            "max_iat_ms":          max(ivs) * 1000 if ivs else 0,
            "tls_ratio":           f["tls_count"] / max(f["packet_count"], 1),
            "rst_count":           f["rst_count"],
            "syn_count":           f["syn_count"],
            "fin_count":           f["fin_count"],
            "ack_count":           0,
            "psh_count":           0,
            "tcp_flags":           json.dumps({"SYN": f["syn_count"], "RST": f["rst_count"], "FIN": f["fin_count"]}),
        }

    def flush_all(self) -> list[dict]:
        with self._lock:
            completed = [self._finalise(k) for k in list(self._flows)]
            self._flows.clear()
            return completed

    @property
    def active_count(self) -> int:
        return len(self._flows)


# ── Capture session ───────────────────────────────────────────────────────────

class _CaptureSession:
    def __init__(self):
        self.running     = False
        self._thread: Optional[threading.Thread] = None
        self._accumulator = _FlowAccumulator()
        self._flow_q:  queue.Queue = queue.Queue()
        self._event_q: queue.Queue = queue.Queue()
        self.stats       = dict(packets_captured=0, tls_packets=0, bytes_seen=0, active_flows=0)
        self._iface      = ""
        self._bpf        = ""
        self._iface_cache: list[dict] = []

    def get_interfaces(self) -> list[dict]:
        if not self._iface_cache:
            self._iface_cache = _get_all_interfaces()
        return self._iface_cache

    def start(self, npf_path: str, bpf_filter: str = "") -> None:
        if self.running:
            raise RuntimeError("Capture already running")
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy not installed. Run: pip install scapy\n"
                               "Also install Npcap (https://npcap.com) on Windows.")
        self._iface       = npf_path
        self._bpf         = bpf_filter
        self.running      = True
        self.stats        = dict(packets_captured=0, tls_packets=0, bytes_seen=0, active_flows=0)
        self._accumulator = _FlowAccumulator()
        self._thread      = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self._push("status", {"running": True, "iface": npf_path})
        self._update_status_row(is_running=1, interface=npf_path, bpf_filter=bpf_filter)

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
            # Skip non-IP packets early
            if not pkt.haslayer("IP"):
                return
            if not (pkt.haslayer("TCP") or pkt.haslayer("UDP")):
                return

            self.stats["packets_captured"] += 1
            self.stats["bytes_seen"]       += len(pkt)

            if pkt.haslayer("TCP"):
                dp = pkt["TCP"].dport
                sp = pkt["TCP"].sport
                if dp in (443, 8443, 993, 465, 587) or sp in (443, 8443, 993, 465, 587):
                    self.stats["tls_packets"] += 1

            self.stats["active_flows"] = self._accumulator.active_count

            completed = self._accumulator.add_packet(pkt)
            if completed:
                self._flow_q.put(completed)
                self._push("flow", {
                    "src": f"{completed['src_ip']}:{completed['src_port']}",
                    "dst": f"{completed['dst_ip']}:{completed['dst_port']}",
                    "pkts": completed["total_packets"],
                    "bytes": completed["total_bytes"],
                })

            if self.stats["packets_captured"] % 20 == 0:
                self._push("stats", self.stats.copy())
                self._update_stats_row()

        # On Windows never pass BPF to Scapy — Npcap BPF is unreliable
        bpf_arg = None
        if self._bpf.strip() and not IS_WINDOWS:
            bpf_arg = self._bpf.strip()

        try:
            sniff(
                iface=self._iface,
                filter=bpf_arg,
                prn=handle,
                stop_filter=lambda _: not self.running,
                store=False,
            )
        except Exception as e:
            logger.error("Capture error on %s: %s", self._iface, e)
            self.running = False
            self._push("error", {"message": str(e)})

    def _push(self, event_type: str, data: dict):
        self._event_q.put({"type": event_type, "data": data, "ts": time.time()})

    def drain_flows(self) -> list[dict]:
        out = []
        while not self._flow_q.empty():
            try: out.append(self._flow_q.get_nowait())
            except queue.Empty: break
        return out

    def drain_events(self) -> list[dict]:
        out = []
        while not self._event_q.empty():
            try: out.append(self._event_q.get_nowait())
            except queue.Empty: break
        return out

    def _update_status_row(self, **kwargs):
        kwargs["updated_at"] = time.time()
        cols = ", ".join(f"{k}=?" for k in kwargs)
        try:
            conn = sqlite3.connect(DB_PATH, timeout=5)
            conn.execute(f"UPDATE live_capture_status SET {cols} WHERE id=1", list(kwargs.values()))
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


# ── Score + store one completed flow ──────────────────────────────────────────

def _ensure_alert_columns(conn: sqlite3.Connection) -> None:
    """Add columns to alerts table that may be missing in older databases."""
    existing = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    additions = [
        ("dst_port",  "INTEGER DEFAULT 0"),
        ("is_live",   "INTEGER DEFAULT 0"),
    ]
    for col, definition in additions:
        if col not in existing:
            try:
                conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} {definition}")
                conn.commit()
                logger.info("Added missing column alerts.%s", col)
            except Exception:
                pass  # Already exists or DB locked — safe to ignore


def _score_and_store(flow: dict, db_path: str = None) -> Optional[dict]:
    db_path = db_path or DB_PATH

    # ── ML anomaly score ──────────────────────────────────────────────────────
    try:
        feats = _scoring_features(flow)
        X     = np.array([[feats[c] for c in SCORING_FEATURE_COLUMNS]])
        X     = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        X_sc  = _scaler.transform(X) if _scaler else X
        raw   = _model.score_samples(X_sc)[0] if _model else -0.5
        anomaly = float(np.clip(-raw * 2.0, 0.0, 1.0))
        verdict = "ANOMALY" if anomaly >= 0.70 else "BENIGN"
    except Exception as e:
        logger.warning("ML scoring failed (%s) — heuristic", e)
        rst_r   = flow.get("rst_count", 0) / max(flow.get("total_packets", 1), 1)
        anomaly = min(1.0, rst_r * 2.0 + 0.3)
        verdict = "ANOMALY" if anomaly >= 0.50 else "BENIGN"

    if verdict == "BENIGN":
        return None

    # ── Module scores (all five) ───────────────────────────────────────────────
    m = _module_scores(flow)
    composite = _composite(anomaly, m["ja3_score"], m["beacon_score"], m["cert_score"], m["graph_score"])
    sev       = _severity(composite)

    src_ip   = str(flow.get("src_ip", ""))
    dst_ip   = str(flow.get("dst_ip", ""))
    src_port = int(flow.get("src_port", 0))
    dst_port = int(flow.get("dst_port", 0))
    protocol = str(flow.get("protocol", "TCP"))

    # ── Findings ──────────────────────────────────────────────────────────────
    findings: list[str] = []
    if composite >= 0.90:   findings.append("Extremely high anomaly score — likely malicious")
    elif composite >= 0.75: findings.append("High anomaly score detected")
    elif composite >= 0.60: findings.append("Moderate anomaly score detected")
    else:                   findings.append("Low-level anomaly detected")
    if m["ja3_score"]    >= 0.60: findings.append(f"Suspicious TLS fingerprint pattern (JA3={m['ja3_score']:.2f})")
    if m["beacon_score"] >= 0.60: findings.append(f"Beaconing behavior detected (beacon={m['beacon_score']:.2f})")
    if m["cert_score"]   >= 0.50: findings.append(f"Certificate anomaly proxy triggered (cert={m['cert_score']:.2f})")
    findings_str = json.dumps(findings)

    recommended = {
        "CRITICAL": "Block immediately — isolate source host",
        "HIGH":     "Investigate and consider blocking source IP",
        "MEDIUM":   "Monitor closely — flag for review",
        "LOW":      "Log and monitor",
    }.get(sev, "Review manually")

    now_ts    = datetime.now(timezone.utc).timestamp()
    flow_id   = hashlib.sha256(f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}".encode()).hexdigest()[:32]
    is_beacon = m["beacon_score"] >= 0.60 and sev in ("HIGH", "CRITICAL")
    aid       = _beacon_alert_id(src_ip, dst_ip, dst_port) if is_beacon \
                else _alert_id(src_ip, src_port, dst_ip, dst_port, protocol)

    try:
        conn = sqlite3.connect(db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        # Add missing columns to alerts table if they don't exist (one-time migration)
        _ensure_alert_columns(conn)
        dur_s = flow.get("duration_ms", 0) / 1000.0

        # ── flows table ───────────────────────────────────────────────────────
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
            ) VALUES (?,?,?,?,?,?,  ?,?,?,  ?,?,?,?,  ?,?,?,  ?,?,?,?,
                      ?,?,?,?,?,?,  ?,?,?,?,?,?)""", (
            flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
            now_ts, now_ts + dur_s, flow.get("duration_ms", 0),
            int(flow.get("total_packets", 0)), int(flow.get("total_bytes", 0)),
            int(flow.get("fwd_bytes", 0)), int(flow.get("bwd_bytes", 0)),
            float(flow.get("packet_rate_per_sec", 0)), float(flow.get("byte_rate_per_sec", 0)),
            float(flow.get("avg_packet_size", 0)),
            flow.get("tcp_flags", "{}"),
            int(flow.get("syn_count", 0)), int(flow.get("rst_count", 0)), int(flow.get("fin_count", 0)),
            round(composite, 4), round(anomaly, 4),
            round(m["ja3_score"], 4), round(m["beacon_score"], 4),
            round(m["cert_score"], 4), round(m["graph_score"], 4),
            "ACTIVE", verdict, sev, "live", 1, now_ts,
        ))

        # ── alerts table ──────────────────────────────────────────────────────
        existing = conn.execute("SELECT alert_id FROM alerts WHERE alert_id=?", (aid,)).fetchone()
        if existing and not is_beacon:
            conn.execute("""
                UPDATE alerts SET
                    composite_score=?, severity=?, anomaly_score=?,
                    ja3_score=?, beacon_score=?, cert_score=?, graph_score=?,
                    findings=?, recommended_action=?, timestamp=?
                WHERE alert_id=?""",
                (round(composite,4), sev, round(anomaly,4),
                 round(m["ja3_score"],4), round(m["beacon_score"],4),
                 round(m["cert_score"],4), round(m["graph_score"],4),
                 findings_str, recommended, now_ts, aid))
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
                (aid, flow_id, now_ts, now_ts, sev,
                 round(composite,4), round(anomaly,4),
                 round(m["ja3_score"],4), round(m["beacon_score"],4),
                 round(m["cert_score"],4), round(m["graph_score"],4),
                 src_ip, src_port, dst_ip, dst_port, "",
                 findings_str, recommended,
                 0, 1, int(is_beacon)))

        conn.commit(); conn.close()

    except Exception as e:
        logger.error("DB write failed: %s", e)
        return None

    result = {
        "alert_id": aid, "flow_id": flow_id,
        "src_ip": src_ip, "src_port": src_port,
        "dst_ip": dst_ip, "dst_port": dst_port,
        "severity": sev, "composite_score": round(composite, 4),
        "anomaly_score": round(anomaly, 4),
        "ja3_score": round(m["ja3_score"], 4),
        "beacon_score": round(m["beacon_score"], 4),
        "cert_score": round(m["cert_score"], 4),
        "graph_score": round(m["graph_score"], 4),
        "findings": findings,
        "recommended_action": recommended,
        "timestamp": now_ts, "is_live": 1, "is_suppressed": 0,
        "is_beacon": int(is_beacon),
    }

    # Mirror ALL anomaly alerts to Supabase; Groq analysis for HIGH/CRITICAL only
    def _bg():
        # Always push to Supabase so alert_id is recorded for every detection
        try:
            from src.integrations.supabase_client import mirror_alert_any_severity
            mirror_alert_any_severity(result)
        except Exception:
            try:
                from src.integrations.supabase_client import mirror_alert
                mirror_alert(result)
            except Exception:
                pass
        # AI explanation only for serious alerts
        if sev in ("HIGH", "CRITICAL"):
            try:
                from src.integrations.groq_client import analyse_and_store
                analyse_and_store(result, db_path)
            except Exception:
                pass
    threading.Thread(target=_bg, daemon=True).start()

    return result


# ── Background processor ──────────────────────────────────────────────────────

async def _processor(db_path: str):
    while _session.running:
        for flow in _session.drain_flows():
            try:
                alert = _score_and_store(flow, db_path)
                if alert:
                    logger.info("LIVE %s  %s:%d→%s:%d  composite=%.3f  "
                                "anomaly=%.3f ja3=%.3f beacon=%.3f cert=%.3f",
                                alert["severity"],
                                alert["src_ip"], alert["src_port"],
                                alert["dst_ip"], alert["dst_port"],
                                alert["composite_score"],
                                alert["anomaly_score"], alert["ja3_score"],
                                alert["beacon_score"], alert["cert_score"])
            except Exception as e:
                logger.warning("Flow scoring error: %s", e)
        await asyncio.sleep(0.5)


# ── Routes ────────────────────────────────────────────────────────────────────

class CaptureStartRequest(BaseModel):
    npf_path:   str
    bpf_filter: str = ""
    db_path:    str = ""


@router.get("/interfaces")
def list_interfaces() -> dict:
    return {"interfaces": _session.get_interfaces()}


@router.post("/start")
def start_capture(req: CaptureStartRequest, background_tasks: BackgroundTasks) -> dict:
    if _session.running:
        raise HTTPException(status_code=409, detail="Capture already running")
    _load_model()
    try:
        _session.start(req.npf_path, req.bpf_filter)
        background_tasks.add_task(_processor, req.db_path or DB_PATH)
        return {"started": True, "iface": req.npf_path, "bpf_filter": req.bpf_filter}
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
            await asyncio.sleep(0.3)
    return StreamingResponse(_gen(), media_type="text/event-stream")


@router.get("/recent-alerts")
def recent_live_alerts(
    limit: int = 50,
    live_only: int = Query(default=0),
    conn: DBConn = None,
) -> dict:
    try:
        cols      = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        order_col = "timestamp" if "timestamp" in cols else "created_at"
        where     = "WHERE is_live=1" if (live_only and "is_live" in cols) else ""
        rows      = conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY {order_col} DESC LIMIT ?", (limit,)
        ).fetchall()
        return {"alerts": [dict(r) for r in rows]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))