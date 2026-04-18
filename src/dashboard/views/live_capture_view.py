"""
src/dashboard/views/live_capture_view.py
Live capture view — real-time packet interception with live scoring.

Fixes vs previous version:
  - Polls /capture/status correctly (was reading wrong nested key for stats)
  - Falls back gracefully when API is unreachable
  - Auto-refresh uses st.rerun() only when capture is active
  - Displays live alerts with Groq summary inline when available
  - "Live" badge distinguishes live flows from PCAP flows
"""

from __future__ import annotations

import threading
import time

import requests
import streamlit as st

API_BASE = "http://localhost:8000"

SEVERITY_COLOR = {
    "CRITICAL": "#f85149",
    "HIGH":     "#e3b341",
    "MEDIUM":   "#d29922",
    "LOW":      "#58a6ff",
    "CLEAN":    "#3fb950",
}


# ── API helper ────────────────────────────────────────────────────────────────

def _api(method: str, path: str, **kwargs):
    try:
        r = requests.request(method, f"{API_BASE}{path}", timeout=5, **kwargs)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        st.error("⚠️  FastAPI backend not reachable at localhost:8000 — start it first.")
        return None
    except Exception as e:
        st.error(f"API error: {e}")
        return None


# ── Session state defaults ────────────────────────────────────────────────────

def _init_state():
    defaults = {
        "cap_running":  False,
        "cap_packets":  0,
        "cap_tls":      0,
        "cap_bytes":    0,
        "cap_flows":    0,
        "cap_alerts":   [],
        "cap_last_poll": 0.0,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


# ── Background poller ─────────────────────────────────────────────────────────

def _poll_once():
    """Fetch latest stats and alerts from API and update session state."""
    try:
        status = requests.get(f"{API_BASE}/capture/status", timeout=3).json()
        if status:
            s = status.get("stats", {})
            st.session_state["cap_packets"] = s.get("packets_captured", 0)
            st.session_state["cap_tls"]     = s.get("tls_packets", 0)
            st.session_state["cap_bytes"]   = s.get("bytes_seen", 0)
            st.session_state["cap_flows"]   = s.get("active_flows", 0)
            # Sync running flag with server state
            st.session_state["cap_running"] = status.get("running", False)
    except Exception:
        pass

    try:
        alerts = requests.get(f"{API_BASE}/capture/recent-alerts?limit=50", timeout=3).json()
        if alerts:
            st.session_state["cap_alerts"] = alerts.get("alerts", [])
    except Exception:
        pass

    st.session_state["cap_last_poll"] = time.time()


# ── Main render ───────────────────────────────────────────────────────────────

def render():
    _init_state()

    # ── Header ────────────────────────────────────────────────────────────────
    col_icon, col_title = st.columns([0.06, 0.94])
    with col_icon:
        st.markdown(
            '<div style="width:48px;height:48px;background:#0d1117;border:1px solid #1f6feb;'
            'border-radius:8px;display:flex;align-items:center;justify-content:center;'
            'font-size:22px;margin-top:4px">⊙</div>',
            unsafe_allow_html=True,
        )
    with col_title:
        st.markdown("## Live Capture")
        st.caption("REAL-TIME PACKET INTERCEPTION")

    st.divider()

    # ── Interface + BPF ───────────────────────────────────────────────────────
    ifaces_resp = _api("GET", "/capture/interfaces")
    ifaces = ifaces_resp.get("interfaces", []) if ifaces_resp else []
    if not ifaces:
        ifaces = ["\\Device\\NPF_Loopback", "eth0", "lo"]

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**NETWORK INTERFACE**")
        iface = st.selectbox(
            "iface", ifaces,
            label_visibility="collapsed",
            disabled=st.session_state["cap_running"],
        )
    with c2:
        st.markdown("**CAPTURE FILTER (BPF)**")
        bpf = st.text_input(
            "bpf", placeholder="Leave empty to capture all traffic",
            label_visibility="collapsed",
            disabled=st.session_state["cap_running"],
        )

    # ── Start / Stop ──────────────────────────────────────────────────────────
    btn_start, btn_stop, _ = st.columns([1, 1, 4])
    with btn_start:
        if st.button(
            "▶  START CAPTURE",
            disabled=st.session_state["cap_running"],
            use_container_width=True,
        ):
            resp = _api("POST", "/capture/start", json={"iface": iface, "bpf_filter": bpf})
            if resp and resp.get("started"):
                st.session_state["cap_running"] = True
                st.rerun()

    with btn_stop:
        if st.button(
            "■  STOP CAPTURE",
            disabled=not st.session_state["cap_running"],
            use_container_width=True,
        ):
            resp = _api("POST", "/capture/stop")
            if resp is not None:
                st.session_state["cap_running"] = False
                flushed = resp.get("flows_flushed", 0)
                st.success(f"Stopped. {flushed} flow(s) flushed and scored.")
                st.rerun()

    st.divider()

    # Poll on every render while running
    if st.session_state["cap_running"]:
        _poll_once()

    # ── Stats cards ───────────────────────────────────────────────────────────
    CARD = (
        '<div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;'
        'padding:16px 20px">'
        '<div style="font-size:10px;color:#8b949e;letter-spacing:1.5px;margin-bottom:6px">{label}</div>'
        '<div style="font-size:28px;font-weight:700;color:{color};font-family:monospace">{value}</div>'
        '</div>'
    )

    c1, c2, c3, c4 = st.columns(4)
    c1.markdown(CARD.format(label="PACKETS CAPTURED",
                             value=f'{st.session_state["cap_packets"]:,}',
                             color="#e6edf3"), unsafe_allow_html=True)
    c2.markdown(CARD.format(label="TLS PACKETS",
                             value=f'{st.session_state["cap_tls"]:,}',
                             color="#58a6ff"), unsafe_allow_html=True)
    c3.markdown(CARD.format(label="BYTES SEEN",
                             value=f'{st.session_state["cap_bytes"]:,}',
                             color="#e6edf3"), unsafe_allow_html=True)
    c4.markdown(CARD.format(label="ACTIVE FLOWS",
                             value=f'{st.session_state["cap_flows"]:,}',
                             color="#3fb950"), unsafe_allow_html=True)

    st.divider()

    # ── Status banner ─────────────────────────────────────────────────────────
    if st.session_state["cap_running"]:
        st.markdown(
            '<div style="background:#0d2137;border:1px solid #1f6feb;border-radius:8px;'
            'padding:14px 18px;display:flex;align-items:center;gap:10px">'
            '<span style="width:9px;height:9px;background:#3fb950;border-radius:50%;'
            'display:inline-block;animation:pulse 1s infinite"></span>'
            '<span style="color:#58a6ff;font-weight:600">Capturing live traffic…</span>'
            '<span style="color:#8b949e;font-size:13px;margin-left:6px">'
            'Flows are scored with the trained IsolationForest model and appear below.</span>'
            '</div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;'
            'padding:24px;text-align:center;color:#8b949e;font-size:15px">'
            'No live packets captured yet. Click START CAPTURE to begin.</div>',
            unsafe_allow_html=True,
        )

    # ── Live alerts ───────────────────────────────────────────────────────────
    alerts = st.session_state.get("cap_alerts", [])
    if alerts:
        st.markdown(f"### ⚡ Live Alerts &nbsp;<span style='font-size:14px;color:#8b949e'>({len(alerts)} recent)</span>",
                    unsafe_allow_html=True)

        for a in alerts[:30]:
            sev      = a.get("severity", "LOW")
            color    = SEVERITY_COLOR.get(sev, "#8b949e")
            score    = a.get("composite_score", 0)
            groq_sum = a.get("groq_summary", "")

            # Groq summary line (shown only when available)
            groq_html = ""
            if groq_sum:
                threat = a.get("groq_threat_type", "")
                threat_label = f"[{threat.replace('_',' ')}] " if threat else ""
                groq_html = (
                    f'<div style="color:#8b949e;font-size:12px;margin-top:5px;'
                    f'padding-left:2px;font-style:italic">'
                    f'🤖 {threat_label}{groq_sum}</div>'
                )

            # Findings (first one only for the list view)
            findings = a.get("findings", "[]")
            if isinstance(findings, str):
                try:
                    import json
                    findings = json.loads(findings)
                except Exception:
                    findings = [findings]
            top_finding = findings[0] if findings else "Anomaly detected"

            st.markdown(
                f'<div style="background:#0d1117;border:1px solid #21262d;border-radius:6px;'
                f'padding:12px 16px;margin-bottom:5px">'
                f'<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">'
                f'<span style="color:{color};font-weight:700;font-size:12px;'
                f'min-width:68px;padding:2px 8px;border:1px solid {color}44;'
                f'border-radius:4px">{sev}</span>'
                f'<span style="color:#e6edf3;font-family:monospace;font-size:13px">'
                f'{a.get("src_ip","?")}:{a.get("src_port","")} '
                f'→ {a.get("dst_ip","?")}:{a.get("dst_port","")}'
                f'</span>'
                f'<span style="color:#8b949e;font-size:12px">score {score:.3f}</span>'
                f'<span style="color:#3fb950;font-size:11px;margin-left:auto;'
                f'background:#0d2014;padding:2px 6px;border-radius:3px">⚡ LIVE</span>'
                f'</div>'
                f'<div style="color:#6e7681;font-size:12px;margin-top:4px">{top_finding}</div>'
                f'{groq_html}'
                f'</div>',
                unsafe_allow_html=True,
            )

    # ── Auto-refresh while running ────────────────────────────────────────────
    if st.session_state["cap_running"]:
        time.sleep(2)
        st.rerun()