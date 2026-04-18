"""
src/dashboard/views/live_capture_view.py

Fixes in this version:
  - Interface dropdown shows friendly names (Wi-Fi, Ethernet, etc.) not raw NPF GUIDs
  - Wi-Fi / WLAN interface is auto-selected by default
  - Sends npf_path (raw path) to the API for Scapy, not the friendly name
  - BPF filter left empty by default on Windows (Npcap BPF support is limited)
  - Polls for alerts on every render (running or stopped) so results show after stop
  - Groq AI explanation shown inline when available
  - Live vs PCAP badge
"""

from __future__ import annotations

import json
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


# ── State ─────────────────────────────────────────────────────────────────────

def _init_state():
    defaults = {
        "cap_running":    False,
        "cap_packets":    0,
        "cap_tls":        0,
        "cap_bytes":      0,
        "cap_flows":      0,
        "cap_alerts":     [],
        "cap_last_poll":  0.0,
        # Interface map: friendly_name → npf_path
        "cap_iface_map":  {},
        "cap_iface_list": [],   # ordered list of friendly names
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


# ── Poll ──────────────────────────────────────────────────────────────────────

def _poll_once():
    try:
        status = requests.get(f"{API_BASE}/capture/status", timeout=3).json()
        if status:
            s = status.get("stats", {})
            st.session_state["cap_packets"] = s.get("packets_captured", 0)
            st.session_state["cap_tls"]     = s.get("tls_packets", 0)
            st.session_state["cap_bytes"]   = s.get("bytes_seen", 0)
            st.session_state["cap_flows"]   = s.get("active_flows", 0)
            st.session_state["cap_running"] = status.get("running", False)
    except Exception:
        pass

    try:
        alerts = requests.get(
            f"{API_BASE}/capture/recent-alerts?limit=50&live_only=1", timeout=3
        ).json()
        if alerts:
            st.session_state["cap_alerts"] = alerts.get("alerts", [])
    except Exception:
        pass

    st.session_state["cap_last_poll"] = time.time()


def _load_interfaces():
    """Fetch interface list from API and build friendly→npf_path map."""
    resp = _api("GET", "/capture/interfaces")
    if not resp:
        return

    ifaces = resp.get("interfaces", [])
    if not ifaces:
        return

    iface_map  = {}
    iface_list = []

    for item in ifaces:
        if isinstance(item, dict):
            friendly = item.get("friendly", "")
            npf_path = item.get("npf_path", friendly)
        else:
            # Fallback if API returns plain strings
            friendly = str(item)
            npf_path = str(item)

        if not friendly:
            continue
        iface_map[friendly]  = npf_path
        iface_list.append(friendly)

    st.session_state["cap_iface_map"]  = iface_map
    st.session_state["cap_iface_list"] = iface_list


def _default_iface_index(iface_list: list[str]) -> int:
    """Pick Wi-Fi / WLAN as default, then Ethernet, then index 0."""
    for i, name in enumerate(iface_list):
        lower = name.lower()
        if "wi-fi" in lower or "wlan" in lower or "wireless" in lower:
            return i
    for i, name in enumerate(iface_list):
        lower = name.lower()
        if "ethernet" in lower or "local area" in lower:
            return i
    return 0


# ── Main render ───────────────────────────────────────────────────────────────

def render():
    _init_state()

    # Header
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

    # Load interfaces on first visit or when not running
    if not st.session_state["cap_iface_list"] or not st.session_state["cap_running"]:
        _load_interfaces()

    iface_list = st.session_state["cap_iface_list"]
    iface_map  = st.session_state["cap_iface_map"]

    if not iface_list:
        st.warning("No interfaces found. Make sure Npcap is installed and the FastAPI backend is running.")
        iface_list = ["Wi-Fi", "Ethernet"]
        iface_map  = {"Wi-Fi": "Wi-Fi", "Ethernet": "Ethernet"}

    # Interface + BPF
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**NETWORK INTERFACE**")
        default_idx = _default_iface_index(iface_list)
        selected_friendly = st.selectbox(
            "iface",
            iface_list,
            index=default_idx,
            label_visibility="collapsed",
            disabled=st.session_state["cap_running"],
            help="Select Wi-Fi or Ethernet — the interface carrying your browser traffic.",
        )
        selected_npf = iface_map.get(selected_friendly, selected_friendly)
        # Show the raw path in small text so you can verify
        st.caption(f"Path: `{selected_npf}`")

    with c2:
        st.markdown("**CAPTURE FILTER (BPF)**")
        bpf = st.text_input(
            "bpf",
            value="",
            placeholder="Leave empty (recommended on Windows) or: tcp port 443",
            label_visibility="collapsed",
            disabled=st.session_state["cap_running"],
            help=(
                "On Windows with Npcap, leave empty to capture all TCP traffic. "
                "BPF filtering happens in Python automatically."
            ),
        )

    st.info(
        "💡 Open a few websites in your browser **before** clicking Start. "
        "Flows are emitted after ~10 packets or 15 s — alerts appear below automatically.",
        icon="ℹ️",
    )

    # Start / Stop
    btn_start, btn_stop, _ = st.columns([1, 1, 4])
    with btn_start:
        if st.button(
            "▶  START CAPTURE",
            disabled=st.session_state["cap_running"],
            use_container_width=True,
        ):
            resp = _api(
                "POST", "/capture/start",
                json={"npf_path": selected_npf, "bpf_filter": bpf},
            )
            if resp and resp.get("started"):
                st.session_state["cap_running"] = True
                st.success(f"Capturing on **{selected_friendly}**")
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
                _poll_once()
                st.rerun()

    st.divider()

    # Poll on every render
    _poll_once()

    # Stats cards
    CARD = (
        '<div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;'
        'padding:16px 20px">'
        '<div style="font-size:10px;color:#8b949e;letter-spacing:1.5px;margin-bottom:6px">{label}</div>'
        '<div style="font-size:28px;font-weight:700;color:{color};font-family:monospace">{value}</div>'
        '</div>'
    )
    c1, c2, c3, c4 = st.columns(4)
    c1.markdown(CARD.format(label="PACKETS CAPTURED",
                             value=f'{st.session_state["cap_packets"]:,}', color="#e6edf3"), unsafe_allow_html=True)
    c2.markdown(CARD.format(label="TLS PACKETS",
                             value=f'{st.session_state["cap_tls"]:,}', color="#58a6ff"), unsafe_allow_html=True)
    c3.markdown(CARD.format(label="BYTES SEEN",
                             value=f'{st.session_state["cap_bytes"]:,}', color="#e6edf3"), unsafe_allow_html=True)
    c4.markdown(CARD.format(label="ACTIVE FLOWS",
                             value=f'{st.session_state["cap_flows"]:,}', color="#3fb950"), unsafe_allow_html=True)

    st.divider()

    # Status banner
    if st.session_state["cap_running"]:
        st.markdown(
            '<div style="background:#0d2137;border:1px solid #1f6feb;border-radius:8px;'
            'padding:14px 18px">'
            '<span style="width:9px;height:9px;background:#3fb950;border-radius:50%;'
            'display:inline-block;margin-right:8px"></span>'
            '<span style="color:#58a6ff;font-weight:600">Capturing live traffic…</span>'
            '<span style="color:#8b949e;font-size:13px;margin-left:8px">'
            'Flows scored after 10 packets or 15 s.</span>'
            '</div>',
            unsafe_allow_html=True,
        )
    else:
        if not st.session_state["cap_alerts"]:
            st.markdown(
                '<div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;'
                'padding:24px;text-align:center;color:#8b949e">'
                'Select Wi-Fi interface above and click START CAPTURE.</div>',
                unsafe_allow_html=True,
            )

    # Alerts
    alerts = st.session_state.get("cap_alerts", [])
    if alerts:
        live_count = sum(1 for a in alerts if a.get("is_live"))
        st.markdown(
            f"### ⚡ Alerts &nbsp;"
            f"<span style='font-size:14px;color:#8b949e'>({live_count} live · {len(alerts)} total)</span>",
            unsafe_allow_html=True,
        )

        for a in alerts[:30]:
            sev      = a.get("severity", "LOW")
            color    = SEVERITY_COLOR.get(sev, "#8b949e")
            score    = float(a.get("composite_score") or 0)
            is_live  = bool(a.get("is_live"))
            groq_sum = a.get("groq_summary", "")
            groq_action = a.get("groq_action", "")
            groq_conf   = a.get("groq_confidence", "")
            groq_threat = a.get("groq_threat_type", "")

            badge = (
                '<span style="color:#3fb950;font-size:11px;background:#0d2014;'
                'padding:2px 6px;border-radius:3px">⚡ LIVE</span>'
                if is_live else
                '<span style="color:#8b949e;font-size:11px;background:#161b22;'
                'padding:2px 6px;border-radius:3px">📁 PCAP</span>'
            )

            groq_html = ""
            if groq_sum:
                threat_label = f"[{groq_threat.replace('_',' ')}] " if groq_threat else ""
                conf_pill    = (f'<span style="font-size:10px;padding:1px 5px;border-radius:3px;'
                                f'background:#1c2128;color:#8b949e">{groq_conf}</span> ') if groq_conf else ""
                groq_html = (
                    f'<div style="color:#8b949e;font-size:12px;margin-top:6px;padding:6px 8px;'
                    f'background:#0d1117;border-left:2px solid #1f6feb;border-radius:0 4px 4px 0">'
                    f'🤖 {conf_pill}<span style="font-style:italic">{threat_label}{groq_sum}</span>'
                    + (f'<br><span style="color:#6e7681;font-size:11px">→ {groq_action}</span>' if groq_action else "")
                    + '</div>'
                )

            findings = a.get("findings", "[]")
            if isinstance(findings, str):
                try:   findings = json.loads(findings)
                except: findings = [findings]
            top_finding = findings[0] if findings else "Anomaly detected"

            st.markdown(
                f'<div style="background:#0d1117;border:1px solid #21262d;border-radius:6px;'
                f'padding:12px 16px;margin-bottom:6px">'
                f'<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">'
                f'<span style="color:{color};font-weight:700;font-size:12px;'
                f'min-width:68px;padding:2px 8px;border:1px solid {color}44;border-radius:4px">{sev}</span>'
                f'<span style="color:#e6edf3;font-family:monospace;font-size:13px">'
                f'{a.get("src_ip","?")}:{a.get("src_port","")} → {a.get("dst_ip","?")}:{a.get("dst_port","")}'
                f'</span>'
                f'<span style="color:#8b949e;font-size:12px">score {score:.3f}</span>'
                f'<span style="margin-left:auto">{badge}</span>'
                f'</div>'
                f'<div style="color:#6e7681;font-size:12px;margin-top:4px">{top_finding}</div>'
                f'{groq_html}'
                f'</div>',
                unsafe_allow_html=True,
            )

    # Auto-refresh while running
    if st.session_state["cap_running"]:
        time.sleep(2)
        st.rerun()