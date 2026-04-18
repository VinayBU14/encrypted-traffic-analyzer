from __future__ import annotations
from datetime import datetime, timezone
from typing import Any
import streamlit as st
from src.dashboard import api_client, state

_SEV_COLOR  = {"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#eab308","LOW":"#3b82f6","CLEAN":"#22c55e"}
_SEV_BG     = {"CRITICAL":"#1a0505","HIGH":"#1a0a00","MEDIUM":"#1a1400","LOW":"#030f1f","CLEAN":"#021208"}
_SEV_BORDER = {"CRITICAL":"#7f1d1d","HIGH":"#7c2d12","MEDIUM":"#78350f","LOW":"#1e3a5f","CLEAN":"#14532d"}
_SEV_GLOW   = {"CRITICAL":"rgba(239,68,68,0.15)","HIGH":"rgba(249,115,22,0.15)",
               "MEDIUM":"rgba(234,179,8,0.15)","LOW":"rgba(59,130,246,0.15)","CLEAN":"rgba(34,197,94,0.15)"}

def _fmt_ts(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S")
    except Exception:
        return "—"

def _fmt_bytes(b: int) -> str:
    if b < 1024: return f"{b} B"
    if b < 1024**2: return f"{b/1024:.1f} KB"
    return f"{b/1024**2:.2f} MB"

def _threat_level(stats: dict[str,int]) -> tuple[str,str,str]:
    if stats.get("CRITICAL", 0) > 0:
        return "CRITICAL", "#ef4444", "Active critical threats detected"
    if stats.get("HIGH", 0) > 0:
        return "HIGH", "#f97316", "High-severity threats present"
    if stats.get("MEDIUM", 0) > 0:
        return "MEDIUM", "#eab308", "Medium-risk activity detected"
    if stats.get("LOW", 0) > 0:
        return "LOW", "#3b82f6", "Low-risk anomalies detected"
    return "CLEAN", "#22c55e", "No active threats"

def _is_capture_running() -> bool:
    """Check if live capture is active by querying the capture status endpoint."""
    try:
        import requests
        r = requests.get("http://localhost:8000/capture/status", timeout=2)
        return r.json().get("running", False)
    except Exception:
        return False

def render() -> None:

    # ── Source toggle ─────────────────────────────────────────────────────────
    capture_running = _is_capture_running()

    col_left, col_right = st.columns([3, 1])
    with col_right:
        source_options = ["All Data", "Live Only", "PCAP Only"]
        # Default to "Live Only" when capture is active
        default_idx = 1 if capture_running else 0
        if "ov_source" not in st.session_state:
            st.session_state["ov_source"] = source_options[default_idx]
        source_label = st.selectbox(
            "Data source",
            source_options,
            index=source_options.index(st.session_state.get("ov_source", source_options[default_idx])),
            key="ov_source_sel",
            label_visibility="collapsed",
        )
        st.session_state["ov_source"] = source_label

    source_param = {"Live Only": "live", "PCAP Only": "pcap"}.get(source_label, None)

    if capture_running and source_label == "Live Only":
        st.markdown(
            '<div style="background:#0d2137;border:1px solid #1f6feb33;border-radius:6px;'
            'padding:6px 12px;font-size:12px;color:#58a6ff;margin-bottom:8px">'
            '⊙ Live capture active — showing live-captured flows and alerts</div>',
            unsafe_allow_html=True,
        )

    try:
        stats     = api_client.get_alert_stats(source=source_param)
        alerts    = api_client.get_alerts(limit=200, source=source_param)
        flows     = api_client.get_flows(limit=200, source=source_param)
        high_risk = api_client.get_high_risk_nodes(threshold=0.30)
    except ConnectionError as exc:
        st.markdown(f"""
        <div style="background:#1a0505;border:1px solid #7f1d1d;border-radius:14px;
                    padding:40px;text-align:center;margin-top:40px">
            <div style="font-size:3rem;margin-bottom:16px">⚠</div>
            <div style="font-family:'Syne',sans-serif;font-size:1.1rem;font-weight:700;
                        color:#ef4444;margin-bottom:8px">API Unavailable</div>
            <div style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;
                        color:#7f1d1d">Start: uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload</div>
        </div>""", unsafe_allow_html=True)
        return
    except Exception as exc:
        st.error(f"Data fetch failed: {exc}")
        return

    total_alerts = sum(stats.values())
    threat_level, tl_color, tl_desc = _threat_level(stats)
    tl_bg     = _SEV_BG.get(threat_level, "#080c14")
    tl_border = _SEV_BORDER.get(threat_level, "#1e2a3a")
    tl_glow   = _SEV_GLOW.get(threat_level, "rgba(255,255,255,0.05)")

    active_flows   = sum(1 for f in flows if f.get("status") == "ACTIVE")
    total_bytes    = sum(int(f.get("bytes_total", 0)) for f in flows)
    malicious_nodes= sum(1 for n in high_risk if n.get("is_malicious"))
    unique_ips     = len({f.get("src_ip") for f in flows if f.get("src_ip")})
    live_alert_cnt = sum(1 for a in alerts if a.get("is_live"))

    # Threat level banner
    source_badge = ""
    if source_label == "Live Only":
        source_badge = f' <span style="font-size:0.6rem;background:#0d2137;color:#58a6ff;padding:3px 8px;border-radius:4px;vertical-align:middle">⚡ LIVE</span>'
    elif source_label == "PCAP Only":
        source_badge = f' <span style="font-size:0.6rem;background:#1c2128;color:#8b949e;padding:3px 8px;border-radius:4px;vertical-align:middle">📁 PCAP</span>'

    st.markdown(f"""
    <div style="background:linear-gradient(135deg,{tl_bg} 0%,#080c14 100%);
                border:1px solid {tl_border};border-radius:16px;
                padding:28px 36px;margin-bottom:24px;
                box-shadow:0 0 40px {tl_glow};position:relative;overflow:hidden;">
        <div style="position:absolute;top:-30px;right:-30px;width:160px;height:160px;
                    border-radius:50%;background:{tl_glow};filter:blur(40px)"></div>
        <div style="display:flex;align-items:center;justify-content:space-between;
                    position:relative;z-index:1">
            <div>
                <div style="font-family:'Syne',sans-serif;font-size:0.7rem;font-weight:700;
                            color:#334155;text-transform:uppercase;letter-spacing:0.12em;
                            margin-bottom:8px">System Threat Level</div>
                <div style="font-family:'Syne',sans-serif;font-size:3rem;font-weight:800;
                            color:{tl_color};letter-spacing:-0.02em;line-height:1">
                    {threat_level}{source_badge}</div>
                <div style="font-family:'Syne',sans-serif;font-size:0.88rem;
                            color:#475569;margin-top:8px">{tl_desc}</div>
            </div>
            <div style="text-align:right">
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;
                            color:#334155;margin-bottom:4px">
                    {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:2.4rem;
                            font-weight:600;color:{tl_color};line-height:1">
                    {total_alerts}</div>
                <div style="font-family:'Syne',sans-serif;font-size:0.7rem;font-weight:700;
                            color:#334155;text-transform:uppercase;letter-spacing:0.1em">
                    total alerts</div>
                {f'<div style="font-family:monospace;font-size:0.65rem;color:#58a6ff;margin-top:4px">{live_alert_cnt} live</div>' if live_alert_cnt > 0 else ""}
            </div>
        </div>
    </div>""", unsafe_allow_html=True)

    # Severity pills
    sev_cols = st.columns(5)
    for col, sev in zip(sev_cols, ["CRITICAL","HIGH","MEDIUM","LOW","CLEAN"]):
        count  = stats.get(sev, 0)
        c      = _SEV_COLOR[sev]
        bg     = _SEV_BG[sev]
        bd     = _SEV_BORDER[sev]
        pct    = int(count / max(total_alerts, 1) * 100)
        with col:
            st.markdown(f"""
            <div style="background:{bg};border:1px solid {bd};border-radius:12px;
                        padding:16px;text-align:center;cursor:pointer">
                <div style="font-family:'JetBrains Mono',monospace;font-size:2rem;
                            font-weight:700;color:{c};line-height:1">{count}</div>
                <div style="font-family:'Syne',sans-serif;font-size:0.65rem;font-weight:700;
                            color:#334155;text-transform:uppercase;letter-spacing:0.1em;
                            margin:6px 0 8px">{sev}</div>
                <div style="background:#080c14;border-radius:2px;height:3px">
                    <div style="width:{pct}%;background:{c};height:3px;border-radius:2px"></div>
                </div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;
                            color:#334155;margin-top:4px">{pct}%</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)

    left_col, right_col = st.columns([1, 1])

    with left_col:
        st.markdown("""<div style="font-family:'Syne',sans-serif;font-size:0.68rem;
                       font-weight:700;color:#334155;text-transform:uppercase;
                       letter-spacing:0.1em;margin-bottom:10px">Network Overview</div>""",
                    unsafe_allow_html=True)
        net_chips = [
            ("Flows Captured", str(len(flows)),    "#e2e8f0"),
            ("Active Flows",   str(active_flows),  "#22c55e" if active_flows == 0 else "#ef4444"),
            ("Unique Sources", str(unique_ips),     "#e2e8f0"),
            ("Total Traffic",  _fmt_bytes(total_bytes), "#38bdf8"),
            ("Malicious Nodes",str(malicious_nodes),"#ef4444" if malicious_nodes else "#22c55e"),
            ("High-risk Nodes",str(len(high_risk)), "#f97316" if high_risk else "#22c55e"),
        ]
        rows_html = ""
        for i in range(0, len(net_chips), 2):
            row_html = '<div style="display:flex;gap:8px;margin-bottom:8px">'
            for label, val, vc in net_chips[i:i+2]:
                row_html += f"""
                <div style="flex:1;background:#0d1117;border:1px solid #1e2a3a;
                            border-radius:10px;padding:12px 14px">
                    <div style="font-family:'JetBrains Mono',monospace;font-size:1.2rem;
                                font-weight:600;color:{vc};line-height:1">{val}</div>
                    <div style="font-family:'Syne',sans-serif;font-size:0.65rem;font-weight:700;
                                color:#334155;text-transform:uppercase;letter-spacing:0.08em;
                                margin-top:4px">{label}</div>
                </div>"""
            row_html += '</div>'
            rows_html += row_html
        st.markdown(rows_html, unsafe_allow_html=True)

    with right_col:
        st.markdown("""<div style="font-family:'Syne',sans-serif;font-size:0.68rem;
                       font-weight:700;color:#334155;text-transform:uppercase;
                       letter-spacing:0.1em;margin-bottom:10px">Score Distribution</div>""",
                    unsafe_allow_html=True)

        buckets = {"0.9–1.0":0,"0.7–0.9":0,"0.5–0.7":0,"0.3–0.5":0,"0.0–0.3":0}
        bucket_colors = {"0.9–1.0":"#ef4444","0.7–0.9":"#f97316","0.5–0.7":"#eab308",
                         "0.3–0.5":"#3b82f6","0.0–0.3":"#22c55e"}
        for a in alerts:
            s = float(a.get("composite_score", 0))
            if s >= 0.9:   buckets["0.9–1.0"] += 1
            elif s >= 0.7: buckets["0.7–0.9"] += 1
            elif s >= 0.5: buckets["0.5–0.7"] += 1
            elif s >= 0.3: buckets["0.3–0.5"] += 1
            else:          buckets["0.0–0.3"] += 1

        max_b = max(buckets.values()) if any(buckets.values()) else 1
        dist_html = '<div style="background:#0d1117;border:1px solid #1e2a3a;border-radius:12px;padding:16px 20px">'
        for label, count in buckets.items():
            bc = bucket_colors[label]
            bar_w = int(count / max(max_b, 1) * 100)
            dist_html += f"""
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;
                            color:#475569;width:60px;flex-shrink:0">{label}</div>
                <div style="flex:1;background:#131c2b;border-radius:3px;height:18px;
                            position:relative;overflow:hidden">
                    <div style="width:{bar_w}%;background:{bc};height:100%;
                                border-radius:3px;opacity:0.85"></div>
                </div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;
                            font-weight:600;color:{bc};width:20px;text-align:right">{count}</div>
            </div>"""
        dist_html += "</div>"
        st.markdown(dist_html, unsafe_allow_html=True)

    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)

    feed_col, method_col = st.columns([3, 2])

    with feed_col:
        st.markdown("""<div style="font-family:'Syne',sans-serif;font-size:0.68rem;
                       font-weight:700;color:#334155;text-transform:uppercase;
                       letter-spacing:0.1em;margin-bottom:10px">Recent Alerts</div>""",
                    unsafe_allow_html=True)

        recent = [a for a in alerts if not a.get("is_suppressed")][:8]
        if not recent:
            recent = alerts[:8]

        if not recent:
            st.markdown("""<div style="background:#0d1117;border:1px solid #1e2a3a;
                           border-radius:12px;padding:24px;text-align:center">
                <div style="font-family:'Syne',sans-serif;color:#1e2a3a;font-size:0.85rem">
                    No alerts — start live capture or run the pipeline</div>
            </div>""", unsafe_allow_html=True)
        else:
            feed_html = '<div style="background:#0d1117;border:1px solid #1e2a3a;border-radius:12px;overflow:hidden">'
            for i, a in enumerate(recent):
                sev   = a.get("severity","")
                sc    = float(a.get("composite_score", 0))
                c     = _SEV_COLOR.get(sev, "#475569")
                src   = a.get("src_ip","—")
                sport = a.get("src_port", "")
                dport = a.get("dst_port", "")
                dom   = a.get("dst_domain","") or a.get("dst_ip","") or "—"
                dst_label = f"{dom}:{dport}" if dport else dom
                ts    = _fmt_ts(a.get("timestamp", 0))
                is_live_flag = a.get("is_live", 0)
                live_dot = ' <span style="color:#3fb950;font-size:9px">⚡</span>' if is_live_flag else ""
                bg_row = "#0a0f18" if i % 2 == 0 else "#0d1117"
                feed_html += f"""
                <div style="display:flex;align-items:center;gap:12px;padding:10px 16px;
                            background:{bg_row};border-bottom:1px solid #0f1923">
                    <div style="width:6px;height:6px;border-radius:50%;
                                background:{c};flex-shrink:0"></div>
                    <div style="flex:1;min-width:0">
                        <div style="display:flex;align-items:center;gap:8px">
                            <span style="font-family:'Syne',sans-serif;font-size:0.72rem;
                                         font-weight:700;color:{c}">{sev}</span>
                            <span style="font-family:'JetBrains Mono',monospace;
                                         font-size:0.72rem;color:#334155">{src}{live_dot}</span>
                            <span style="font-family:'JetBrains Mono',monospace;
                                         font-size:0.68rem;color:#1e2a3a">→</span>
                            <span style="font-family:'JetBrains Mono',monospace;
                                         font-size:0.72rem;color:#334155;
                                         white-space:nowrap;overflow:hidden;
                                         text-overflow:ellipsis;max-width:180px">{dst_label}</span>
                        </div>
                    </div>
                    <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;
                                font-weight:600;color:{c};flex-shrink:0">{sc:.3f}</div>
                    <div style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;
                                color:#1e2a3a;flex-shrink:0">{ts}</div>
                </div>"""
            feed_html += "</div>"
            st.markdown(feed_html, unsafe_allow_html=True)

            st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
            if st.button("View all alerts  →", key="ov_to_monitor", use_container_width=False):
                state.set_active_page("Live Monitor")
                st.rerun()

    with method_col:
        st.markdown("""<div style="font-family:'Syne',sans-serif;font-size:0.68rem;
                       font-weight:700;color:#334155;text-transform:uppercase;
                       letter-spacing:0.1em;margin-bottom:10px">Detection Modules</div>""",
                    unsafe_allow_html=True)

        modules = [
            ("JA3 Fingerprint",  "ja3_score",    "#8b5cf6", "TLS client fingerprinting"),
            ("Beacon Detection", "beacon_score",  "#06b6d4", "C2 periodicity analysis"),
            ("Certificate Risk", "cert_score",    "#f59e0b", "Certificate lifecycle"),
            ("Graph Proximity",  "graph_score",   "#10b981", "Infrastructure graph"),
            ("Anomaly (ML)",     "anomaly_score", "#f43f5e", "Isolation Forest"),
        ]
        mod_html = '<div style="background:#0d1117;border:1px solid #1e2a3a;border-radius:12px;padding:16px 20px">'
        for name, key, color, desc in modules:
            scores = [float(a.get(key) or 0) for a in alerts if a.get(key) is not None]
            avg = sum(scores) / len(scores) if scores else 0.0
            pct = int(avg * 100)
            mod_html += f"""
            <div style="margin-bottom:14px">
                <div style="display:flex;justify-content:space-between;
                            align-items:baseline;margin-bottom:5px">
                    <div>
                        <span style="font-family:'Syne',sans-serif;font-size:0.78rem;
                                     font-weight:700;color:#94a3b8">{name}</span>
                        <span style="font-family:'Syne',sans-serif;font-size:0.65rem;
                                     color:#334155;margin-left:6px">{desc}</span>
                    </div>
                    <span style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;
                                 font-weight:600;color:{color}">{avg:.3f}</span>
                </div>
                <div style="background:#131c2b;border-radius:3px;height:6px">
                    <div style="width:{pct}%;background:{color};height:6px;
                                border-radius:3px;opacity:0.9"></div>
                </div>
            </div>"""
        mod_html += "</div>"
        st.markdown(mod_html, unsafe_allow_html=True)

        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
        b1, b2 = st.columns(2)
        if b1.button("Graph →", key="ov_to_graph", use_container_width=True):
            state.set_active_page("Graph View")
            st.rerun()
        if b2.button("Flows →", key="ov_to_flows", use_container_width=True):
            state.set_active_page("Session Timeline")
            st.rerun()