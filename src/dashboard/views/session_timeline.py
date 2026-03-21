

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pandas as pd
import streamlit as st

from src.dashboard import api_client, state

_STATUS_COLOR  = {"ACTIVE":"#22c55e","CLOSED":"#475569","TIMEOUT":"#eab308","RST":"#ef4444"}
_PROTOCOL_COLOR = {"TCP":"#3b82f6","UDP":"#8b5cf6","TLS":"#06b6d4"}


def _fmt_ts(ts: float | None) -> str:
    if ts is None: return "—"
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


def _fmt_bytes(b: int) -> str:
    if b < 1024: return f"{b} B"
    if b < 1024**2: return f"{b/1024:.1f} KB"
    return f"{b/1024**2:.2f} MB"


def _fmt_dur(ms: float | None) -> str:
    if ms is None: return "—"
    return f"{ms:.0f} ms" if ms < 1000 else f"{ms/1000:.2f} s"


def _build_df(flows: list[dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for f in flows:
        rows.append({
            "flow_id":       f.get("flow_id",""),
            "start_time":    _fmt_ts(f.get("start_time")),
            "src_ip":        f.get("src_ip",""),
            "src_port":      int(f.get("src_port",0)),
            "dst_ip":        f.get("dst_ip",""),
            "dst_port":      int(f.get("dst_port",0)),
            "protocol":      f.get("protocol",""),
            "status":        f.get("status",""),
            "duration_ms":   f.get("duration_ms"),
            "bytes_total":   int(f.get("bytes_total",0)),
            "upload_bytes":  int(f.get("upload_bytes",0)),
            "download_bytes":int(f.get("download_bytes",0)),
            "packet_count":  int(f.get("packet_count",0)),
        })
    return pd.DataFrame(rows)


def _stat_chip(label: str, value: str) -> str:
    return f"""<div style="background:#0d1117;border:1px solid #1e2a3a;border-radius:10px;
               padding:14px 16px;text-align:center;flex:1">
        <div style="font-family:'JetBrains Mono',monospace;font-size:1.5rem;
                    font-weight:600;color:#e2e8f0;line-height:1">{value}</div>
        <div style="font-family:'Syne',sans-serif;font-size:0.68rem;font-weight:700;
                    color:#334155;text-transform:uppercase;letter-spacing:0.08em;
                    margin-top:5px">{label}</div>
    </div>"""


def render() -> None:
    st.markdown("""
    <div class="page-header">
        <div class="page-header-icon" style="background:#0d1a2b;">◷</div>
        <div>
            <div class="page-header-title">Session Timeline</div>
            <div class="page-header-sub">Network flow browser &amp; drill-down</div>
        </div>
    </div>""", unsafe_allow_html=True)

    c1, c2, c3, c4 = st.columns([2, 2, 2, 1])
    with c1: limit = st.slider("Max flows", 25, 500, 100, 25, key="st_limit")
    with c2: proto = st.selectbox("Protocol", ["ALL","TCP","UDP","TLS"], key="st_proto")
    with c3: status = st.selectbox("Status", ["ALL","ACTIVE","CLOSED","TIMEOUT","RST"], key="st_status")
    with c4:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("↻ Refresh", key="st_ref", use_container_width=True): st.rerun()

    ip_q = st.text_input("Filter by IP", placeholder="e.g. 192.168.1.1", key="st_ip")

    try:
        flows = api_client.get_flows(limit=limit)
    except ConnectionError as exc:
        st.error(f"API Unavailable — {exc}"); return
    except Exception as exc:
        st.error(f"Fetch failed: {exc}"); return

    if not flows:
        st.markdown("""<div style="background:#0d1117;border:1px solid #1e2a3a;
                       border-radius:10px;padding:32px;text-align:center;">
            <div style="font-family:'Syne',sans-serif;color:#334155;font-weight:600">
                No flows found. Run the pipeline first.</div></div>""",
                    unsafe_allow_html=True)
        return

    
    filtered = flows
    if proto != "ALL":
        filtered = [f for f in filtered if f.get("protocol","").upper() == proto]
    if status != "ALL":
        filtered = [f for f in filtered if f.get("status","").upper() == status]
    if ip_q.strip():
        q = ip_q.strip()
        filtered = [f for f in filtered if q in f.get("src_ip","") or q in f.get("dst_ip","")]

    
    total_b  = sum(int(f.get("bytes_total",0)) for f in filtered)
    total_pk = sum(int(f.get("packet_count",0)) for f in filtered)
    active_n = sum(1 for f in filtered if f.get("status") == "ACTIVE")
    unique_s = len({f.get("src_ip") for f in filtered})
    chips = (_stat_chip("Flows", str(len(filtered))) +
             _stat_chip("Active", str(active_n)) +
             _stat_chip("Sources", str(unique_s)) +
             _stat_chip("Traffic", _fmt_bytes(total_b)) +
             _stat_chip("Packets", f"{total_pk:,}"))
    st.markdown(f'<div style="display:flex;gap:10px;margin:16px 0">{chips}</div>',
                unsafe_allow_html=True)

    
    chart_l, chart_r = st.columns([3, 2])
    with chart_l:
        agg: dict[str,int] = {}
        for f in filtered:
            src = f.get("src_ip","unknown")
            agg[src] = agg.get(src,0) + int(f.get("upload_bytes",0))
        if agg:
            df_chart = (pd.DataFrame(list(agg.items()), columns=["Source IP","Upload Bytes"])
                        .sort_values("Upload Bytes", ascending=False).head(15))
            st.markdown('<div style="font-family:\'Syne\',sans-serif;font-size:0.72rem;'
                        'font-weight:700;color:#334155;text-transform:uppercase;'
                        'letter-spacing:0.1em;margin-bottom:8px">Top sources by upload</div>',
                        unsafe_allow_html=True)
            st.bar_chart(df_chart.set_index("Source IP"), use_container_width=True, height=160)

    with chart_r:
        proto_agg: dict[str,int] = {}
        for f in filtered:
            p = f.get("protocol","?").upper()
            proto_agg[p] = proto_agg.get(p,0) + 1
        st.markdown('<div style="font-family:\'Syne\',sans-serif;font-size:0.72rem;'
                    'font-weight:700;color:#334155;text-transform:uppercase;'
                    'letter-spacing:0.1em;margin-bottom:8px">Protocol split</div>',
                    unsafe_allow_html=True)
        for p, cnt in sorted(proto_agg.items(), key=lambda x: -x[1]):
            pc = _PROTOCOL_COLOR.get(p, "#475569")
            pct = int(cnt / max(len(filtered),1) * 100)
            st.markdown(f"""
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
                <div style="font-family:'Syne',sans-serif;font-size:0.75rem;
                            font-weight:700;color:{pc};width:36px">{p}</div>
                <div style="flex:1;background:#131c2b;border-radius:3px;height:6px">
                    <div style="width:{pct}%;background:{pc};height:6px;border-radius:3px"></div>
                </div>
                <div class="mono" style="font-size:0.75rem;color:#334155;width:24px;
                            text-align:right">{cnt}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown('<div style="border-bottom:1px solid #1e2a3a;margin:16px 0 12px"></div>',
                unsafe_allow_html=True)

    # ── Flow table ──
    df = _build_df(filtered)
    if df.empty:
        st.markdown('<div style="font-family:\'Syne\',sans-serif;color:#334155;'
                    'font-size:0.85rem">No flows match filters.</div>',
                    unsafe_allow_html=True)
        return

    st.markdown(f'<div style="font-family:\'Syne\',sans-serif;font-size:0.68rem;'
                f'font-weight:700;color:#334155;text-transform:uppercase;'
                f'letter-spacing:0.1em;margin-bottom:8px">{len(df)} flow(s)</div>',
                unsafe_allow_html=True)

    hcols = st.columns([2.0, 1.6, 1.6, 0.7, 1.4, 0.8, 0.9, 0.7, 0.6])
    for col, h in zip(hcols, ["Start (UTC)","Source","Destination","Proto",
                                "Status","Duration","Bytes","Pkts",""]):
        col.markdown(f'<div style="font-family:\'Syne\',sans-serif;font-size:0.65rem;'
                     f'font-weight:700;color:#1e2a3a;text-transform:uppercase;'
                     f'letter-spacing:0.08em;padding-bottom:6px">{h}</div>',
                     unsafe_allow_html=True)

    selected_fid = None
    for _, row in df.iterrows():
        sc = _STATUS_COLOR.get(row["status"], "#475569")
        pc = _PROTOCOL_COLOR.get(row["protocol"].upper(), "#475569")
        c1,c2,c3,c4,c5,c6,c7,c8,c9 = st.columns([2.0,1.6,1.6,0.7,1.4,0.8,0.9,0.7,0.6])
        c1.markdown(f'<div class="mono">{row["start_time"]}</div>', unsafe_allow_html=True)
        c2.markdown(f'<div class="mono">{row["src_ip"]}:{row["src_port"]}</div>',
                    unsafe_allow_html=True)
        c3.markdown(f'<div class="mono">{row["dst_ip"]}:{row["dst_port"]}</div>',
                    unsafe_allow_html=True)
        c4.markdown(f'<div style="font-family:\'Syne\',sans-serif;font-size:0.72rem;'
                    f'font-weight:700;color:{pc}">{row["protocol"]}</div>',
                    unsafe_allow_html=True)
        c5.markdown(f'<div style="font-family:\'Syne\',sans-serif;font-size:0.75rem;'
                    f'font-weight:600;color:{sc}">{row["status"]}</div>',
                    unsafe_allow_html=True)
        c6.markdown(f'<div class="mono">{_fmt_dur(row["duration_ms"])}</div>',
                    unsafe_allow_html=True)
        c7.markdown(f'<div class="mono">{_fmt_bytes(row["bytes_total"])}</div>',
                    unsafe_allow_html=True)
        c8.markdown(f'<div class="mono">{row["packet_count"]}</div>',
                    unsafe_allow_html=True)
        if c9.button("→", key=f"st_{row['flow_id']}", use_container_width=True):
            selected_fid = row["flow_id"]
        st.markdown('<div style="border-bottom:1px solid #0f1923;margin:1px 0"></div>',
                    unsafe_allow_html=True)

    # ── Flow detail ──
    fid = selected_fid or state.get_selected_flow()
    if fid:
        if selected_fid:
            state.set_selected_flow(selected_fid)
        try:
            flow = api_client.get_flow(fid)
        except Exception as exc:
            st.error(f"Could not load flow: {exc}")
            return

        st.markdown('<div style="height:20px"></div>', unsafe_allow_html=True)
        st.markdown(f"""
        <div style="background:#0d1117;border:1px solid #1e2a3a;border-left:3px solid #3b82f6;
                    border-radius:12px;padding:20px 24px;margin-bottom:16px">
            <div style="font-family:'Syne',sans-serif;font-size:0.68rem;font-weight:700;
                        color:#334155;text-transform:uppercase;letter-spacing:0.1em;
                        margin-bottom:14px">◈ Flow detail</div>
            <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px">
                {_stat_chip("Source", f"{flow.get('src_ip')}:{flow.get('src_port')}")}
                {_stat_chip("Destination", f"{flow.get('dst_ip')}:{flow.get('dst_port')}")}
                {_stat_chip("Protocol", flow.get("protocol",""))}
                {_stat_chip("Status", flow.get("status",""))}
                {_stat_chip("Duration", _fmt_dur(flow.get("duration_ms")))}
                {_stat_chip("Bytes", _fmt_bytes(int(flow.get("bytes_total",0))))}
                {_stat_chip("Upload", _fmt_bytes(int(flow.get("upload_bytes",0))))}
                {_stat_chip("Download", _fmt_bytes(int(flow.get("download_bytes",0))))}
            </div>
        </div>""", unsafe_allow_html=True)

        src, dst = flow.get("src_ip",""), flow.get("dst_ip","")
        if src and dst:
            try:
                pairs = api_client.get_flows_by_pair(src, dst)
                if len(pairs) > 1:
                    with st.expander(f"All flows {src} → {dst}  ({len(pairs)})", expanded=False):
                        st.dataframe(_build_df(pairs)[["start_time","duration_ms",
                                                        "bytes_total","packet_count","status"]],
                                     use_container_width=True, hide_index=True)
            except Exception:
                pass

        with st.expander("Raw JSON", expanded=False):
            st.json(flow)
